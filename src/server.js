require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const argon2 = require('argon2');

const { pool } = require('./db');
const { runMigrations } = require('./db/migrate');
const {
  registerSchema,
  loginSchema,
  verifySmsSchema,
  cleanDigits,
  formatCPF
} = require('./utils/validators');
const { loginAndPoll } = require('./services/nbi');
const { buildSmsProvider } = require('./services/smsProvider');
const { logInfo, logError, LOG_TZ, AUTH_LOG_FILE_PATH } = require('./utils/logger');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const USER_ACCOUNT_VALIDITY_DAYS = Number(process.env.USER_ACCOUNT_VALIDITY_DAYS || 30);
const RENEW_ON_LOGIN = (process.env.RENEW_ON_LOGIN || 'true').toLowerCase() !== 'false';
const SESSION_MAX_AGE_MS = USER_ACCOUNT_VALIDITY_DAYS * 24 * 60 * 60 * 1000;
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 300);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const OTP_RESEND_COOLDOWN_SECONDS = Number(process.env.OTP_RESEND_COOLDOWN_SECONDS || 60);
const LOGIN_SESSION_TTL_SECONDS = Number(process.env.LOGIN_SESSION_TTL_SECONDS || 600);
const smsProvider = buildSmsProvider();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
  if (req.cookies?.portal_session) {
    res.cookie('portal_session', req.cookies.portal_session, {
      maxAge: SESSION_MAX_AGE_MS,
      httpOnly: true,
      sameSite: 'lax'
    });
  }
  next();
});
app.use('/public', express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 60 * 1000, limit: Number(process.env.RATE_LIMIT_PER_MINUTE || 30), standardHeaders: true, legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, limit: Number(process.env.RATE_LIMIT_VERIFY_PER_MINUTE || 20), standardHeaders: true, legacyHeaders: false });

app.use('/register', authLimiter);
app.use('/login', authLimiter);
app.use('/verify/sms', verifyLimiter);

function getRedirectParams(req) {
  return normalizeBodyFields({ ...req.query, ...req.body });
}
function getOriginalUrl(params) { return params.url || params.orig_url || '/success'; }
function normalizeBodyFields(body = {}) {
  return Object.fromEntries(Object.entries(body).map(([key, value]) => [key, Array.isArray(value) ? value[0] : value]));
}
function sanitizeParams(params = {}) {
  const sanitized = normalizeBodyFields(params);
  delete sanitized.password;
  delete sanitized.confirmPassword;
  delete sanitized.code;
  if (sanitized.cpf) sanitized.cpf = cleanDigits(sanitized.cpf);
  return sanitized;
}
function genericInvalidCredentials(res, params, statusCode = 401) {
  return res.status(statusCode).render('portal', { title: 'Portal Visitantes TRT9', error: 'Credenciais inválidas.', message: null, params });
}

async function createLoginSession(userId, ctxJson) {
  const lsid = crypto.randomUUID();
  await pool.query(
    `INSERT INTO login_sessions (id, user_id, ctx_json, expires_at)
     VALUES ($1, $2, $3::jsonb, NOW() + ($4 || ' seconds')::interval)`,
    [lsid, userId, JSON.stringify(ctxJson), LOGIN_SESSION_TTL_SECONDS]
  );
  return lsid;
}

async function sendOtpForUser({ userId, phoneE164, reason }) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await argon2.hash(code);

  await smsProvider.send(phoneE164, `Seu código de acesso do Portal TRT9 é ${code}. Ele expira em ${Math.ceil(OTP_TTL_SECONDS / 60)} minutos.`);

  await pool.query(
    `INSERT INTO otp_codes (user_id, channel, destination, code_hash, expires_at)
     VALUES ($1, 'sms', $2, $3, NOW() + ($4 || ' seconds')::interval)`,
    [userId, phoneE164, codeHash, OTP_TTL_SECONDS]
  );

  logInfo('otp_sent', { user_id: userId, destination: phoneE164, reason });
}

async function getLatestOtp(userId) {
  const result = await pool.query(
    `SELECT * FROM otp_codes
     WHERE user_id = $1 AND channel = 'sms'
     ORDER BY created_at DESC LIMIT 1`,
    [userId]
  );
  return result.rows[0] || null;
}

async function ensureResendCooldown(userId) {
  const latestOtp = await getLatestOtp(userId);
  if (!latestOtp) return { allowed: true, waitSeconds: 0 };

  const cooldownSql = `SELECT GREATEST(0, $2 - EXTRACT(EPOCH FROM (NOW() - $1::timestamptz))::int) AS wait_seconds`;
  const cooldown = await pool.query(cooldownSql, [latestOtp.created_at, OTP_RESEND_COOLDOWN_SECONDS]);
  const waitSeconds = cooldown.rows[0].wait_seconds;
  return { allowed: waitSeconds <= 0, waitSeconds };
}

class AuthFlowError extends Error {
  constructor(message, userMessage, statusCode = 401, reason = null) {
    super(message);
    this.name = 'AuthFlowError';
    this.userMessage = userMessage;
    this.statusCode = statusCode;
    this.reason = reason;
  }
}

app.get('/healthz', (_, res) => res.json({ status: 'ok' }));

app.get('/portal', (req, res) => {
  res.render('portal', { title: 'Portal Visitantes TRT9', error: null, message: null, params: req.query });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Cadastro de visitante', error: null, values: {}, params: req.query });
});

app.get('/verify/sms', async (req, res) => {
  const lsid = String(req.query.lsid || '');
  if (!lsid) return res.redirect('/portal');

  const sessionQuery = await pool.query(
    `SELECT ls.id, ls.user_id, ls.ctx_json, ls.expires_at, ls.consumed_at, u.phone_e164
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     WHERE ls.id = $1`,
    [lsid]
  );

  if (sessionQuery.rowCount === 0) return res.redirect('/portal');
  const session = sessionQuery.rows[0];
  if (session.consumed_at || new Date(session.expires_at) < new Date()) return res.redirect('/portal');

  const cooldown = await ensureResendCooldown(session.user_id);

  return res.render('verify_sms', {
    title: 'Verificar SMS',
    error: null,
    message: 'Digite o código enviado por SMS.',
    lsid,
    maskedPhone: session.phone_e164.replace(/(\+55\d{2})\d{5}(\d{4})/, '$1*****$2'),
    resendWaitSeconds: cooldown.waitSeconds
  });
});

app.post('/register', async (req, res) => {
  const params = getRedirectParams(req);
  const normalizedBody = normalizeBodyFields(req.body);
  const requestContext = {
    cpf: cleanDigits(normalizedBody.cpf || ''),
    request_ip: req.ip,
    user_agent: req.get('user-agent') || '',
    params: sanitizeParams(params)
  };

  logInfo('register_attempt_started', requestContext);
  const parsed = registerSchema.safeParse(normalizedBody);
  if (!parsed.success) {
    return res.status(400).render('register', { title: 'Cadastro de visitante', error: parsed.error.issues[0].message, values: normalizedBody, params });
  }

  const { fullName, cpf, phone, email, password } = parsed.data;
  const usernameRadius = `visitante_${cpf}`;

  try {
    const passwordHash = await argon2.hash(password);
    const userInsert = await pool.query(
      `INSERT INTO users (nome, cpf_normalizado, cpf_formatado, phone_e164, email, cpf, phone, username_radius, password_hash, is_active, expires_at)
       VALUES ($1, $2, $3, $4, $5, $2, $4, $6, $7, true, NOW() + ($8 || ' days')::interval)
       ON CONFLICT (cpf_normalizado) DO UPDATE SET
          nome = EXCLUDED.nome,
          cpf_formatado = EXCLUDED.cpf_formatado,
          phone_e164 = EXCLUDED.phone_e164,
          email = EXCLUDED.email,
          phone = EXCLUDED.phone,
          username_radius = EXCLUDED.username_radius,
          password_hash = EXCLUDED.password_hash,
          expires_at = NOW() + ($8 || ' days')::interval,
          updated_at = NOW()
       RETURNING id, cpf_normalizado, phone_e164`,
      [fullName, cpf, formatCPF(cpf), phone, email, usernameRadius, passwordHash, USER_ACCOUNT_VALIDITY_DAYS]
    );

    const user = userInsert.rows[0];
    await pool.query(
      `INSERT INTO lgpd_consents (user_id, accepted_terms, accepted_privacy, accepted_processing, terms_version, privacy_version, accepted_at, ip, user_agent)
       VALUES ($1, true, true, true, $2, $3, NOW(), $4, $5)`,
      [user.id, process.env.TERMS_VERSION || 'v1.0', process.env.PRIVACY_VERSION || 'v1.0', req.ip, req.get('user-agent') || '']
    );

    await pool.query(
      `INSERT INTO user_verifications (user_id)
       VALUES ($1)
       ON CONFLICT (user_id) DO NOTHING`,
      [user.id]
    );

    const lsid = await createLoginSession(user.id, { ...params, stage: 'register', ue: { ip: params['UE-IP'] || params.ue_ip || params.uip, mac: params['UE-MAC'] || params.ue_mac || params.client_mac }, login_password: password });
    try {
      await sendOtpForUser({ userId: user.id, phoneE164: user.phone_e164, reason: 'register' });
      logInfo('register_attempt_success', { ...requestContext, user_id: user.id, normalized_cpf: user.cpf_normalizado });
      return res.redirect(`/verify/sms?lsid=${encodeURIComponent(lsid)}`);
    } catch (smsError) {
      logError('register_sms_send_failed', { ...requestContext, user_id: user.id, normalized_cpf: user.cpf_normalizado, error: smsError });
      return res.status(200).render('verify_sms', {
        title: 'Verificar SMS',
        error: 'Seu cadastro foi concluído, mas houve falha no envio do SMS. Clique em "Reenviar código" para tentar novamente.',
        message: null,
        lsid,
        maskedPhone: user.phone_e164.replace(/(\+55\d{2})\d{5}(\d{4})/, '$1*****$2'),
        resendWaitSeconds: 0
      });
    }
  } catch (error) {
    logError('register_attempt_failed', { ...requestContext, error });
    return res.status(500).render('register', { title: 'Cadastro de visitante', error: 'Falha ao cadastrar usuário.', values: normalizedBody, params });
  }
});

app.post('/login', async (req, res) => {
  const params = getRedirectParams(req);
  const normalizedBody = normalizeBodyFields(req.body);
  const requestContext = { cpf: cleanDigits(normalizedBody.cpf || ''), request_ip: req.ip, user_agent: req.get('user-agent') || '', params: sanitizeParams(params) };

  logInfo('login_attempt_started', requestContext);
  const parsed = loginSchema.safeParse(normalizedBody);
  if (!parsed.success) return genericInvalidCredentials(res, params, 401);

  const { cpf, password } = parsed.data;
  try {
    const query = await pool.query(
      `SELECT id, cpf_normalizado, username_radius, password_hash, is_active, expires_at, phone_e164
       FROM users
       WHERE cpf_normalizado = $1`,
      [cpf]
    );
    if (query.rowCount === 0) throw new AuthFlowError('Credenciais inválidas.', 'Credenciais inválidas.');

    const user = query.rows[0];
    if (!user.is_active) throw new AuthFlowError('Usuário inativo.', 'Credenciais inválidas.');
    if (new Date(user.expires_at) < new Date()) throw new AuthFlowError('Conta expirada.', 'Credenciais inválidas.', 401, 'account_expired');

    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) throw new AuthFlowError('Credenciais inválidas.', 'Credenciais inválidas.');

    if (RENEW_ON_LOGIN) {
      await pool.query(`UPDATE users SET expires_at = NOW() + ($2 || ' days')::interval, updated_at = NOW() WHERE id = $1`, [user.id, USER_ACCOUNT_VALIDITY_DAYS]);
    }

    const lsid = await createLoginSession(user.id, {
      ...params,
      stage: 'login',
      ue: { ip: params['UE-IP'] || params.ue_ip || params.uip, mac: params['UE-MAC'] || params.ue_mac || params.client_mac },
      radius_username: user.username_radius,
      login_password: password
    });

    await sendOtpForUser({ userId: user.id, phoneE164: user.phone_e164, reason: 'login' });

    return res.redirect(`/verify/sms?lsid=${encodeURIComponent(lsid)}`);
  } catch (error) {
    logError('login_attempt_failed', { ...requestContext, reason: error.reason || undefined, error });
    return genericInvalidCredentials(res, params, error.statusCode || 401);
  }
});

app.post('/verify/sms/resend', async (req, res) => {
  const lsid = String(req.body.lsid || '');
  const sessionQuery = await pool.query(
    `SELECT ls.id, ls.user_id, ls.expires_at, ls.consumed_at, u.phone_e164
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     WHERE ls.id = $1`,
    [lsid]
  );
  if (sessionQuery.rowCount === 0) return genericInvalidCredentials(res, {});

  const session = sessionQuery.rows[0];
  if (session.consumed_at || new Date(session.expires_at) < new Date()) return genericInvalidCredentials(res, {});

  const cooldown = await ensureResendCooldown(session.user_id);
  if (!cooldown.allowed) {
    return res.status(429).render('verify_sms', {
      title: 'Verificar SMS',
      error: `Aguarde ${cooldown.waitSeconds}s para reenviar o código.`,
      message: null,
      lsid,
      maskedPhone: session.phone_e164.replace(/(\+55\d{2})\d{5}(\d{4})/, '$1*****$2'),
      resendWaitSeconds: cooldown.waitSeconds
    });
  }

  await sendOtpForUser({ userId: session.user_id, phoneE164: session.phone_e164, reason: 'resend' });
  return res.redirect(`/verify/sms?lsid=${encodeURIComponent(lsid)}`);
});

app.post('/verify/sms', async (req, res) => {
  const normalizedBody = normalizeBodyFields(req.body);
  const parsed = verifySmsSchema.safeParse(normalizedBody);
  const lsid = String(normalizedBody.lsid || '');

  if (!parsed.success) {
    return res.status(400).render('verify_sms', { title: 'Verificar SMS', error: 'Código inválido ou expirado.', message: null, lsid, maskedPhone: '', resendWaitSeconds: OTP_RESEND_COOLDOWN_SECONDS });
  }

  const { code } = parsed.data;
  try {
    const sessionQuery = await pool.query(
      `SELECT ls.id, ls.user_id, ls.ctx_json, ls.expires_at, ls.consumed_at, u.username_radius, u.phone_e164, u.cpf_normalizado
       FROM login_sessions ls
       JOIN users u ON u.id = ls.user_id
       WHERE ls.id = $1`,
      [parsed.data.lsid]
    );

    if (sessionQuery.rowCount === 0) throw new AuthFlowError('Sessão não encontrada.', 'Código inválido ou expirado.');
    const session = sessionQuery.rows[0];
    if (session.consumed_at || new Date(session.expires_at) < new Date()) throw new AuthFlowError('Sessão inválida.', 'Código inválido ou expirado.');

    const otp = await getLatestOtp(session.user_id);
    if (!otp || otp.verified_at || otp.blocked_at || new Date(otp.expires_at) < new Date()) {
      throw new AuthFlowError('OTP inválido.', 'Código inválido ou expirado.');
    }

    const updateOtp = await pool.query(
      `UPDATE otp_codes
       SET attempts = attempts + 1,
           blocked_at = CASE WHEN attempts + 1 >= $2 THEN NOW() ELSE blocked_at END
       WHERE id = $1
       RETURNING attempts, blocked_at`,
      [otp.id, OTP_MAX_ATTEMPTS]
    );
    const attempts = updateOtp.rows[0]?.attempts || 0;
    if (updateOtp.rows[0]?.blocked_at) throw new AuthFlowError('OTP bloqueado por tentativas.', 'Código inválido ou expirado.');

    const otpOk = await argon2.verify(otp.code_hash, code);
    if (!otpOk) {
      logInfo('otp_verify_failed', { lsid: parsed.data.lsid, user_id: session.user_id, attempts });
      throw new AuthFlowError('OTP inválido.', 'Código inválido ou expirado.');
    }

    await pool.query(`UPDATE otp_codes SET verified_at = NOW() WHERE id = $1`, [otp.id]);
    await pool.query(
      `INSERT INTO user_verifications (user_id, phone_verified_at)
       VALUES ($1, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         phone_verified_at = COALESCE(user_verifications.phone_verified_at, NOW()),
         updated_at = NOW()`,
      [session.user_id]
    );

    const ctx = session.ctx_json || {};
    const ueIp = ctx.ue?.ip;
    const ueMac = ctx.ue?.mac;
    if (!ueIp || !ueMac) throw new AuthFlowError('Parâmetros WISPr ausentes.', 'Código válido, mas faltam parâmetros de rede.', 400);

    const nbiResult = await loginAndPoll({
      ueIp,
      ueMac,
      ueUsername: session.username_radius || `visitante_${session.cpf_normalizado}`,
      uePassword: ctx.login_password || '',
      redirectParams: ctx
    });

    await pool.query(`INSERT INTO auth_events (user_id, login_session_id, event_type, status, detail) VALUES ($1, $2, 'sms_otp_login', $3, $4::jsonb)`, [session.user_id, session.id, nbiResult.success ? 'success' : 'failed', JSON.stringify({ mode: nbiResult.mode })]);

    if (!nbiResult.success) throw new AuthFlowError('NBI falhou.', 'Falha na autorização do acesso. Tente novamente.', 401);

    await pool.query(`UPDATE login_sessions SET consumed_at = NOW() WHERE id = $1`, [session.id]);
    res.cookie('portal_session', String(session.user_id), { maxAge: SESSION_MAX_AGE_MS, httpOnly: true, sameSite: 'lax' });

    logInfo('otp_verify_success', { lsid: session.id, user_id: session.user_id, ue_ip: ueIp, ue_mac: ueMac });
    return res.redirect(getOriginalUrl(ctx));
  } catch (error) {
    logError('otp_verify_error', { lsid, error });
    return res.status(error.statusCode || 401).render('verify_sms', {
      title: 'Verificar SMS',
      error: 'Código inválido ou expirado.',
      message: null,
      lsid,
      maskedPhone: '',
      resendWaitSeconds: OTP_RESEND_COOLDOWN_SECONDS
    });
  }
});

app.get('/terms', (_, res) => {
  res.render('terms', { title: 'Termos de Uso' });
});

app.get('/success', (req, res) => {
  res.render('success', { title: 'Conectado' });
});

async function bootstrap() {
  await runMigrations(pool);
  app.listen(PORT, () => {
    console.log(`Portal online na porta ${PORT}`);
    console.log(`Log estruturado em stdout com timezone ${LOG_TZ}`);
    if (AUTH_LOG_FILE_PATH) console.log(`Log estruturado também em arquivo: ${AUTH_LOG_FILE_PATH}`);
  });
}

bootstrap().catch((error) => {
  console.error('Falha ao iniciar aplicação:', error);
  process.exit(1);
});
