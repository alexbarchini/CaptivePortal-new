require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const argon2 = require('argon2');

const { pool } = require('./db');
const { runMigrations } = require('./db/migrate');
const { registerSchema, loginSchema, cleanDigits } = require('./utils/validators');
const { loginAndPoll } = require('./services/nbi');
const { logInfo, logError, LOG_TZ, AUTH_LOG_FILE_PATH } = require('./utils/logger');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const USER_ACCOUNT_VALIDITY_DAYS = Number(process.env.USER_ACCOUNT_VALIDITY_DAYS || 30);
const RENEW_ON_LOGIN = (process.env.RENEW_ON_LOGIN || 'true').toLowerCase() !== 'false';
const SESSION_MAX_AGE_MS = USER_ACCOUNT_VALIDITY_DAYS * 24 * 60 * 60 * 1000;

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

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_PER_MINUTE || 40),
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/register', authLimiter);
app.use('/login', authLimiter);

function getRedirectParams(req) {
  return normalizeBodyFields({ ...req.query, ...req.body });
}

function getOriginalUrl(params) {
  return params.url || params.orig_url || '/success';
}

function normalizeBodyFields(body = {}) {
  return Object.fromEntries(
    Object.entries(body).map(([key, value]) => [key, Array.isArray(value) ? value[0] : value])
  );
}

function sanitizeParams(params = {}) {
  const sanitized = normalizeBodyFields(params);
  delete sanitized.password;
  delete sanitized.confirmPassword;
  if (sanitized.cpf) {
    sanitized.cpf = cleanDigits(sanitized.cpf);
  }
  return sanitized;
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
  res.render('portal', {
    title: 'Portal Visitantes TRT9',
    error: null,
    message: null,
    params: req.query
  });
});

app.get('/register', (req, res) => {
  res.render('register', {
    title: 'Cadastro de visitante',
    error: null,
    values: {},
    params: req.query
  });
});

app.get('/terms', (_, res) => {
  res.render('terms', { title: 'Termos de Uso' });
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
    logInfo('register_attempt_validation_failed', {
      ...requestContext,
      validation_error: parsed.error.issues[0].message
    });
    return res.status(400).render('register', {
      title: 'Cadastro de visitante',
      error: parsed.error.issues[0].message,
      values: normalizedBody,
      params
    });
  }

  const { cpf, phone, password } = parsed.data;
  const usernameRadius = `visitante_${cpf}`;

  try {
    const passwordHash = await argon2.hash(password);
    const userInsert = await pool.query(
      `INSERT INTO users (cpf, phone, username_radius, password_hash, is_active, expires_at)
       VALUES ($1, $2, $3, $4, true, NOW() + ($5 || ' days')::interval)
       ON CONFLICT (cpf) DO UPDATE SET
        phone = EXCLUDED.phone,
        username_radius = EXCLUDED.username_radius,
        password_hash = EXCLUDED.password_hash,
        expires_at = NOW() + ($5 || ' days')::interval,
        updated_at = NOW()
       RETURNING id, cpf`,
      [cpf, phone, usernameRadius, passwordHash, USER_ACCOUNT_VALIDITY_DAYS]
    );

    const user = userInsert.rows[0];
    await pool.query(
      `INSERT INTO lgpd_consents (
          user_id, accepted_terms, accepted_privacy, accepted_processing,
          terms_version, privacy_version, accepted_at, ip, user_agent
) VALUES ($1, true, false, true, $2, $3, NOW(), $4, $5)`,
      [
        user.id,
        process.env.TERMS_VERSION || 'v1.0',
        process.env.PRIVACY_VERSION || 'v1.0',
        req.ip,
        req.get('user-agent') || ''
      ]
    );

    logInfo('register_attempt_success', {
      ...requestContext,
      user_id: user.id,
      normalized_cpf: user.cpf
    });

    return res.render('portal', {
      title: 'Portal Visitantes TRT9',
      error: null,
      message: 'Cadastro realizado com sucesso. Faça login para continuar.',
      params
    });
  } catch (error) {
    logError('register_attempt_failed', {
      ...requestContext,
      error
    });
    return res.status(500).render('register', {
      title: 'Cadastro de visitante',
      error: 'Falha ao cadastrar usuário.',
      values: normalizedBody,
      params
    });
  }
});

app.post('/login', async (req, res) => {
  const params = getRedirectParams(req);
  const normalizedBody = normalizeBodyFields(req.body);
  const requestContext = {
    cpf: cleanDigits(normalizedBody.cpf || ''),
    request_ip: req.ip,
    user_agent: req.get('user-agent') || '',
    params: sanitizeParams(params)
  };

  logInfo('login_attempt_started', requestContext);
  const parsed = loginSchema.safeParse(normalizedBody);
  if (!parsed.success) {
    logInfo('login_attempt_validation_failed', {
      ...requestContext,
      validation_error: parsed.error.issues[0].message
    });
    return res.status(400).render('portal', {
      title: 'Portal Visitantes TRT9',
      error: parsed.error.issues[0].message,
      message: null,
      params
    });
  }

  const { cpf, password } = parsed.data;
  try {
    const query = await pool.query(
      `SELECT id, cpf, username_radius, password_hash, is_active
             , expires_at
       FROM users
       WHERE regexp_replace(cpf, '\\D', '', 'g') = $1`,
      [cpf]
    );
    if (query.rowCount === 0) {
      throw new AuthFlowError('Usuário não encontrado para CPF informado.', 'CPF ou senha inválidos.');
    }

    const user = query.rows[0];
    if (!user.is_active) {
      throw new AuthFlowError('Usuário inativo.', 'Usuário inativo. Entre em contato com o suporte.');
    }

    if (new Date(user.expires_at) < new Date()) {
      throw new AuthFlowError('Conta expirada para o CPF informado.', 'Conta expirada. Faça um novo cadastro.', 401, 'account_expired');
    }

    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
      throw new AuthFlowError('Falha na verificação do hash Argon2 para o usuário.', 'CPF ou senha inválidos.');
    }

    logInfo('login_password_verified', {
      ...requestContext,
      user_id: user.id,
      normalized_cpf: user.cpf,
      username_radius: user.username_radius
    });

    if (RENEW_ON_LOGIN) {
      await pool.query(
        `UPDATE users
         SET expires_at = NOW() + ($2 || ' days')::interval,
             updated_at = NOW()
         WHERE id = $1`,
        [user.id, USER_ACCOUNT_VALIDITY_DAYS]
      );
    }

    const ueIp = params['UE-IP'] || params.ue_ip || params.uip;
    const ueMac = params['UE-MAC'] || params.ue_mac || params.client_mac;

    if (!ueIp || !ueMac) {
      throw new AuthFlowError(
        'Parâmetros de cliente (UE-IP/UE-MAC) ausentes no redirect WISPr.',
        'Login válido, mas faltam parâmetros de rede (UE-IP/UE-MAC) no redirect do portal.',
        400
      );
    }

    const nbiResult = await loginAndPoll({
      ueIp,
      ueMac,
      ueUsername: user.username_radius || `visitante_${user.cpf}`,
      uePassword: password,
      redirectParams: params
    });

    logInfo('login_attempt_nbi_result', {
      ...requestContext,
      user_id: user.id,
      normalized_cpf: user.cpf,
      ue_ip: ueIp,
      ue_mac: ueMac,
      nbi_success: nbiResult.success,
      nbi_mode: nbiResult.mode,
      nbi_detail: nbiResult.detail
    });

    if (nbiResult.success) {
      res.cookie('portal_session', String(user.id), {
        maxAge: SESSION_MAX_AGE_MS,
        httpOnly: true,
        sameSite: 'lax'
      });
      return res.redirect(getOriginalUrl(params));
    }

    throw new AuthFlowError(
      `NBI retornou falha na autorização: ${JSON.stringify(nbiResult.detail)}`,
      'Falha na autorização do acesso. Tente novamente.',
      401
    );
  } catch (error) {
    logError('login_attempt_failed', {
      ...requestContext,
      normalized_cpf: parsed.success ? parsed.data.cpf : normalizedBody.cpf,
      reason: error.reason || undefined,
      error
    });

    const statusCode = error instanceof AuthFlowError ? error.statusCode : 401;
    const userMessage = 'Credenciais inválidas.';

    return res.status(statusCode).render('portal', {
      title: 'Portal Visitantes TRT9',
      error: userMessage,
      message: null,
      params
    });
  }
});

app.get('/success', (req, res) => {
  res.render('success', { title: 'Conectado' });
});

async function bootstrap() {
  await runMigrations(pool);
  app.listen(PORT, () => {
    console.log(`Portal online na porta ${PORT}`);
    console.log(`Log estruturado em stdout com timezone ${LOG_TZ}`);
    if (AUTH_LOG_FILE_PATH) {
      console.log(`Log estruturado também em arquivo: ${AUTH_LOG_FILE_PATH}`);
    }
  });
}

bootstrap().catch((error) => {
  console.error('Falha ao iniciar aplicação:', error);
  process.exit(1);
});
