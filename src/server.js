require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const argon2 = require('argon2');

const { pool } = require('./db');
const { runMigrations } = require('./db/migrate');
const { registerSchema, loginSchema } = require('./utils/validators');
const { loginAndPoll } = require('./services/nbi');
const { LOG_PATH, logInfo, logError } = require('./utils/logger');

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
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
  return { ...req.query, ...req.body };
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
  const sanitized = { ...params };
  delete sanitized.password;
  delete sanitized.confirmPassword;
  return sanitized;
}

class AuthFlowError extends Error {
  constructor(message, userMessage, statusCode = 401) {
    super(message);
    this.name = 'AuthFlowError';
    this.userMessage = userMessage;
    this.statusCode = statusCode;
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
    cpf: normalizedBody.cpf,
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
      `INSERT INTO users (cpf, phone, username_radius, password_hash, is_active)
       VALUES ($1, $2, $3, $4, true)
       ON CONFLICT (cpf) DO UPDATE SET
        phone = EXCLUDED.phone,
        username_radius = EXCLUDED.username_radius,
        password_hash = EXCLUDED.password_hash,
        updated_at = NOW()
       RETURNING id, cpf`,
      [cpf, phone, usernameRadius, passwordHash]
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
    cpf: normalizedBody.cpf,
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

    await pool.query(
      `INSERT INTO auth_events (user_id, cpf, client_mac, client_ip, ap, ssid, result, reason, raw_params_json)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
      [
        user.id,
        user.cpf,
        params.client_mac || params['UE-MAC'] || ueMac,
        params.uip || params.client_ip || params['UE-IP'] || ueIp,
        params.apip || params.ap,
        params.ssid,
        nbiResult.success ? 'success' : 'fail',
        nbiResult.success ? 'authorized' : JSON.stringify(nbiResult.detail),
        JSON.stringify(params)
      ]
    );

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
      return res.redirect(getOriginalUrl(params));
    }

    throw new AuthFlowError(
      `NBI retornou falha na autorização: ${JSON.stringify(nbiResult.detail)}`,
      'Falha na autorização do acesso. Tente novamente.',
      401
    );
  } catch (error) {
    await pool.query(
      `INSERT INTO auth_events (user_id, cpf, client_mac, client_ip, ap, ssid, result, reason, raw_params_json)
       VALUES (NULL, $1, $2, $3, $4, $5, 'fail', $6, $7::jsonb)`,
      [
        parsed.success ? parsed.data.cpf : req.body.cpf,
        params.client_mac || params['UE-MAC'] || null,
        params.uip || params.client_ip || params['UE-IP'] || null,
        params.apip || params.ap || null,
        params.ssid || null,
        error.message,
        JSON.stringify(params)
      ]
    );

    logError('login_attempt_failed', {
      ...requestContext,
      normalized_cpf: parsed.success ? parsed.data.cpf : normalizedBody.cpf,
      error
    });

    const statusCode = error instanceof AuthFlowError ? error.statusCode : 401;
    const userMessage = error instanceof AuthFlowError
      ? error.userMessage
      : 'CPF ou senha inválidos.';

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
    console.log(`Log de autenticação em: ${LOG_PATH}`);
  });
}

bootstrap().catch((error) => {
  console.error('Falha ao iniciar aplicação:', error);
  process.exit(1);
});
