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
  const parsed = registerSchema.safeParse(normalizedBody);
  if (!parsed.success) {
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

    return res.render('portal', {
      title: 'Portal Visitantes TRT9',
      error: null,
      message: 'Cadastro realizado com sucesso. Faça login para continuar.',
      params
    });
  } catch (error) {
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
  const parsed = loginSchema.safeParse(normalizedBody);
  if (!parsed.success) {
    return res.status(400).render('portal', {
      title: 'Portal Visitantes TRT9',
      error: parsed.error.issues[0].message,
      message: null,
      params
    });
  }

  const { cpf, password } = parsed.data;
  try {
    const query = await pool.query('SELECT id, cpf, username_radius, password_hash, is_active FROM users WHERE cpf = $1', [cpf]);
    if (query.rowCount === 0) throw new Error('Usuário não encontrado');

    const user = query.rows[0];
    if (!user.is_active) throw new Error('Usuário inativo');

    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) throw new Error('Senha inválida');

    const ueIp = params['UE-IP'] || params.ue_ip || params.uip;
    const ueMac = params['UE-MAC'] || params.ue_mac || params.client_mac;

    if (!ueIp || !ueMac) {
      throw new Error('Parâmetros de cliente (UE-IP/UE-MAC) ausentes no redirect WISPr.');
    }

    const nbiResult = await loginAndPoll({
      ueIp,
      ueMac,
      ueUsername: user.username_radius,
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

    if (nbiResult.success) {
      return res.redirect(getOriginalUrl(params));
    }

    return res.status(401).render('portal', {
      title: 'Portal Visitantes TRT9',
      error: 'Falha na autorização do acesso. Tente novamente.',
      message: null,
      params
    });
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

    return res.status(401).render('portal', {
      title: 'Portal Visitantes TRT9',
      error: 'CPF ou senha inválidos, ou falha na autorização SmartZone.',
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
  });
}

bootstrap().catch((error) => {
  console.error('Falha ao iniciar aplicação:', error);
  process.exit(1);
});
