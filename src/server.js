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
const { loginAsync, disconnectAsync } = require('./services/ruckusNbi');
const { buildSmsProvider } = require('./services/smsProvider');
const { logInfo, logError, LOG_TZ, AUTH_LOG_FILE_PATH } = require('./utils/logger');

const app = express();
const TRUST_PROXY = (process.env.TRUST_PROXY || 'true').toLowerCase() !== 'false';
const PORT = Number(process.env.PORT || 3000);
const USER_ACCOUNT_VALIDITY_DAYS = Number(process.env.USER_ACCOUNT_VALIDITY_DAYS || 30);
const RENEW_ON_LOGIN = (process.env.RENEW_ON_LOGIN || 'true').toLowerCase() !== 'false';
const SESSION_MAX_AGE_MS = USER_ACCOUNT_VALIDITY_DAYS * 24 * 60 * 60 * 1000;
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 300);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const OTP_RESEND_COOLDOWN_SECONDS = Number(process.env.OTP_RESEND_COOLDOWN_SECONDS || 60);
const OTP_VALID_REUSE_WINDOW_SECONDS = Number(process.env.OTP_VALID_REUSE_WINDOW_SECONDS || 120);
const LOGIN_SESSION_TTL_SECONDS = Number(process.env.LOGIN_SESSION_TTL_SECONDS || 600);
const ADMIN_SESSION_COOKIE_NAME = 'admin_session';
const ADMIN_SESSION_TTL_MS = Number(process.env.ADMIN_SESSION_TTL_HOURS || 8) * 60 * 60 * 1000;
const ADMIN_ALLOWED_CIDRS = String(process.env.ADMIN_ALLOWED_CIDRS || '10.9.62.0/23').split(',').map((item) => item.trim()).filter(Boolean);
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD_HASH || 'admin-session-secret';
const smsProvider = buildSmsProvider();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
if (TRUST_PROXY) app.set('trust proxy', true);

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
const adminLoginLimiter = rateLimit({ windowMs: 60 * 1000, limit: Number(process.env.ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE || 10), standardHeaders: true, legacyHeaders: false });

app.use('/register', authLimiter);
app.use('/login', authLimiter);
app.use('/verify/sms', verifyLimiter);
app.use('/otp/verify', verifyLimiter);
app.use('/admin', allowCidrs, (req, res, next) => {
  if (req.path === '/login') return next();
  return requireAdminSession(req, res, next);
});

function getOriginalUrl(params) {
  const candidate = params.url || params.orig_url || '/success';
  try {
    return decodeURIComponent(candidate);
  } catch (_) {
    return candidate;
  }
}
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
function buildCtxFromSession(session = {}) {
  return {
    nbiIP: session.nbi_ip || '',
    uip: session.uip || '',
    client_mac: session.client_mac || '',
    proxy: session.proxy || '',
    ssid: session.ssid || '',
    sip: session.sip || '',
    dn: session.dn || '',
    wlanName: session.wlan_name || '',
    url: session.url || '',
    apip: session.apip || '',
    vlan: session.vlan || '',
    stage: session.stage || '',
    login_password: session.login_password || ''
  };
}
function looksLikePlainMac(mac = '') {
  const compact = String(mac || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  return /^[A-F0-9]{12}$/.test(compact);
}
function maskMac(mac = '') {
  const value = String(mac || '');
  if (!value) return '';
  const compact = value.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  if (!looksLikePlainMac(value)) {
    if (value.length <= 6) return '***';
    return `${value.slice(0, 3)}...${value.slice(-3)}`;
  }
  return `${compact.slice(0, 2)}:**:**:**:${compact.slice(-2)}`;
}
function normalizeMacIfPlain(mac = '') {
  if (!looksLikePlainMac(mac)) return String(mac || '');
  return String(mac || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
}
function resolveWisprParams(params = {}) {
  const userIp = params.uip || params['UE-IP'] || params.client_ip;
  const userMac = params.client_mac || params['UE-MAC'];
  const proxy = params.proxy || '0';
  const nbiIP = params.nbiIP;
  return { userIp, userMac, proxy, nbiIP };
}
function hasRequiredWispr(ctx = {}) {
  return Boolean(String(ctx.nbiIP || '').trim() && String(ctx.uip || '').trim() && String(ctx.client_mac || '').trim());
}
function pickWisprParams(raw = {}) {
  const params = normalizeBodyFields(raw);
  return {
    nbiIP: params.nbiIP || '',
    uip: params.uip || params['UE-IP'] || params.client_ip || '',
    client_mac: params.client_mac || params['UE-MAC'] || '',
    proxy: params.proxy || '0',
    ssid: params.ssid || '',
    sip: params.sip || '',
    dn: params.dn || '',
    wlanName: params.wlanName || params.wlan_name || '',
    url: params.url || params.orig_url || '/success',
    apip: params.apip || '',
    vlan: params.vlan || ''
  };
}
function ctxKeys(ctx = {}) {
  return Object.entries(ctx)
    .filter(([key, value]) => {
      const normalized = String(value || '').trim();
      if (!normalized) return false;
      if (key === 'stage' || key === 'login_password') return false;
      if (key === 'proxy' && normalized === '0') return false;
      if (key === 'url' && normalized === '/success') return false;
      return true;
    })
    .map(([key]) => key)
    .sort();
}
function logCtxPresence(event, lsid, ctx) {
  const keys = ctxKeys(ctx || {});
  logInfo(event, { lsid, ctx_present: keys.length > 0, ctx_keys: keys });
}
function renderInvalidAccess(res, { title = 'Acesso inválido', statusCode = 400, message = 'Sessão expirada ou entrada inválida.' } = {}) {
  return res.status(statusCode).render('invalid_access', {
    title,
    message
  });
}
function genericInvalidCredentials(res, lsid = '', statusCode = 401) {
  return res.status(statusCode).render('portal', { title: 'Portal Visitantes TRT9', error: 'Credenciais inválidas.', message: null, lsid, contextBadge: null });
}


function maskCpf(cpf = '') {
  const digits = cleanDigits(cpf);
  if (digits.length !== 11) return '***.***.***-**';
  return `${digits.slice(0, 3)}.***.***-${digits.slice(-2)}`;
}
function formatDateTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return new Intl.DateTimeFormat('pt-BR', {
    timeZone: LOG_TZ,
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}
function formatDurationSince(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  const diffMs = Date.now() - date.getTime();
  if (diffMs <= 0) return 'menos de 1 minuto';
  const totalMinutes = Math.floor(diffMs / 60000);
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours <= 0) return `${minutes} minuto${minutes === 1 ? '' : 's'}`;
  if (minutes === 0) return `${hours} hora${hours === 1 ? '' : 's'}`;
  return `${hours} hora${hours === 1 ? '' : 's'} e ${minutes} minuto${minutes === 1 ? '' : 's'}`;
}

function formatDurationHms(secondsValue) {
  const totalSeconds = Number(secondsValue);
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) return '-';
  const seconds = Math.floor(totalSeconds % 60);
  const minutes = Math.floor((totalSeconds / 60) % 60);
  const hours = Math.floor(totalSeconds / 3600);
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, '0')).join(':');
}

function parseDatetimeLocal(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function normalizeMacForFilter(mac = '') {
  return String(mac || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
}

function normalizeClientIp(ip = '') {
  if (!ip) return '';
  const value = String(ip).trim();
  if (value.startsWith('::ffff:')) return value.replace('::ffff:', '');
  return value;
}


function ipToInteger(ip = '') {
  const normalized = normalizeClientIp(ip);
  const parts = normalized.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
  return octets.reduce((acc, octet) => ((acc << 8) + octet) >>> 0, 0);
}

function parseCidr(cidr = '') {
  const [network, bitsRaw] = String(cidr).split('/');
  const bits = Number(bitsRaw);
  const networkInt = ipToInteger(network);
  if (networkInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
  return { network: (networkInt & mask) >>> 0, mask };
}

function isIpAllowedByCidrs(ip, cidrs = ADMIN_ALLOWED_CIDRS) {
  const ipInt = ipToInteger(ip);
  if (ipInt === null) return false;
  return cidrs.some((cidr) => {
    const parsed = parseCidr(cidr);
    if (!parsed) return false;
    return ((ipInt & parsed.mask) >>> 0) === parsed.network;
  });
}

function signAdminSession(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', ADMIN_SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${signature}`;
}

function parseAdminSessionToken(token = '') {
  const value = String(token || '');
  const [data, signature] = value.split('.');
  if (!data || !signature) return null;
  const expected = crypto.createHmac('sha256', ADMIN_SESSION_SECRET).update(data).digest('base64url');
  if (signature !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!payload || !payload.user || !payload.exp) return null;
    if (Date.now() > Number(payload.exp)) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function allowCidrs(req, res, next) {
  if (isIpAllowedByCidrs(req.ip)) return next();
  return res.status(403).send('Acesso administrativo não permitido para este IP.');
}

function requireAdminSession(req, res, next) {
  const payload = parseAdminSessionToken(req.cookies?.[ADMIN_SESSION_COOKIE_NAME]);
  if (!payload) return res.redirect('/admin/login');
  req.adminSession = payload;
  return next();
}

async function getActiveSessionByUserId(userId) {
  if (!userId) return null;
  const result = await pool.query(
    `SELECT pas.id, pas.user_id, pas.ue_ip, pas.ue_mac, pas.ssid, pas.authorized_at, pas.last_seen_at,
            u.nome, u.cpf_formatado, u.cpf_normalizado
     FROM portal_active_sessions pas
     JOIN users u ON u.id = pas.user_id
     WHERE pas.user_id = $1 AND pas.ended_at IS NULL
     ORDER BY pas.authorized_at DESC
     LIMIT 1`,
    [userId]
  );
  return result.rows[0] || null;
}

async function getActiveSessionByIp(clientIp) {
  if (!clientIp) return null;
  const result = await pool.query(
    `SELECT pas.id, pas.user_id, pas.ue_ip, pas.ue_mac, pas.ssid, pas.authorized_at, pas.last_seen_at,
            u.nome, u.cpf_formatado, u.cpf_normalizado
     FROM portal_active_sessions pas
     JOIN users u ON u.id = pas.user_id
     WHERE pas.ue_ip = $1 AND pas.ended_at IS NULL
     ORDER BY pas.authorized_at DESC
     LIMIT 1`,
    [clientIp]
  );
  return result.rows[0] || null;
}

async function touchActiveSession(sessionId) {
  if (!sessionId) return;
  await pool.query(`UPDATE portal_active_sessions SET last_seen_at = NOW() WHERE id = $1`, [sessionId]);
}

async function createPortalSession(params) {
  const lsid = crypto.randomUUID();
  const ctx = pickWisprParams(params);
  await pool.query(
    `INSERT INTO login_sessions (
      id, ctx_json, nbi_ip, uip, client_mac, proxy, ssid, sip, dn, wlan_name, url, apip, vlan, expires_at
    ) VALUES (
      $1, $2::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW() + ($14 || ' seconds')::interval
    )`,
    [
      lsid,
      JSON.stringify(ctx),
      ctx.nbiIP,
      ctx.uip,
      normalizeMacIfPlain(ctx.client_mac),
      ctx.proxy,
      ctx.ssid,
      ctx.sip,
      ctx.dn,
      ctx.wlanName,
      ctx.url,
      ctx.apip,
      ctx.vlan,
      LOGIN_SESSION_TTL_SECONDS
    ]
  );
  logCtxPresence('portal_ctx_captured', lsid, ctx);
  return lsid;
}

function buildContextBadge(ctx = {}) {
  if (!hasRequiredWispr(ctx)) return null;
  return {
    ssid: ctx.ssid || 'desconhecido',
    uip: ctx.uip,
    macMasked: maskMac(ctx.client_mac)
  };
}

async function getLoginSession(lsid) {
  const result = await pool.query('SELECT * FROM login_sessions WHERE id = $1', [lsid]);
  return result.rows[0] || null;
}

async function resolvePreferredLsid(req, providedLsid = '') {
  const bodyLsid = String(providedLsid || '').trim();
  const cookieLsid = String(req.cookies?.portal_lsid || '').trim();

  if (!bodyLsid && !cookieLsid) return { lsid: '', session: null };

  const uniqueIds = [...new Set([bodyLsid, cookieLsid].filter(Boolean))];
  const sessions = [];
  for (const id of uniqueIds) {
    const session = await getLoginSession(id);
    if (session) sessions.push({ id, session });
  }

  const validWithCtx = sessions.find(({ session }) => {
    const ctx = buildCtxFromSession(session);
    return new Date(session.expires_at) >= new Date() && hasRequiredWispr(ctx);
  });
  if (validWithCtx) return { lsid: validWithCtx.id, session: validWithCtx.session };

  const byProvided = sessions.find(({ id }) => id === bodyLsid);
  if (byProvided) return { lsid: byProvided.id, session: byProvided.session };

  const byCookie = sessions.find(({ id }) => id === cookieLsid);
  if (byCookie) return { lsid: byCookie.id, session: byCookie.session };

  return { lsid: bodyLsid || cookieLsid, session: null };
}

async function sendOtpForUser({ userId, phoneE164, reason, ueIp = null, ueMac = null, lsid = null }) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await argon2.hash(code);

  await smsProvider.send(phoneE164, `Seu código de acesso do Portal TRT9 é ${code}. Ele expira em ${Math.ceil(OTP_TTL_SECONDS / 60)} minutos.`);

  await pool.query(
    `INSERT INTO otp_codes (user_id, login_session_id, channel, destination, code_hash, expires_at, ue_ip, ue_mac)
     VALUES ($1, $2, 'sms', $3, $4, NOW() + ($5 || ' seconds')::interval, $6, $7)`,
    [userId, lsid, phoneE164, codeHash, OTP_TTL_SECONDS, ueIp, normalizeMacIfPlain(ueMac)]
  );

  logInfo('otp_sent', { lsid, user_id: userId, destination: phoneE164, reason, ue_ip: ueIp, ue_mac: maskMac(ueMac) });
}

async function getLatestOtp(userId, lsid = null) {
  if (lsid) {
    const result = await pool.query(
      `SELECT * FROM otp_codes
       WHERE user_id = $1 AND login_session_id = $2 AND channel = 'sms'
       ORDER BY created_at DESC LIMIT 1`,
      [userId, lsid]
    );
    return result.rows[0] || null;
  }
  const result = await pool.query(
    `SELECT * FROM otp_codes
     WHERE user_id = $1 AND channel = 'sms'
     ORDER BY created_at DESC LIMIT 1`,
    [userId]
  );
  return result.rows[0] || null;
}

async function ensureResendCooldown(userId, lsid = null) {
  const latestOtp = await getLatestOtp(userId, lsid);
  if (!latestOtp) return { allowed: true, waitSeconds: 0 };

  const cooldownSql = `SELECT GREATEST(0, $2 - EXTRACT(EPOCH FROM (NOW() - $1::timestamptz))::int) AS wait_seconds`;
  const cooldown = await pool.query(cooldownSql, [latestOtp.created_at, OTP_RESEND_COOLDOWN_SECONDS]);
  const waitSeconds = cooldown.rows[0].wait_seconds;
  return { allowed: waitSeconds <= 0, waitSeconds };
}

async function hasRecentValidOtpForContext({ userId, ueIp, ueMac }) {
  if (!userId || !ueIp || !ueMac) return false;
  const result = await pool.query(
    `SELECT 1
     FROM otp_codes
     WHERE user_id = $1
       AND channel = 'sms'
       AND ue_ip = $2
       AND ue_mac = $3
       AND verified_at IS NOT NULL
       AND verified_at >= NOW() - ($4 || ' seconds')::interval
     LIMIT 1`,
    [userId, ueIp, normalizeMacIfPlain(ueMac), OTP_VALID_REUSE_WINDOW_SECONDS]
  );
  return result.rowCount > 0;
}

async function authorizeViaNbi(ctx, user) {
  const { userIp, userMac, proxy, nbiIP } = resolveWisprParams(ctx);
  if (!userIp || !userMac || !nbiIP) {
    throw new AuthFlowError(
      'Parâmetros WISPr ausentes.',
      'Acesse o portal a partir do Wi-Fi visitante (redirect captive).',
      400,
      'missing_wispr_params'
    );
  }

  logInfo('wispr_params_received', { lsid: user.sessionId, user_id: user.userId, user_ip: userIp, user_mac: maskMac(userMac), proxy, nbi_ip: nbiIP });

  return loginAsync({
    nbiIP,
    ueIp: userIp,
    ueMac: userMac,
    proxy,
    ueUsername: user.usernameRadius || `visitante_${user.cpf}`,
    uePassword: ctx.login_password || ''
  });
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


app.get('/admin/login', (req, res) => {
  res.render('admin_login', { title: 'Administração', error: null });
});

app.post('/admin/login', adminLoginLimiter, async (req, res) => {
  const adminUser = String(process.env.ADMIN_USER || '');
  const adminPasswordHash = String(process.env.ADMIN_PASSWORD_HASH || '');
  const providedUser = String(req.body.user || '').trim();
  const providedPassword = String(req.body.password || '');

  if (!adminUser || !adminPasswordHash) {
    return res.status(500).render('admin_login', { title: 'Administração', error: 'Admin não configurado no ambiente.' });
  }

  const userMatches = providedUser && providedUser === adminUser;
  const passwordMatches = userMatches ? await argon2.verify(adminPasswordHash, providedPassword) : false;
  if (!userMatches || !passwordMatches) {
    return res.status(401).render('admin_login', { title: 'Administração', error: 'Credenciais inválidas.' });
  }

  const token = signAdminSession({ user: adminUser, exp: Date.now() + ADMIN_SESSION_TTL_MS });
  res.cookie(ADMIN_SESSION_COOKIE_NAME, token, {
    maxAge: ADMIN_SESSION_TTL_MS,
    httpOnly: true,
    sameSite: 'lax'
  });

  return res.redirect('/admin/sessions');
});

app.get('/admin', (req, res) => {
  return res.redirect('/admin/sessions');
});

app.get('/admin/sessions', async (req, res) => {
  const cpfNormalized = cleanDigits(String(req.query.cpf || ''));
  const nameQuery = String(req.query.name || '').trim();
  const ipQuery = normalizeClientIp(String(req.query.ip || ''));
  const macRaw = String(req.query.mac || '').trim();
  const macNormalized = normalizeMacForFilter(macRaw);
  const fromRaw = String(req.query.from || '').trim();
  const toRaw = String(req.query.to || '').trim();
  const offsetRaw = Number.parseInt(String(req.query.offset || '0'), 10);
  const offset = Number.isInteger(offsetRaw) && offsetRaw > 0 ? offsetRaw : 0;
  const fromIso = parseDatetimeLocal(fromRaw);
  const toIso = parseDatetimeLocal(toRaw);

  if (cpfNormalized && cpfNormalized.length !== 11) {
    return res.status(400).render('admin_sessions', {
      title: 'Sessões administrativas',
      adminUser: req.adminSession.user,
      filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw },
      error: 'CPF inválido para consulta.',
      sessions: [],
      pagination: { limit: 50, offset, hasNextPage: false, nextOffset: offset + 50 }
    });
  }

  if (macRaw && macNormalized.length !== 12) {
    return res.status(400).render('admin_sessions', {
      title: 'Sessões administrativas',
      adminUser: req.adminSession.user,
      filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw },
      error: 'MAC inválido para consulta.',
      sessions: [],
      pagination: { limit: 50, offset, hasNextPage: false, nextOffset: offset + 50 }
    });
  }

  if ((fromRaw && !fromIso) || (toRaw && !toIso)) {
    return res.status(400).render('admin_sessions', {
      title: 'Sessões administrativas',
      adminUser: req.adminSession.user,
      filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw },
      error: 'Intervalo de data/hora inválido.',
      sessions: [],
      pagination: { limit: 50, offset, hasNextPage: false, nextOffset: offset + 50 }
    });
  }

  const filters = [];
  const values = [];
  const pushFilter = (sql, value) => {
    values.push(value);
    filters.push(sql.replace('?', `$${values.length}`));
  };

  if (cpfNormalized) pushFilter('u.cpf_normalizado = ?', cpfNormalized);
  if (nameQuery) pushFilter('u.nome ILIKE ?', `%${nameQuery}%`);
  if (ipQuery) pushFilter('ls.uip = ?', ipQuery);
  if (macNormalized) pushFilter("UPPER(regexp_replace(COALESCE(ls.client_mac, ''), '[^A-Fa-f0-9]', '', 'g')) = ?", macNormalized);
  if (fromIso) pushFilter('ls.created_at >= ?', fromIso);
  if (toIso) pushFilter('ls.created_at <= ?', toIso);

  values.push(51, offset);
  const whereClause = filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : '';
  const sessionsResult = await pool.query(
    `SELECT ls.id AS lsid,
            ls.created_at,
            ls.authorized_at,
            ls.consumed_at,
            ls.uip,
            ls.client_mac,
            ls.ssid,
            ls.vlan,
            ls.apip,
            u.nome,
            u.cpf_formatado,
            u.cpf_normalizado,
            EXTRACT(EPOCH FROM (COALESCE(ls.consumed_at, NOW()) - COALESCE(ls.authorized_at, ls.created_at)))::int AS duration_seconds
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     ${whereClause}
     ORDER BY ls.created_at DESC
     LIMIT $${values.length - 1}
     OFFSET $${values.length}`,
    values
  );

  const hasNextPage = sessionsResult.rows.length > 50;
  const sessions = sessionsResult.rows.slice(0, 50).map((session) => ({
    ...session,
    status: !session.authorized_at ? 'OPEN' : (session.consumed_at ? 'CLOSED' : 'AUTHORIZED'),
    duration_hms: formatDurationHms(session.duration_seconds)
  }));

  logInfo('admin_lookup', {
    cpf_normalizado: cpfNormalized || null,
    name_filter: nameQuery || null,
    ip_filter: ipQuery || null,
    mac_filter: macNormalized || null,
    from_filter: fromIso,
    to_filter: toIso,
    offset,
    result_count: sessions.length,
    admin_user: req.adminSession.user,
    request_ip: normalizeClientIp(req.ip)
  });

  return res.render('admin_sessions', {
    title: 'Sessões administrativas',
    adminUser: req.adminSession.user,
    filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw },
    error: null,
    sessions,
    pagination: { limit: 50, offset, hasNextPage, nextOffset: offset + 50 }
  });
});


app.get('/admin/lookup', (req, res) => {
  const query = new URLSearchParams(req.query || {}).toString();
  return res.redirect(query ? `/admin/sessions?${query}` : '/admin/sessions');
});
app.post('/admin/logout', (req, res) => {
  res.clearCookie(ADMIN_SESSION_COOKIE_NAME, { httpOnly: true, sameSite: 'lax' });
  return res.redirect('/admin/login');
});

app.get('/portal', async (req, res) => {
  try {
    const wisprCtx = pickWisprParams(req.query);
    if (hasRequiredWispr(wisprCtx)) {
      const lsid = await createPortalSession(req.query);
      res.cookie('portal_lsid', lsid, {
        maxAge: LOGIN_SESSION_TTL_SECONDS * 1000,
        httpOnly: true,
        sameSite: 'lax'
      });
      return res.render('portal', {
        title: 'Portal Visitantes TRT9',
        error: null,
        message: null,
        lsid,
        contextBadge: buildContextBadge(wisprCtx)
      });
    }

    const portalSessionUserId = String(req.cookies?.portal_session || '').trim();
    const clientIp = normalizeClientIp(req.ip);

    const portalSessionUserIdNumber = Number(portalSessionUserId);
    const hasValidUserIdCookie = Boolean(
      portalSessionUserId &&
      Number.isInteger(portalSessionUserIdNumber) &&
      portalSessionUserIdNumber > 0
    );

    if (!hasValidUserIdCookie) {
      logInfo('portal_ctx_missing_blocked', { request_ip: req.ip, params: sanitizeParams(wisprCtx) });
      return renderInvalidAccess(res, {
        title: 'Acesso inválido',
        statusCode: 400,
        message: 'Conecte-se ao Wi‑Fi de visitantes e abra qualquer site para ser redirecionado automaticamente ao portal.'
      });
    }

    let activeSession = null;
    if (hasValidUserIdCookie) {
      activeSession = await getActiveSessionByUserId(portalSessionUserIdNumber);
    }
    if (!activeSession && clientIp) {
      activeSession = await getActiveSessionByIp(clientIp);
    }

    if (activeSession) {
      await touchActiveSession(activeSession.id);
      return res.render('status', {
        title: 'Status da conexão',
        userName: activeSession.nome || 'Visitante',
        cpfMasked: maskCpf(activeSession.cpf_formatado || activeSession.cpf_normalizado || ''),
        authorizedAtLabel: formatDateTime(activeSession.authorized_at),
        sessionDuration: formatDurationSince(activeSession.authorized_at),
        ssid: activeSession.ssid || 'GuestTRT-Teste',
        ueIp: activeSession.ue_ip || clientIp || '-',
        macMasked: maskMac(activeSession.ue_mac || '')
      });
    }

    return renderInvalidAccess(res, {
      title: 'Acesso inválido',
      statusCode: 400,
      message: 'Conecte-se ao Wi‑Fi de visitantes e abra qualquer site para ser redirecionado automaticamente ao portal.'
    });
  } catch (error) {
    logError('portal_session_create_failed', { error });
    return res.status(500).render('portal', { title: 'Portal Visitantes TRT9', error: 'Falha ao iniciar sessão captive.', message: null, lsid: '', contextBadge: null });
  }
});

app.get('/register', async (req, res) => {
  const lsid = String(req.query.lsid || '');
  if (!lsid) return res.redirect('/portal');
  const session = await getLoginSession(lsid);
  if (!session || new Date(session.expires_at) < new Date()) return res.redirect('/portal');
  logCtxPresence('register_ctx_lookup', lsid, buildCtxFromSession(session));
  res.render('register', { title: 'Cadastro de visitante', error: null, values: {}, lsid });
});

app.get('/verify/sms', async (req, res) => {
  const lsid = String(req.query.lsid || '');
  if (!lsid) return res.redirect('/portal');

  const sessionQuery = await pool.query(
    `SELECT ls.id, ls.user_id, ls.ctx_json, ls.expires_at, ls.consumed_at, ls.authorized_at, ls.nbi_ip, ls.uip, ls.client_mac, ls.proxy, ls.ssid, ls.sip, ls.dn, ls.wlan_name, ls.url, ls.apip, ls.vlan, u.phone_e164
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     WHERE ls.id = $1`,
    [lsid]
  );

  if (sessionQuery.rowCount === 0) return res.redirect('/portal');
  const session = sessionQuery.rows[0];
  if (session.authorized_at || session.consumed_at || new Date(session.expires_at) < new Date()) return res.redirect('/portal');

  logCtxPresence('verify_sms_ctx_lookup', lsid, buildCtxFromSession(session));
  const cooldown = await ensureResendCooldown(session.user_id, lsid);

  return res.render('verify_sms', {
    title: 'Verificar SMS',
    error: null,
    message: 'Digite o código enviado por SMS.',
    lsid,
    maskedPhone: session.phone_e164.replace(/(\+55\d{2})\d{5}(\d{4})/, '$1*****$2'),
    resendWaitSeconds: cooldown.waitSeconds,
    contextBadge: buildContextBadge(buildCtxFromSession(session))
  });
});

app.post('/register', async (req, res) => {
  const lsid = String(req.body.lsid || '');
  const session = lsid ? await getLoginSession(lsid) : null;
  const params = buildCtxFromSession(session || {});
  const normalizedBody = normalizeBodyFields(req.body);
  const requestContext = {
    lsid,
    cpf: cleanDigits(normalizedBody.cpf || ''),
    request_ip: req.ip,
    user_agent: req.get('user-agent') || '',
    params: sanitizeParams(params)
  };

  logInfo('register_attempt_started', requestContext);
  logCtxPresence('register_post_ctx_lookup', lsid, params);
  if (!session || new Date(session.expires_at) < new Date()) {
    return res.status(400).render('portal', {
      title: 'Portal Visitantes TRT9',
      error: 'Sessão do captive expirada, volte e conecte novamente ao Wi-Fi',
      message: null,
      lsid: ''
    });
  }

  if (session.authorized_at || session.consumed_at) {
    return res.redirect(getOriginalUrl(params));
  }

  const parsed = registerSchema.safeParse(normalizedBody);
  if (!parsed.success) {
    return res.status(400).render('register', { title: 'Cadastro de visitante', error: parsed.error.issues[0].message, values: normalizedBody, lsid });
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

    await pool.query(
      `UPDATE login_sessions
       SET user_id = $2, stage = 'register', login_password = $3
       WHERE id = $1`,
      [lsid, user.id, password]
    );
    const wispr = resolveWisprParams(params);
    try {
      await sendOtpForUser({ userId: user.id, phoneE164: user.phone_e164, reason: 'register', ueIp: wispr.userIp, ueMac: wispr.userMac, lsid });
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
        resendWaitSeconds: 0,
        contextBadge: buildContextBadge(params)
      });
    }
  } catch (error) {
    logError('register_attempt_failed', { ...requestContext, error });
    return res.status(500).render('register', { title: 'Cadastro de visitante', error: 'Falha ao cadastrar usuário.', values: normalizedBody, lsid });
  }
});

app.post('/login', async (req, res) => {
  const normalizedBody = normalizeBodyFields(req.body);
  const preferred = await resolvePreferredLsid(req, normalizedBody.lsid);
  const lsid = preferred.lsid;
  const session = preferred.session;
  const params = buildCtxFromSession(session || {});
  const requestContext = { lsid, cpf: cleanDigits(normalizedBody.cpf || ''), request_ip: req.ip, user_agent: req.get('user-agent') || '', params: sanitizeParams(params) };

  logInfo('login_attempt_started', requestContext);
  logCtxPresence('login_ctx_lookup', lsid, params);
  const parsed = loginSchema.safeParse(normalizedBody);
  if (!parsed.success) return genericInvalidCredentials(res, lsid, 401);

  if (!session || new Date(session.expires_at) < new Date() || !hasRequiredWispr(params)) {
    logInfo('ctx_missing_blocked', { lsid, request_ip: req.ip });
    return renderInvalidAccess(res, {
      title: 'Sessão expirada/entrada inválida',
      statusCode: 400,
      message: 'Sessão expirada ou entrada inválida. Conecte-se ao Wi‑Fi de visitantes e abra um site para iniciar novamente o fluxo captive.'
    });
  }
  if (session.authorized_at || session.consumed_at) {
    return res.redirect(getOriginalUrl(params));
  }

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

    await pool.query(
      `UPDATE login_sessions
       SET user_id = $2,
           stage = 'login',
           radius_username = $3,
           login_password = $4
       WHERE id = $1`,
      [lsid, user.id, user.username_radius, password]
    );

    const wispr = resolveWisprParams(params);
    const hasRecentValidOtp = await hasRecentValidOtpForContext({ userId: user.id, ueIp: wispr.userIp, ueMac: wispr.userMac });
    if (!hasRecentValidOtp) {
      await sendOtpForUser({ userId: user.id, phoneE164: user.phone_e164, reason: 'login', ueIp: wispr.userIp, ueMac: wispr.userMac, lsid });
    } else {
      logInfo('otp_resend_skipped_recent_valid', { user_id: user.id, ue_ip: wispr.userIp, ue_mac: maskMac(wispr.userMac), window_seconds: OTP_VALID_REUSE_WINDOW_SECONDS });
    }

    return res.redirect(`/verify/sms?lsid=${encodeURIComponent(lsid)}`);
  } catch (error) {
    logError('login_attempt_failed', { ...requestContext, reason: error.reason || undefined, error });
    return genericInvalidCredentials(res, lsid, error.statusCode || 401);
  }
});

app.post('/verify/sms/resend', async (req, res) => {
  const lsid = String(req.body.lsid || '');
  const sessionQuery = await pool.query(
    `SELECT ls.id, ls.user_id, ls.ctx_json, ls.expires_at, ls.consumed_at, ls.authorized_at, ls.nbi_ip, ls.uip, ls.client_mac, ls.proxy, ls.ssid, ls.sip, ls.dn, ls.wlan_name, ls.url, ls.apip, ls.vlan, u.phone_e164
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     WHERE ls.id = $1`,
    [lsid]
  );
  if (sessionQuery.rowCount === 0) return genericInvalidCredentials(res, lsid);

  const session = sessionQuery.rows[0];
  if (session.authorized_at || session.consumed_at || new Date(session.expires_at) < new Date()) return genericInvalidCredentials(res, lsid);

  logCtxPresence('otp_resend_ctx_lookup', lsid, buildCtxFromSession(session));
  const cooldown = await ensureResendCooldown(session.user_id, lsid);
  if (!cooldown.allowed) {
    return res.status(429).render('verify_sms', {
      title: 'Verificar SMS',
      error: `Aguarde ${cooldown.waitSeconds}s para reenviar o código.`,
      message: null,
      lsid,
      maskedPhone: session.phone_e164.replace(/(\+55\d{2})\d{5}(\d{4})/, '$1*****$2'),
      resendWaitSeconds: cooldown.waitSeconds,
      contextBadge: buildContextBadge(buildCtxFromSession(session))
    });
  }

  const wispr = resolveWisprParams(buildCtxFromSession(session));
  const hasRecentValidOtp = await hasRecentValidOtpForContext({ userId: session.user_id, ueIp: wispr.userIp, ueMac: wispr.userMac });
  if (hasRecentValidOtp) {
    logInfo('otp_resend_skipped_recent_valid', { user_id: session.user_id, ue_ip: wispr.userIp, ue_mac: maskMac(wispr.userMac), window_seconds: OTP_VALID_REUSE_WINDOW_SECONDS });
    return res.status(409).render('verify_sms', {
      title: 'Verificar SMS',
      error: 'Já existe OTP validado recentemente para este dispositivo. Aguarde 2 minutos para solicitar novo código.',
      message: null,
      lsid,
      maskedPhone: session.phone_e164.replace(/(\+55\d{2})\d{5}(\d{4})/, '$1*****$2'),
      resendWaitSeconds: OTP_VALID_REUSE_WINDOW_SECONDS,
      contextBadge: buildContextBadge(buildCtxFromSession(session))
    });
  }

  await sendOtpForUser({ userId: session.user_id, phoneE164: session.phone_e164, reason: 'resend', ueIp: wispr.userIp, ueMac: wispr.userMac, lsid });
  return res.redirect(`/verify/sms?lsid=${encodeURIComponent(lsid)}`);
});

async function verifySmsHandler(req, res) {
  const normalizedBody = normalizeBodyFields(req.body);
  const parsed = verifySmsSchema.safeParse(normalizedBody);
  const lsid = String(normalizedBody.lsid || '');

  if (!parsed.success) {
    return res.status(400).render('verify_sms', { title: 'Verificar SMS', error: 'Código inválido ou expirado.', message: null, lsid, maskedPhone: '', resendWaitSeconds: OTP_RESEND_COOLDOWN_SECONDS, contextBadge: null });
  }

  const { code } = parsed.data;
  try {
    const sessionQuery = await pool.query(
      `SELECT ls.*, u.username_radius, u.phone_e164, u.cpf_normalizado
       FROM login_sessions ls
       JOIN users u ON u.id = ls.user_id
       WHERE ls.id = $1`,
      [parsed.data.lsid]
    );

    if (sessionQuery.rowCount === 0) throw new AuthFlowError('Sessão não encontrada.', 'Sessão do captive expirada, volte e conecte novamente ao Wi-Fi', 400);
    const session = sessionQuery.rows[0];
    const sessionCtx = buildCtxFromSession(session);
    logCtxPresence('otp_verify_ctx_lookup', session.id, sessionCtx);
    if (!hasRequiredWispr(sessionCtx)) {
      logInfo('ctx_missing_blocked', { lsid: session.id, request_ip: req.ip });
      return renderInvalidAccess(res, {
        title: 'Sessão expirada/entrada inválida',
        statusCode: 400,
        message: 'Sessão expirada ou entrada inválida. Conecte-se ao Wi‑Fi de visitantes e abra um site para iniciar novamente o fluxo captive.'
      });
    }
    if (session.authorized_at || session.consumed_at) return res.redirect(getOriginalUrl(sessionCtx));
    if (new Date(session.expires_at) < new Date()) throw new AuthFlowError('Sessão inválida.', 'Sessão do captive expirada, volte e conecte novamente ao Wi-Fi', 400);

    const otp = await getLatestOtp(session.user_id, session.id);
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

    const ctx = sessionCtx;
    const { userIp, userMac } = resolveWisprParams(ctx);

    logInfo('otp_verify_success', { lsid: session.id, user_id: session.user_id, ue_ip: userIp, ue_mac: maskMac(userMac) });
    logInfo('authorize_flow_started', { lsid: session.id, user_id: session.user_id });

    const nbiResult = await authorizeViaNbi(ctx, {
      sessionId: session.id,
      userId: session.user_id,
      usernameRadius: session.username_radius,
      cpf: session.cpf_normalizado
    });

    await pool.query(`INSERT INTO auth_events (user_id, login_session_id, event_type, status, detail) VALUES ($1, $2, 'sms_otp_login', $3, $4::jsonb)`, [session.user_id, session.id, nbiResult.success ? 'success' : 'failed', JSON.stringify({ mode: nbiResult.mode, request_id: nbiResult.requestId || null })]);

    if (!nbiResult.success) {
      logInfo('authorize_flow_failed', {
        lsid: session.id,
        user_id: session.user_id,
        reason: 'nbi_failed',
        request_id: nbiResult.requestId || null,
        response_code: String(nbiResult.detail?.ResponseCode || ''),
        reply_message: String(nbiResult.detail?.ReplyMessage || '')
      });
      throw new AuthFlowError('NBI falhou.', `Falha na autorização do acesso no SmartZone. request_id=${nbiResult.requestId || 'n/a'}`, 401, 'nbi_failed');
    }

    await pool.query(`UPDATE login_sessions SET consumed_at = NOW(), authorized_at = NOW() WHERE id = $1`, [session.id]);
    await pool.query(
      `INSERT INTO portal_active_sessions (id, user_id, ue_ip, ue_mac, ssid, authorized_at, ended_at, last_seen_at, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW(), NULL, NOW(), NOW())
       ON CONFLICT (user_id, ue_ip, ue_mac) DO UPDATE SET
         ssid = EXCLUDED.ssid,
         authorized_at = NOW(),
         ended_at = NULL,
         last_seen_at = NOW()`,
      [crypto.randomUUID(), session.user_id, userIp, normalizeMacIfPlain(userMac), ctx.ssid || null]
    );
    res.cookie('portal_session', String(session.user_id), { maxAge: SESSION_MAX_AGE_MS, httpOnly: true, sameSite: 'lax' });

    logInfo('authorize_flow_success', { lsid: session.id, user_id: session.user_id, request_id: nbiResult.requestId || null });
    return res.redirect(getOriginalUrl(ctx));
  } catch (error) {
    logError('otp_verify_error', { lsid, error });

    const isMissingWispr = error instanceof AuthFlowError && error.reason === 'missing_wispr_params';
    const isNbiFailed = error instanceof AuthFlowError && error.reason === 'nbi_failed';
    const isSessionExpired = error instanceof AuthFlowError && (error.statusCode === 400) && error.userMessage;
    const errorMessage = isMissingWispr
      ? 'Acesse o portal a partir do Wi-Fi visitante (redirect captive).'
      : isNbiFailed
        ? error.userMessage || 'Falha na autorização do acesso no SmartZone.'
        : isSessionExpired
          ? error.userMessage
          : 'Código inválido ou expirado.';

    return res.status(error.statusCode || 401).render('verify_sms', {
      title: 'Verificar SMS',
      error: errorMessage,
      message: null,
      lsid,
      maskedPhone: '',
      resendWaitSeconds: OTP_RESEND_COOLDOWN_SECONDS,
      contextBadge: null
    });
  }
}

app.post('/verify/sms', verifySmsHandler);
app.post('/otp/verify', verifySmsHandler);


app.post('/logout', async (req, res) => {
  const portalSessionUserId = String(req.cookies?.portal_session || '').trim();
  const clientIp = normalizeClientIp(req.ip);

  try {
    let activeSession = null;
    if (portalSessionUserId) {
      activeSession = await getActiveSessionByUserId(portalSessionUserId);
    }
    if (!activeSession && clientIp) {
      activeSession = await getActiveSessionByIp(clientIp);
    }

    if (activeSession) {
      const sessionQuery = await pool.query(
        `SELECT ls.nbi_ip, ls.proxy, u.username_radius, u.cpf_normalizado
         FROM login_sessions ls
         JOIN users u ON u.id = ls.user_id
         WHERE ls.user_id = $1
         ORDER BY ls.authorized_at DESC NULLS LAST, ls.created_at DESC
         LIMIT 1`,
        [activeSession.user_id]
      );
      const latestLogin = sessionQuery.rows[0] || {};

      if (latestLogin.nbi_ip && activeSession.ue_ip && activeSession.ue_mac) {
        const disconnectResult = await disconnectAsync({
          nbiIP: latestLogin.nbi_ip,
          ueIp: activeSession.ue_ip,
          ueMac: activeSession.ue_mac,
          proxy: latestLogin.proxy || '0',
          ueUsername: latestLogin.username_radius || `visitante_${latestLogin.cpf_normalizado || ''}`
        });

        if (!disconnectResult.success) {
          logInfo('logout_disconnect_failed', {
            user_id: activeSession.user_id,
            portal_active_session_id: activeSession.id,
            request_id: disconnectResult.requestId || null,
            response_code: String(disconnectResult.detail?.ResponseCode || '')
          });
        }
      }

      await pool.query(
        `UPDATE portal_active_sessions
         SET ended_at = NOW(),
             last_seen_at = NOW()
         WHERE id = $1`,
        [activeSession.id]
      );
      await pool.query(
        `UPDATE login_sessions
         SET consumed_at = COALESCE(consumed_at, NOW())
         WHERE user_id = $1
           AND authorized_at IS NOT NULL`,
        [activeSession.user_id]
      );
    }
  } catch (error) {
    logError('logout_failed', { user_id: portalSessionUserId || null, request_ip: clientIp || null, error });
  }

  res.clearCookie('portal_session');
  res.clearCookie('portal_lsid');
  return res.redirect('/portal');
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
