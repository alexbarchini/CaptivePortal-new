require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
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
const { loginAsync, disconnectAsync, statusAsync, isRetryableNbiError } = require('./services/ruckusNbi');
const { buildSmsProvider } = require('./services/smsProvider');
const {
  enforceMaxOpenSessionsTx,
  closeStaleAuthorizedOpenSessions,
  closeExpiredPendingSessions
} = require('./services/sessionCleanup');
const { logInfo, logError, LOG_TZ, AUTH_LOG_FILE_PATH } = require('./utils/logger');
const { detectDeviceType } = require('./utils/device');
const { resolveNbiMode, validateNbiConfigOrThrow, buildNbiConfigSnapshot } = require('./services/nbiConfig');

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
const OTP_SEND_WINDOW_SECONDS = Number(process.env.OTP_SEND_WINDOW_SECONDS || 600);
const OTP_SEND_MAX_PER_WINDOW = Number(process.env.OTP_SEND_MAX_PER_WINDOW || 3);
const OTP_SEND_BLOCK_SECONDS = Number(process.env.OTP_SEND_BLOCK_SECONDS || 900);
const OTP_INVALID_WINDOW_SECONDS = Number(process.env.OTP_INVALID_WINDOW_SECONDS || 600);
const OTP_INVALID_MAX_PER_WINDOW = Number(process.env.OTP_INVALID_MAX_PER_WINDOW || 5);
const OTP_INVALID_BLOCK_SECONDS = Number(process.env.OTP_INVALID_BLOCK_SECONDS || 900);
const LOGIN_INVALID_CPF_WINDOW_SECONDS = 600;
const LOGIN_INVALID_CPF_MAX_PER_WINDOW = 5;
const LOGIN_INVALID_CPF_BLOCK_SECONDS = 900;
const LOGIN_INVALID_IP_WINDOW_SECONDS = 300;
const LOGIN_INVALID_IP_MAX_PER_WINDOW = 20;
const LOGIN_INVALID_IP_BLOCK_SECONDS = 600;
const LOGIN_INVALID_MAC_WINDOW_SECONDS = 600;
const LOGIN_INVALID_MAC_MAX_PER_WINDOW = 10;
const LOGIN_INVALID_MAC_BLOCK_SECONDS = 600;
const LOGIN_SESSION_TTL_SECONDS = Number(process.env.LOGIN_SESSION_TTL_SECONDS || 600);
const PENDING_SESSION_TIMEOUT_MINUTES = Number(process.env.PENDING_SESSION_TIMEOUT_MINUTES || 60);
const ADMIN_SESSION_COOKIE_NAME = 'admin_session';
const ADMIN_SESSION_TTL_MS = Number(process.env.ADMIN_SESSION_TTL_HOURS || 8) * 60 * 60 * 1000;
const ADMIN_ALLOWED_CIDRS = String(process.env.ADMIN_ALLOWED_CIDRS || '10.9.62.0/23').split(',').map((item) => item.trim()).filter(Boolean);
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_PASSWORD_HASH || 'admin-session-secret';
const PORTAL_CAPTURE_REPEAT_WINDOW_MS = Number(process.env.PORTAL_CAPTURE_REPEAT_WINDOW_MS || 120000);
const smsProvider = buildSmsProvider();
const DISPLAY_TIME_ZONE = 'America/Sao_Paulo';
const portalCaptureTracker = new Map();


function logNbiStartupConfiguration() {
  const nbiMode = resolveNbiMode();
  const snapshot = buildNbiConfigSnapshot();
  const nbiEndpoints = snapshot.smartZoneHosts.map((host) => `https://${host}:9443/portalintf`);

  logInfo('nbi_startup_configuration', {
    nbi_mode: nbiMode,
    smartzone_hosts: snapshot.smartZoneHosts,
    nbi_endpoints: nbiEndpoints,
    tls_insecure: String(process.env.NBI_TLS_INSECURE || 'false').toLowerCase() === 'true'
  });

  if (nbiMode === 'real') {
    validateNbiConfigOrThrow();
  }
}
function parseSmartZoneManagementIps(rawValue = '') {
  return [...new Set(
    String(rawValue || '')
      .split(',')
      .map((item) => String(item || '').trim())
      .filter(Boolean)
  )];
}

const SMARTZONE_HOSTS = parseSmartZoneManagementIps(process.env.SZ_MANAGEMENT_IPS);

for (const legacyHost of parseSmartZoneManagementIps(process.env.SZ_MANAGEMENT_IP || '')) {
  if (!SMARTZONE_HOSTS.includes(legacyHost)) SMARTZONE_HOSTS.push(legacyHost);
}

function normalizeSmartZoneHostCandidate(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.includes(',')) return '';

  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    const url = new URL(withScheme);
    return String(url.hostname || '').trim().toLowerCase();
  } catch (_) {
    return raw.replace(/^https?:\/\//i, '').replace(/\/$/, '').trim().toLowerCase();
  }
}

const SMARTZONE_ALLOWLIST = [...new Set(SMARTZONE_HOSTS.map((item) => normalizeSmartZoneHostCandidate(item)).filter(Boolean))];

function isIpv4Address(host = '') {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
}

async function resolveHostIps(host = '') {
  const normalizedHost = normalizeSmartZoneHostCandidate(host);
  if (!normalizedHost || isIpv4Address(normalizedHost)) return [normalizedHost].filter(Boolean);
  try {
    const records = await dns.lookup(normalizedHost, { all: true });
    return [...new Set(records.map((record) => String(record.address || '').trim()).filter(Boolean))];
  } catch (_) {
    return [];
  }
}

async function validateSmartZoneHostAgainstAllowlist(host = '') {
  const normalizedHost = normalizeSmartZoneHostCandidate(host);
  if (!normalizedHost) {
    return { allowed: false, reason: 'empty_host', normalizedHost };
  }

  if (SMARTZONE_ALLOWLIST.includes(normalizedHost)) {
    return { allowed: true, reason: 'exact_allowlist_match', normalizedHost };
  }

  const hostIps = await resolveHostIps(normalizedHost);
  if (hostIps.length === 0) {
    return { allowed: false, reason: 'host_not_resolvable_or_not_in_allowlist', normalizedHost };
  }

  for (const allowedEntry of SMARTZONE_ALLOWLIST) {
    const allowedIps = await resolveHostIps(allowedEntry);
    const hasIpMatch = allowedIps.some((ip) => hostIps.includes(ip));
    if (hasIpMatch) {
      return {
        allowed: true,
        reason: 'resolved_ip_allowlist_match',
        normalizedHost,
        matchedAllowlistEntry: allowedEntry
      };
    }
  }

  return { allowed: false, reason: 'resolved_ip_not_in_allowlist', normalizedHost };
}

function normalizeNbiIpCandidate(value = '') {
  return normalizeSmartZoneHostCandidate(value);
}

async function resolveSmartZoneHost(ctx = {}) {
  const normalizedFromEnv = SMARTZONE_ALLOWLIST[0] || '';
  const legacyFallback = normalizeSmartZoneHostCandidate(process.env.SZ_MANAGEMENT_IP || '');
  const candidates = [
    { source: 'nbiIP', value: ctx.nbiIP },
    { source: 'sip', value: ctx.sip },
    { source: 'dn', value: ctx.dn },
    { source: 'sz_management_ips_first', value: normalizedFromEnv },
    { source: 'sz_management_ip_legacy', value: legacyFallback }
  ];

  const fallbackTrail = [];
  for (const candidate of candidates) {
    const normalizedValue = normalizeSmartZoneHostCandidate(candidate.value);
    if (!normalizedValue) continue;
    const validation = await validateSmartZoneHostAgainstAllowlist(normalizedValue);
    if (validation.allowed) {
      return {
        host: validation.normalizedHost,
        source: candidate.source,
        validation_reason: validation.reason,
        fallbackTrail
      };
    }
    fallbackTrail.push({ source: candidate.source, value: normalizedValue, reason: validation.reason });
    logInfo('smartzone_host_candidate_rejected', {
      source: candidate.source,
      value: normalizedValue,
      reason: validation.reason,
      allowlist: SMARTZONE_ALLOWLIST
    });
  }

  return {
    host: '',
    source: null,
    validation_reason: 'no_allowed_candidate',
    fallbackTrail
  };
}


async function ensureSelectedSmartZoneHostIsValid(host = '') {
  const normalizedHost = normalizeSmartZoneHostCandidate(host);
  if (!normalizedHost) {
    return { valid: false, reason: 'empty_or_malformed_selected_host', normalizedHost };
  }
  const validation = await validateSmartZoneHostAgainstAllowlist(normalizedHost);
  if (!validation.allowed) {
    return { valid: false, reason: validation.reason, normalizedHost };
  }
  return { valid: true, reason: validation.reason, normalizedHost };
}

async function pickSmartZoneHost(ctx = {}, action = async () => null) {
  const hostResolution = await resolveSmartZoneHost(ctx);
  const rawNbiIp = String(ctx.nbiIP || '').trim();
  const hosts = [];

  if (hostResolution.host) hosts.push(hostResolution.host);
  for (const host of SMARTZONE_HOSTS) {
    const normalizedHost = normalizeSmartZoneHostCandidate(host);
    if (!normalizedHost) continue;
    const validation = await validateSmartZoneHostAgainstAllowlist(normalizedHost);
    if (validation.allowed && !hosts.includes(normalizedHost)) hosts.push(normalizedHost);
  }

  if (hosts.length === 0) {
    throw new AuthFlowError(
      'SmartZone hosts não configurados.',
      'Infraestrutura SmartZone indisponível no portal.',
      500,
      'smartzone_hosts_missing'
    );
  }

  let lastError = null;
  let usedHost = null;

  for (let index = 0; index < hosts.length; index += 1) {
    const host = hosts[index];
    usedHost = host;

    try {
      const result = await action(host);
      const didFailover = index > 0;
      logInfo('smartzone_host_selected', {
        requested_nbi_ip: rawNbiIp || null,
        selected_source: hostResolution.source,
        resolved_host: hostResolution.host || null,
        allowlist: SMARTZONE_ALLOWLIST,
        fallback_trail: hostResolution.fallbackTrail,
        selected_host: host,
        did_failover: didFailover,
        attempts: index + 1
      });
      return { host, result, didFailover, source: hostResolution.source, fallbackTrail: hostResolution.fallbackTrail };
    } catch (error) {
      lastError = error;
      const shouldRetry = isRetryableNbiError(error) && index < hosts.length - 1;
      logError('smartzone_host_attempt_failed', {
        requested_nbi_ip: rawNbiIp || null,
        attempted_host: host,
        will_retry: shouldRetry,
        remaining_hosts: hosts.length - index - 1,
        error
      });
      if (!shouldRetry) throw error;
    }
  }

  if (lastError) throw lastError;
  throw new Error(`Falha ao selecionar host SmartZone. último host=${usedHost || 'n/a'}`);
}

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

function normalizeDeviceName(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return null;
  if (/^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i.test(value)) return null;
  if (/^[a-f0-9]{12}$/i.test(value.replace(/[^a-f0-9]/gi, ''))) return null;
  return value.slice(0, 255);
}

function getDeviceNameFromRequest(req, context = {}) {
  const candidates = [
    req?.headers?.['x-client-name'],
    req?.headers?.['x-device-name'],
    context?.hostname,
    context?.client_name,
    context?.device_name
  ];

  for (const candidate of candidates) {
    const normalized = normalizeDeviceName(candidate);
    if (normalized) return normalized;
  }

  return null;
}

function friendlyDeviceNameFromUserAgent(userAgent = '') {
  const ua = String(userAgent || '');
  if (!ua) return null;
  if (/iphone/i.test(ua)) return 'iPhone';
  if (/ipad/i.test(ua)) return 'iPad';
  if (/android/i.test(ua)) return 'Android';
  if (/windows nt/i.test(ua)) return 'Windows';
  if (/mac os x|macintosh/i.test(ua) && !/iphone|ipad|ipod/i.test(ua)) return 'macOS';
  if (/linux/i.test(ua) && !/android/i.test(ua)) return 'Linux';
  return null;
}

function resolveDeviceDisplayName(session = {}) {
  const explicitName = normalizeDeviceName(session.device_name);
  if (explicitName) return explicitName;
  const fromAgent = friendlyDeviceNameFromUserAgent(session.user_agent || session.ua);
  if (fromAgent) return fromAgent;
  if (session.device_type && session.device_type !== 'Unknown') return session.device_type;
  return '-';
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
function toMacColonFormat(mac = '') {
  const normalized = normalizeMacIfPlain(mac);
  if (!looksLikePlainMac(normalized)) return String(mac || '');
  return normalized.match(/.{1,2}/g).join(':');
}
function resolveWisprParams(params = {}) {
  const userIp = params.uip || params['UE-IP'] || params.client_ip;
  const userMac = params.client_mac || params['UE-MAC'];
  const proxy = params.proxy || '0';
  const nbiIP = normalizeNbiIpCandidate(params.nbiIP);
  return { userIp, userMac, proxy, nbiIP };
}
function hasRequiredWispr(ctx = {}) {
  const hasClientMac = Boolean(String(ctx.client_mac || '').trim());
  const hasUip = Boolean(String(ctx.uip || '').trim());
  const hasApip = Boolean(String(ctx.apip || '').trim());
  const hasSsid = Boolean(String(ctx.ssid || '').trim() || String(ctx.wlanName || '').trim());
  const hasController = Boolean(String(ctx.nbiIP || '').trim() || String(ctx.sip || '').trim() || String(ctx.dn || '').trim());
  return hasClientMac && hasUip && hasApip && hasSsid && hasController;
}

function getMissingWisprFields(ctx = {}) {
  const missing = [];
  if (!String(ctx.client_mac || '').trim()) missing.push('client_mac');
  if (!String(ctx.uip || '').trim()) missing.push('uip');
  if (!String(ctx.apip || '').trim()) missing.push('apip');
  if (!String(ctx.ssid || '').trim() && !String(ctx.wlanName || '').trim()) missing.push('ssid_or_wlanName');
  if (!String(ctx.nbiIP || '').trim() && !String(ctx.sip || '').trim() && !String(ctx.dn || '').trim()) missing.push('nbiIP_or_sip_or_dn');
  return missing;
}
function pickWisprParams(raw = {}) {
  const params = normalizeBodyFields(raw);
  return {
    nbiIP: normalizeNbiIpCandidate(params.nbiIP),
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
    timeZone: DISPLAY_TIME_ZONE,
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
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


function formatAdminSessionStatus(session = {}) {
  const normalizedStatus = String(session.status || (session.consumed_at ? 'CLOSED' : (session.authorized_at ? 'OPEN' : 'PENDING'))).toUpperCase();
  const closedReason = String(session.closed_reason || '').toLowerCase();
  if (normalizedStatus === 'CLOSED' && closedReason === 'pending_timeout') return 'CLOSED (TIMEOUT)';
  return normalizedStatus;
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

const ADMIN_STATUS_VALUES = ['pending', 'open', 'closed'];

function normalizeAdminStatusFilter(rawStatus) {
  const statusList = Array.isArray(rawStatus) ? rawStatus : [rawStatus];
  const normalized = statusList
    .flatMap((value) => String(value || '').split(','))
    .map((value) => value.trim().toLowerCase())
    .filter((value) => ADMIN_STATUS_VALUES.includes(value));

  const unique = [...new Set(normalized)];
  if (unique.length === 0) return [...ADMIN_STATUS_VALUES];
  return unique;
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

async function getActiveSessionByMac(clientMac) {
  const normalizedMac = normalizeMacIfPlain(clientMac);
  if (!normalizedMac) return null;
  const result = await pool.query(
    `SELECT pas.id, pas.user_id, pas.ue_ip, pas.ue_mac, pas.ssid, pas.authorized_at, pas.last_seen_at,
            u.nome, u.cpf_formatado, u.cpf_normalizado
     FROM portal_active_sessions pas
     JOIN users u ON u.id = pas.user_id
     WHERE pas.ue_mac = $1 AND pas.ended_at IS NULL
     ORDER BY pas.authorized_at DESC
     LIMIT 1`,
    [normalizedMac]
  );
  return result.rows[0] || null;
}

async function touchActiveSession(sessionId) {
  if (!sessionId) return;
  await pool.query(`UPDATE portal_active_sessions SET last_seen_at = NOW() WHERE id = $1`, [sessionId]);
}

async function findAuthorizedLoginSessionByWispr({ userIp = '', userMac = '' }) {
  const normalizedMac = normalizeMacIfPlain(userMac);
  if (!normalizedMac) return null;

  const query = await pool.query(
    `SELECT ls.id, ls.user_id, ls.nbi_ip, ls.proxy, ls.uip, ls.client_mac, ls.ssid, ls.authorized_at, ls.login_password,
            u.nome, u.cpf_formatado, u.cpf_normalizado, u.username_radius
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     WHERE ls.authorized_at IS NOT NULL
       AND ls.status = 'OPEN'
       AND ls.client_mac = $1
     ORDER BY ls.authorized_at DESC
     LIMIT 1`,
    [normalizedMac]
  );
  return query.rows[0] || null;
}

async function findOpenLoginSessionByMac(clientMac = '') {
  const normalizedMac = normalizeMacIfPlain(clientMac);
  if (!normalizedMac) return null;

  const query = await pool.query(
    `SELECT id, status, authorized_at, client_mac
     FROM login_sessions
     WHERE client_mac = $1
       AND status = 'OPEN'
     ORDER BY COALESCE(authorized_at, created_at) DESC
     LIMIT 1`,
    [normalizedMac]
  );
  return query.rows[0] || null;
}

function sanitizeSmartZoneStatusDetail(detail = {}) {
  if (!detail || typeof detail !== 'object') return null;
  return {
    ResponseCode: detail.ResponseCode || null,
    ReplyMessage: String(detail.ReplyMessage || ''),
    AccessAccept: detail.AccessAccept || null,
    ChallengeState: detail.ChallengeState || null
  };
}

function buildPortalAuthorizationDecisionLog({
  decision,
  source,
  lsid = null,
  originalMac = '',
  normalizedMac = '',
  clientIp = '',
  openSession = null,
  extras = {}
} = {}) {
  return {
    decision,
    source,
    lsid,
    client_mac_original: originalMac || null,
    client_mac_normalized: normalizedMac || null,
    client_ip: clientIp || null,
    has_open_session_same_mac: Boolean(openSession),
    open_session_id: openSession?.id || null,
    open_session_authorized_at: openSession?.authorized_at || null,
    open_session_status: openSession?.status || null,
    ...extras
  };
}

async function resolvePortalStatusFromWispr(ctx = {}) {
  const wispr = resolveWisprParams(ctx);
  const normalizedIp = normalizeClientIp(wispr.userIp);
  const normalizedMac = normalizeMacIfPlain(wispr.userMac);
  const localOpenSession = normalizedMac ? await findOpenLoginSessionByMac(normalizedMac) : null;

  const lookupLogBase = {
    lsid: null,
    client_ip: normalizedIp || null,
    client_mac_original: wispr.userMac || null,
    client_mac_normalized: normalizedMac || null,
    local_open_session_found: Boolean(localOpenSession),
    local_open_session_id: localOpenSession?.id || null,
    local_open_session_status: localOpenSession?.status || null,
    local_open_session_authorized_at: localOpenSession?.authorized_at || null
  };

  if (!normalizedIp || !normalizedMac) {
    logInfo('portal_authorization_lookup', {
      ...lookupLogBase,
      smartzone_consulted: false,
      smartzone_raw: null,
      smartzone_sanitized: null,
      decision_rule: 'missing_required_wispr'
    });
    return { authorized: false, reason: 'missing_required_wispr' };
  }

  const dbSession = await findAuthorizedLoginSessionByWispr({ userIp: normalizedIp, userMac: normalizedMac });
  if (!dbSession) {
    logInfo('portal_authorization_lookup', {
      ...lookupLogBase,
      smartzone_consulted: false,
      smartzone_raw: null,
      smartzone_sanitized: null,
      decision_rule: 'no_authorized_open_session_for_mac'
    });
  }

  if (dbSession) {
    try {
      const pick = await pickSmartZoneHost(ctx, (selectedHost) => statusAsync({
        nbiIP: selectedHost,
        ueIp: normalizedIp,
        ueMac: normalizedMac,
        proxy: wispr.proxy || dbSession.proxy || '0',
        ueUsername: dbSession.username_radius,
        uePassword: dbSession.login_password || undefined
      }));
      const nbiResult = pick.result;
      const sanitizedDetail = sanitizeSmartZoneStatusDetail(nbiResult.detail);
      const lookupRule = (nbiResult.success && nbiResult.authorized)
        ? 'authorized_when_local_open_session_and_smartzone_confirms'
        : 'unauthorized_when_local_open_session_but_smartzone_denies_or_unconfirmed';

      logInfo('portal_authorization_lookup', {
        ...lookupLogBase,
        lsid: dbSession.id,
        smartzone_consulted: true,
        smartzone_raw: nbiResult.detail || null,
        smartzone_sanitized: sanitizedDetail,
        smartzone_success: Boolean(nbiResult.success),
        smartzone_authorized: Boolean(nbiResult.authorized),
        smartzone_unconfirmed: Boolean(nbiResult.unconfirmed),
        decision_rule: lookupRule
      });

      const responseCode = String(nbiResult.detail?.ResponseCode || '');
      if (nbiResult.success && nbiResult.authorized) {
        logInfo('portal_authorization_decision', buildPortalAuthorizationDecisionLog({
          decision: 'authorized',
          source: 'nbi_status',
          lsid: dbSession.id,
          originalMac: wispr.userMac,
          normalizedMac,
          clientIp: normalizedIp,
          openSession: localOpenSession,
          extras: {
            response_code: responseCode,
            auth_state_key: nbiResult.authStateKey || null,
            auth_state_value: nbiResult.authStateValue || null,
            unconfirmed: Boolean(nbiResult.unconfirmed),
            authorization_reason: nbiResult.authorizationReason || null,
            reply_message: String(nbiResult.detail?.ReplyMessage || ''),
            ue_mac_masked: maskMac(normalizedMac)
          }
        }));
        return { authorized: true, source: 'nbi_status', responseCode, session: dbSession };
      }

      logInfo('portal_authorization_decision', buildPortalAuthorizationDecisionLog({
        decision: 'unauthorized',
        source: 'nbi_status',
        lsid: dbSession.id,
        originalMac: wispr.userMac,
        normalizedMac,
        clientIp: normalizedIp,
        openSession: localOpenSession,
        extras: {
          response_code: responseCode,
          auth_state_key: nbiResult.authStateKey || null,
          auth_state_value: nbiResult.authStateValue || null,
          unconfirmed: Boolean(nbiResult.unconfirmed),
          reply_message: String(nbiResult.detail?.ReplyMessage || ''),
          ue_mac_masked: maskMac(normalizedMac)
        }
      }));
    } catch (error) {
      logInfo('portal_authorization_lookup', {
        ...lookupLogBase,
        lsid: dbSession.id,
        smartzone_consulted: true,
        smartzone_raw: null,
        smartzone_sanitized: null,
        decision_rule: 'smartzone_lookup_failed'
      });
      logError('portal_status_nbi_failed', {
        ue_ip: normalizedIp,
        ue_mac: maskMac(normalizedMac),
        nbi_ip: wispr.nbiIP || null,
        error
      });
    }
  }

  return { authorized: false, reason: 'not_authorized' };
}

function renderConnectedStatus(res, session, fallback = {}) {
  return res.render('status', {
    title: 'Status da conexão',
    userName: session?.nome || 'Visitante',
    cpfMasked: maskCpf(session?.cpf_formatado || session?.cpf_normalizado || ''),
    authorizedAtLabel: formatDateTime(session?.authorized_at),
    sessionDuration: formatDurationSince(session?.authorized_at),
    ssid: session?.ssid || fallback.ssid || 'GuestTRT-Teste',
    ueIp: session?.uip || session?.ue_ip || fallback.uip || '-',
    macMasked: maskMac(session?.client_mac || session?.ue_mac || fallback.client_mac || ''),
    ueIpRaw: session?.uip || session?.ue_ip || fallback.uip || '',
    ueMacRaw: session?.client_mac || session?.ue_mac || fallback.client_mac || '',
    nbiIP: fallback.nbiIP || session?.nbi_ip || '',
    proxy: fallback.proxy || session?.proxy || '0'
  });
}

async function createPortalSession(req, params) {
  const newLsid = crypto.randomUUID();
  const ctx = pickWisprParams(params);
  const deviceType = detectDeviceType(req.get('user-agent') || '');
  const deviceName = getDeviceNameFromRequest(req, params);
  const normalizedClientMac = normalizeMacIfPlain(ctx.client_mac);
  let lsid = newLsid;
  let reusedSessionMetadata = null;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (normalizedClientMac) {
      const reusablePendingSessionResult = await client.query(
        `SELECT id, created_at
         FROM login_sessions
         WHERE status = 'PENDING'
           AND client_mac = $1
           AND created_at >= NOW() - ($2::int * INTERVAL '1 minute')
         ORDER BY created_at DESC
         LIMIT 1
         FOR UPDATE`,
        [normalizedClientMac, PENDING_SESSION_TIMEOUT_MINUTES]
      );

      if (reusablePendingSessionResult.rowCount > 0) {
        const reusablePendingSession = reusablePendingSessionResult.rows[0];
        lsid = reusablePendingSession.id;
        reusedSessionMetadata = {
          id: reusablePendingSession.id,
          previousCreatedAt: reusablePendingSession.created_at
        };

        await client.query(
          `UPDATE login_sessions
           SET ctx_json = $2::jsonb,
               nbi_ip = COALESCE(NULLIF($3, ''), nbi_ip),
               uip = COALESCE(NULLIF($4, ''), uip),
               proxy = COALESCE(NULLIF($5, ''), proxy),
               ssid = COALESCE(NULLIF($6, ''), ssid),
               sip = COALESCE(NULLIF($7, ''), sip),
               dn = COALESCE(NULLIF($8, ''), dn),
               wlan_name = COALESCE(NULLIF($9, ''), wlan_name),
               url = COALESCE(NULLIF($10, ''), url),
               apip = COALESCE(NULLIF($11, ''), apip),
               vlan = COALESCE(NULLIF($12, ''), vlan),
               expires_at = NOW() + ($13 || ' seconds')::interval,
               device_type = COALESCE(NULLIF($14, ''), device_type),
               device_name = COALESCE(NULLIF($15, ''), device_name),
               user_agent = COALESCE(NULLIF($16, ''), user_agent)
           WHERE id = $1
             AND status = 'PENDING'`,
          [
            lsid,
            JSON.stringify(ctx),
            ctx.nbiIP,
            ctx.uip,
            ctx.proxy,
            ctx.ssid,
            ctx.sip,
            ctx.dn,
            ctx.wlanName,
            ctx.url,
            ctx.apip,
            ctx.vlan,
            LOGIN_SESSION_TTL_SECONDS,
            deviceType,
            deviceName,
            req.get('user-agent') || ''
          ]
        );
      }

      await client.query(
        `UPDATE login_sessions
         SET status = 'CLOSED',
             closed_at = COALESCE(closed_at, NOW()),
             consumed_at = COALESCE(consumed_at, NOW())
         WHERE client_mac = $1
           AND status = 'OPEN'`,
        [normalizedClientMac]
      );
    }

    if (!reusedSessionMetadata) {
      await client.query(
        `INSERT INTO login_sessions (
          id, ctx_json, nbi_ip, uip, client_mac, proxy, ssid, sip, dn, wlan_name, url, apip, vlan, expires_at, device_type, device_name, user_agent, status
        ) VALUES (
          $1, $2::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW() + ($14 || ' seconds')::interval, $15, $16, $17, 'PENDING'
        )`,
        [
          lsid,
          JSON.stringify(ctx),
          ctx.nbiIP,
          ctx.uip,
          normalizedClientMac,
          ctx.proxy,
          ctx.ssid,
          ctx.sip,
          ctx.dn,
          ctx.wlanName,
          ctx.url,
          ctx.apip,
          ctx.vlan,
          LOGIN_SESSION_TTL_SECONDS,
          deviceType,
          deviceName,
          req.get('user-agent') || ''
        ]
      );
    }

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }

  const hostResolution = await resolveSmartZoneHost(ctx);
  if (reusedSessionMetadata) {
    logInfo('pending_session_reused', {
      reused_session_id: reusedSessionMetadata.id,
      client_mac: normalizedClientMac || null,
      client_ip: normalizeClientIp(ctx.uip),
      previous_created_at: reusedSessionMetadata.previousCreatedAt,
      reason: 'same_client_recent_pending'
    });
  }

  logInfo('portal_ctx_captured', {
    lsid,
    params: sanitizeParams(ctx),
    client_ip: normalizeClientIp(ctx.uip),
    client_mac_original: ctx.client_mac || null,
    client_mac_normalized: normalizedClientMac || null,
    smartzone_host_resolved: hostResolution.host || null,
    smartzone_host_source: hostResolution.source,
    allowlist: SMARTZONE_ALLOWLIST,
    fallback_trail: hostResolution.fallbackTrail
  });

  const trackingKey = `${normalizeClientIp(ctx.uip)}|${normalizedClientMac}`;
  if (normalizedClientMac && normalizeClientIp(ctx.uip)) {
    const previous = portalCaptureTracker.get(trackingKey);
    const now = Date.now();
    const withinWindow = previous && (now - previous.lastSeenAtMs) <= PORTAL_CAPTURE_REPEAT_WINDOW_MS;
    if (withinWindow) {
      const captureCount = previous.captureCount + 1;
      portalCaptureTracker.set(trackingKey, { captureCount, lastSeenAtMs: now });
      if (captureCount === 2 || captureCount % 5 === 0) {
        logInfo('portal_ctx_capture_repeated_expected', {
          behavior: 'expected_repeated_capture_for_unauthenticated_client',
          client_ip: normalizeClientIp(ctx.uip),
          client_mac_original: ctx.client_mac || null,
          client_mac_normalized: normalizedClientMac,
          captures_in_window: captureCount,
          window_ms: PORTAL_CAPTURE_REPEAT_WINDOW_MS,
          latest_lsid: lsid
        });
      }
    } else {
      portalCaptureTracker.set(trackingKey, { captureCount: 1, lastSeenAtMs: now });
    }
  }
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
  const userQuery = await pool.query(`SELECT cpf_normalizado FROM users WHERE id = $1`, [userId]);
  const cpf = userQuery.rows[0]?.cpf_normalizado || null;
  const otpLimit = await checkOtpSendRateLimit({ cpf, userId, lsid, clientIp: ueIp, clientMac: ueMac });
  if (!otpLimit.allowed) {
    throw new AuthFlowError(
      'Limite de envio de OTP excedido.',
      otpLimit.userMessage,
      429,
      'otp_send_rate_limited'
    );
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = await argon2.hash(code);

  await smsProvider.send(phoneE164, `Seu código de acesso do Portal TRT9 é ${code}. Ele expira em ${Math.ceil(OTP_TTL_SECONDS / 60)} minutos.`);

  await pool.query(
    `INSERT INTO otp_codes (user_id, login_session_id, channel, destination, code_hash, expires_at, ue_ip, ue_mac)
     VALUES ($1, $2, 'sms', $3, $4, NOW() + ($5 || ' seconds')::interval, $6, $7)`,
    [userId, lsid, phoneE164, codeHash, OTP_TTL_SECONDS, ueIp, normalizeMacIfPlain(ueMac)]
  );

  let otpSendAttemptNumber = 1;
  if (lsid) {
    const sendAttempts = await pool.query(
      `SELECT COUNT(*)::int AS send_count
       FROM auth_events
       WHERE lsid = $1
         AND event_type IN ('otp_sent', 'otp_resend')`,
      [lsid]
    );
    otpSendAttemptNumber = (sendAttempts.rows[0]?.send_count || 0) + 1;
  }

  const otpSendOrigin = reason === 'resend' ? 'resend' : 'initial';

  await recordAuthEvent({
    eventType: reason === 'resend' ? 'otp_resend' : 'otp_sent',
    lsid,
    userId,
    cpf,
    clientMac: ueMac,
    clientIp: ueIp,
    details: {
      reason,
      channel: 'sms',
      otp_send_origin: otpSendOrigin,
      otp_send_attempt_number: otpSendAttemptNumber
    }
  });

  logInfo('otp_sent', { lsid, user_id: userId, destination: phoneE164, reason, ue_ip: ueIp, ue_mac: maskMac(ueMac) });
}

function buildRateLimitFriendlyMessage() {
  return 'Muitas tentativas de envio de código. Aguarde alguns minutos para tentar novamente.';
}

function buildOtpInvalidFriendlyMessage() {
  return 'Muitas tentativas inválidas de código. Aguarde alguns minutos antes de tentar novamente.';
}

function buildLoginBruteforceFriendlyMessage() {
  return 'Credenciais inválidas ou muitas tentativas. Aguarde alguns minutos antes de tentar novamente.';
}

async function recordAuthEvent({ eventType, lsid = null, userId = null, cpf = null, clientMac = null, clientIp = null, ssid = null, apIp = null, vlan = null, userAgent = null, details = null }) {
  await pool.query(
    `INSERT INTO auth_events (event_type, lsid, user_id, cpf, client_mac, client_ip, ssid, ap_ip, vlan, user_agent, details_json, login_session_id, status, detail)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $2, 'info', $11::jsonb)`,
    [eventType, lsid, userId, cpf, normalizeMacIfPlain(clientMac), normalizeClientIp(clientIp), ssid, apIp, vlan, userAgent, JSON.stringify(details || {})]
  );
}

async function recordSecurityEvent({ eventType, severity = 'medium', correlationType, correlationValue, description, reason, attemptCount = null, windowSeconds = null, blockedUntil = null, details = null }) {
  await pool.query(
    `INSERT INTO security_events (event_type, severity, correlation_type, correlation_value, description, reason, attempt_count, window_seconds, blocked_until, details_json)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`,
    [eventType, severity, correlationType, correlationValue, description, reason, attemptCount, windowSeconds, blockedUntil, JSON.stringify(details || {})]
  );
}

async function getActiveSecurityBlock(correlationType, correlationValue, eventType) {
  if (!correlationValue) return null;
  const result = await pool.query(
    `SELECT *
     FROM security_events
     WHERE correlation_type = $1
       AND correlation_value = $2
       AND event_type = $3
       AND blocked_until IS NOT NULL
       AND blocked_until > NOW()
     ORDER BY blocked_until DESC, created_at DESC
     LIMIT 1`,
    [correlationType, correlationValue, eventType]
  );
  return result.rows[0] || null;
}

async function evaluateLoginBruteforceBlocks({ cpf, clientIp = null, clientMac = null }) {
  const normalizedIp = normalizeClientIp(clientIp);
  const normalizedMac = normalizeMacIfPlain(clientMac);

  const cpfBlock = cpf ? await getActiveSecurityBlock('cpf', cpf, 'cpf_bruteforce_suspected') : null;
  const ipBlock = normalizedIp ? await getActiveSecurityBlock('ip', normalizedIp, 'ip_bruteforce_suspected') : null;
  const macBlock = normalizedMac ? await getActiveSecurityBlock('mac', normalizedMac, 'mac_bruteforce_suspected') : null;

  const activeBlocks = [cpfBlock, ipBlock, macBlock].filter(Boolean);
  if (activeBlocks.length === 0) return null;

  const primaryBlock = activeBlocks.reduce((latest, current) => {
    if (!latest) return current;
    return new Date(current.blocked_until) > new Date(latest.blocked_until) ? current : latest;
  }, null);

  await recordSecurityEvent({
    eventType: 'login_blocked',
    severity: 'high',
    correlationType: primaryBlock.correlation_type,
    correlationValue: primaryBlock.correlation_value,
    description: 'Tentativa de login bloqueada por proteção anti-força-bruta.',
    reason: 'active_bruteforce_block',
    attemptCount: primaryBlock.attempt_count,
    windowSeconds: primaryBlock.window_seconds,
    blockedUntil: primaryBlock.blocked_until,
    details: {
      cpf,
      client_ip: normalizedIp || null,
      client_mac: normalizedMac || null,
      blocked_by: activeBlocks.map((item) => ({
        correlation_type: item.correlation_type,
        correlation_value: item.correlation_value,
        blocked_until: item.blocked_until,
        attempt_count: item.attempt_count,
        window_seconds: item.window_seconds
      }))
    }
  });

  return primaryBlock;
}

async function registerInvalidLoginAttempt({ cpf, clientIp = null, clientMac = null, lsid = null, userAgent = '' }) {
  const normalizedIp = normalizeClientIp(clientIp);
  const normalizedMac = normalizeMacIfPlain(clientMac);

  await recordAuthEvent({
    eventType: 'login_invalid_credentials',
    lsid,
    userId: null,
    cpf,
    clientIp: normalizedIp,
    clientMac: normalizedMac,
    userAgent,
    details: {
      reason: 'invalid_credentials',
      cpf_window_seconds: LOGIN_INVALID_CPF_WINDOW_SECONDS,
      ip_window_seconds: LOGIN_INVALID_IP_WINDOW_SECONDS,
      mac_window_seconds: LOGIN_INVALID_MAC_WINDOW_SECONDS
    }
  });

  const countByCpfQuery = cpf
    ? pool.query(
      `SELECT COUNT(*)::int AS attempt_count
       FROM auth_events
       WHERE event_type = 'login_invalid_credentials'
         AND cpf = $1
         AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
      [cpf, LOGIN_INVALID_CPF_WINDOW_SECONDS]
    )
    : Promise.resolve({ rows: [{ attempt_count: 0 }] });
  const countByIpQuery = normalizedIp
    ? pool.query(
      `SELECT COUNT(*)::int AS attempt_count
       FROM auth_events
       WHERE event_type = 'login_invalid_credentials'
         AND client_ip = $1
         AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
      [normalizedIp, LOGIN_INVALID_IP_WINDOW_SECONDS]
    )
    : Promise.resolve({ rows: [{ attempt_count: 0 }] });
  const countByMacQuery = normalizedMac
    ? pool.query(
      `SELECT COUNT(*)::int AS attempt_count
       FROM auth_events
       WHERE event_type = 'login_invalid_credentials'
         AND UPPER(regexp_replace(COALESCE(client_mac, ''), '[^A-Fa-f0-9]', '', 'g')) = UPPER(regexp_replace(COALESCE($1, ''), '[^A-Fa-f0-9]', '', 'g'))
         AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
      [normalizedMac, LOGIN_INVALID_MAC_WINDOW_SECONDS]
    )
    : Promise.resolve({ rows: [{ attempt_count: 0 }] });

  const [countByCpfResult, countByIpResult, countByMacResult] = await Promise.all([countByCpfQuery, countByIpQuery, countByMacQuery]);

  const countByCpf = countByCpfResult.rows[0]?.attempt_count || 0;
  const countByIp = countByIpResult.rows[0]?.attempt_count || 0;
  const countByMac = countByMacResult.rows[0]?.attempt_count || 0;

  if (cpf && countByCpf >= LOGIN_INVALID_CPF_MAX_PER_WINDOW) {
    const blockedUntilQuery = await pool.query(
      `SELECT NOW() + ($1::int * INTERVAL '1 second') AS blocked_until`,
      [LOGIN_INVALID_CPF_BLOCK_SECONDS]
    );
    const blockedUntil = blockedUntilQuery.rows[0]?.blocked_until || null;
    await recordSecurityEvent({
      eventType: 'cpf_bruteforce_suspected',
      severity: 'high',
      correlationType: 'cpf',
      correlationValue: cpf,
      description: 'Tentativas inválidas de login excederam limite por CPF.',
      reason: 'max_5_invalid_in_10_minutes',
      attemptCount: countByCpf,
      windowSeconds: LOGIN_INVALID_CPF_WINDOW_SECONDS,
      blockedUntil,
      details: { cpf, client_ip: normalizedIp || null, client_mac: normalizedMac || null }
    });
  }

  if (normalizedIp && countByIp >= LOGIN_INVALID_IP_MAX_PER_WINDOW) {
    const blockedUntilQuery = await pool.query(
      `SELECT NOW() + ($1::int * INTERVAL '1 second') AS blocked_until`,
      [LOGIN_INVALID_IP_BLOCK_SECONDS]
    );
    const blockedUntil = blockedUntilQuery.rows[0]?.blocked_until || null;
    await recordSecurityEvent({
      eventType: 'ip_bruteforce_suspected',
      severity: 'high',
      correlationType: 'ip',
      correlationValue: normalizedIp,
      description: 'Tentativas inválidas de login excederam limite por IP.',
      reason: 'max_20_invalid_in_5_minutes',
      attemptCount: countByIp,
      windowSeconds: LOGIN_INVALID_IP_WINDOW_SECONDS,
      blockedUntil,
      details: { cpf, client_ip: normalizedIp, client_mac: normalizedMac || null }
    });
  }

  if (normalizedMac && countByMac >= LOGIN_INVALID_MAC_MAX_PER_WINDOW) {
    const blockedUntilQuery = await pool.query(
      `SELECT NOW() + ($1::int * INTERVAL '1 second') AS blocked_until`,
      [LOGIN_INVALID_MAC_BLOCK_SECONDS]
    );
    const blockedUntil = blockedUntilQuery.rows[0]?.blocked_until || null;
    await recordSecurityEvent({
      eventType: 'mac_bruteforce_suspected',
      severity: 'high',
      correlationType: 'mac',
      correlationValue: normalizedMac,
      description: 'Tentativas inválidas de login excederam limite por MAC.',
      reason: 'max_10_invalid_in_10_minutes',
      attemptCount: countByMac,
      windowSeconds: LOGIN_INVALID_MAC_WINDOW_SECONDS,
      blockedUntil,
      details: { cpf, client_ip: normalizedIp || null, client_mac: normalizedMac }
    });
  }
}

async function checkOtpSendRateLimit({ cpf, userId, lsid = null, clientIp = null, clientMac = null }) {
  if (!cpf) return { allowed: true, userMessage: null };

  const activeBlock = await getActiveSecurityBlock('cpf', cpf, 'sms_abuse_suspected');
  if (activeBlock) {
    await recordAuthEvent({
      eventType: 'sms_rate_limited',
      lsid,
      userId,
      cpf,
      clientIp,
      clientMac,
      details: {
        reason: 'active_block',
        blocked_until: activeBlock.blocked_until,
        window_seconds: OTP_SEND_WINDOW_SECONDS,
        attempt_count: activeBlock.attempt_count || OTP_SEND_MAX_PER_WINDOW
      }
    });
    return { allowed: false, userMessage: buildRateLimitFriendlyMessage() };
  }

  const sendEvents = await pool.query(
    `SELECT COUNT(*)::int AS attempt_count,
            MAX(created_at) AS latest_attempt_at
     FROM auth_events
     WHERE cpf = $1
       AND event_type IN ('otp_sent', 'otp_resend')
       AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
    [cpf, OTP_SEND_WINDOW_SECONDS]
  );

  const attemptCount = sendEvents.rows[0]?.attempt_count || 0;
  const latestAttemptAt = sendEvents.rows[0]?.latest_attempt_at;

  if (latestAttemptAt) {
    const cooldownResult = await pool.query(
      `SELECT GREATEST(0, $2 - EXTRACT(EPOCH FROM (NOW() - $1::timestamptz))::int) AS wait_seconds`,
      [latestAttemptAt, OTP_RESEND_COOLDOWN_SECONDS]
    );
    const waitSeconds = cooldownResult.rows[0]?.wait_seconds || 0;
    if (waitSeconds > 0) {
      await recordAuthEvent({
        eventType: 'sms_rate_limited',
        lsid,
        userId,
        cpf,
        clientIp,
        clientMac,
        details: {
          reason: 'cooldown_60_seconds',
          wait_seconds: waitSeconds,
          attempt_count: attemptCount,
          window_seconds: OTP_SEND_WINDOW_SECONDS
        }
      });
      return { allowed: false, userMessage: `Aguarde ${waitSeconds}s para solicitar um novo código.` };
    }
  }

  if (attemptCount >= OTP_SEND_MAX_PER_WINDOW) {
    const blockUntilResult = await pool.query(`SELECT NOW() + ($1::int * INTERVAL '1 second') AS blocked_until`, [OTP_SEND_BLOCK_SECONDS]);
    const blockedUntil = blockUntilResult.rows[0]?.blocked_until || null;

    await recordAuthEvent({
      eventType: 'sms_rate_limited',
      lsid,
      userId,
      cpf,
      clientIp,
      clientMac,
      details: {
        reason: 'max_3_in_10_minutes',
        attempt_count: attemptCount,
        window_seconds: OTP_SEND_WINDOW_SECONDS,
        blocked_until: blockedUntil
      }
    });

    await recordSecurityEvent({
      eventType: 'sms_abuse_suspected',
      severity: 'high',
      correlationType: 'cpf',
      correlationValue: cpf,
      description: 'Muitas tentativas de envio/reenvio de OTP por CPF.',
      reason: 'max 3 envios em 10 minutos',
      attemptCount,
      windowSeconds: OTP_SEND_WINDOW_SECONDS,
      blockedUntil,
      details: { cpf, user_id: userId, lsid, client_ip: normalizeClientIp(clientIp), client_mac: normalizeMacIfPlain(clientMac) }
    });

    return { allowed: false, userMessage: buildRateLimitFriendlyMessage() };
  }

  return { allowed: true, userMessage: null };
}

async function checkOtpInvalidBlock({ cpf, userId, lsid, clientIp, clientMac }) {
  const activeBlock = await getActiveSecurityBlock('cpf', cpf, 'bruteforce_otp_suspected');
  if (!activeBlock) return { blocked: false, blockedUntil: null };

  await recordAuthEvent({
    eventType: 'otp_validation_blocked',
    lsid,
    userId,
    cpf,
    clientIp,
    clientMac,
    details: {
      reason: 'active_block',
      blocked_until: activeBlock.blocked_until,
      window_seconds: OTP_INVALID_WINDOW_SECONDS,
      attempt_count: activeBlock.attempt_count || OTP_INVALID_MAX_PER_WINDOW
    }
  });

  await recordSecurityEvent({
    eventType: 'otp_validation_blocked',
    severity: 'high',
    correlationType: 'cpf',
    correlationValue: cpf,
    description: 'Validação de OTP temporariamente bloqueada.',
    reason: '5 OTP inválidos em 10 minutos',
    attemptCount: activeBlock.attempt_count || OTP_INVALID_MAX_PER_WINDOW,
    windowSeconds: OTP_INVALID_WINDOW_SECONDS,
    blockedUntil: activeBlock.blocked_until,
    details: { cpf, user_id: userId, lsid, client_ip: normalizeClientIp(clientIp), client_mac: normalizeMacIfPlain(clientMac) }
  });

  return { blocked: true, blockedUntil: activeBlock.blocked_until };
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
  const { userIp, userMac, proxy } = resolveWisprParams(ctx);
  if (!userIp || !userMac) {
    throw new AuthFlowError(
      'Parâmetros WISPr ausentes.',
      'Acesse o portal a partir do Wi-Fi visitante (redirect captive).',
      400,
      'missing_wispr_params'
    );
  }

  const hostResolution = await resolveSmartZoneHost(ctx);
  if (!hostResolution.host) {
    throw new AuthFlowError(
      'Host SmartZone não permitido ou ausente.',
      'Infraestrutura SmartZone indisponível no momento.',
      503,
      'smartzone_host_not_allowed'
    );
  }

  logInfo('wispr_params_received', {
    lsid: user.sessionId,
    user_id: user.userId,
    user_ip: userIp,
    user_mac_received: userMac,
    user_mac_normalized: normalizeMacIfPlain(userMac),
    user_mac_controller_format: toMacColonFormat(userMac),
    user_mac: maskMac(userMac),
    proxy,
    smartzone_host_resolved: hostResolution.host,
    smartzone_host_source: hostResolution.source,
    allowlist: SMARTZONE_ALLOWLIST,
    fallback_trail: hostResolution.fallbackTrail
  });

  const pick = await pickSmartZoneHost(ctx, (selectedHost) => loginAsync({
    nbiIP: selectedHost,
    ueIp: userIp,
    ueMac: userMac,
    proxy,
    ueUsername: user.usernameRadius || `visitante_${user.cpf}`,
    uePassword: ctx.login_password || ''
  }));

  return {
    ...pick.result,
    nbiIP: pick.host,
    selectedSource: pick.source,
    fallbackTrail: pick.fallbackTrail,
    failoverUsed: pick.didFailover
  };
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



function requestPrefersJson(req) {
  const acceptHeader = String(req.get('accept') || '').toLowerCase();
  return acceptHeader.includes('application/json');
}

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

function buildPtOrdinal(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1) return null;
  return `${number}º`;
}

const AUTH_EVENTS_ALLOWED_PAGE_SIZES = [10, 20, 50, 100];
const AUTH_FAILURE_EVENT_TYPES = [
  'otp_invalid',
  'otp_expired',
  'otp_validation_blocked',
  'sms_rate_limited',
  'controller_authorization_failed',
  'otp_flow_abandoned',
  'login_invalid_credentials',
  'session_denied'
];
const AUTH_OPERATIONAL_EVENT_TYPES = [
  'portal_start',
  'portal_ctx_captured',
  'login_attempt_started',
  'register_attempt_started',
  'otp_sent',
  'otp_resend',
  'otp_verify_success',
  'authorize_flow_started',
  'session_authorized',
  'session_closed',
  'logout_logical_completed',
  ...AUTH_FAILURE_EVENT_TYPES
];

function parsePageAndPageSize(reqQuery = {}, defaultPageSize = 20) {
  const pageRaw = Number.parseInt(String(reqQuery.page || '1'), 10);
  const page = Number.isInteger(pageRaw) && pageRaw > 0 ? pageRaw : 1;

  const sizeRaw = Number.parseInt(String(reqQuery.page_size || defaultPageSize), 10);
  const pageSize = AUTH_EVENTS_ALLOWED_PAGE_SIZES.includes(sizeRaw) ? sizeRaw : defaultPageSize;
  const offset = (page - 1) * pageSize;
  return { page, pageSize, offset };
}

function buildPaginationMeta({ page, pageSize, totalCount }) {
  const safeTotalCount = Math.max(0, Number(totalCount) || 0);
  const totalPages = Math.max(1, Math.ceil(safeTotalCount / pageSize));
  const currentPage = Math.min(Math.max(1, page), totalPages);
  const hasPrevPage = currentPage > 1;
  const hasNextPage = currentPage < totalPages;

  return {
    totalCount: safeTotalCount,
    currentPage,
    pageSize,
    totalPages,
    hasPrevPage,
    hasNextPage,
    prevPage: hasPrevPage ? currentPage - 1 : 1,
    nextPage: hasNextPage ? currentPage + 1 : totalPages
  };
}

function buildPageWindow(currentPage, totalPages, windowSize = 5) {
  const size = Math.max(1, windowSize);
  const half = Math.floor(size / 2);
  let start = Math.max(1, currentPage - half);
  let end = Math.min(totalPages, start + size - 1);

  if ((end - start + 1) < size) {
    start = Math.max(1, end - size + 1);
  }

  return Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => start + index);
}

function mapAuthEventLabel(eventType = '') {
  const labels = {
    portal_start: 'Início do portal',
    portal_ctx_captured: 'Contexto do portal capturado',
    login_attempt_started: 'Tentativa de login iniciada',
    register_attempt_started: 'Tentativa de cadastro iniciada',
    otp_sent: 'OTP enviado',
    otp_resend: 'OTP reenviado',
    otp_verify_success: 'OTP validado com sucesso',
    authorize_flow_started: 'Fluxo de autorização iniciado',
    session_authorized: 'Sessão autorizada',
    session_closed: 'Sessão encerrada',
    logout_logical_completed: 'Logout lógico concluído',
    sms_rate_limited: 'Envio de SMS limitado por proteção',
    otp_invalid: 'OTP inválido',
    otp_validation_blocked: 'Validação de OTP bloqueada',
    otp_flow_abandoned: 'Fluxo OTP abandonado',
    sms_otp_login: 'Tentativa de autorização após OTP',
    controller_authorization_failed: 'Falha de autorização na controladora',
    session_denied: 'Sessão negada na etapa de autenticação',
    otp_expired: 'Código OTP expirado',
    login_invalid_credentials: 'Login inválido'
  };
  return labels[eventType] || eventType;
}

function mapAuthEventDescription(event = {}) {
  const details = event.details_json || {};
  const attemptNumber = Number(details.otp_send_attempt_number);
  const ordinal = buildPtOrdinal(attemptNumber);

  if (event.event_type === 'otp_sent') {
    if (ordinal) return `OTP enviado (${ordinal} envio)`;
    return 'OTP enviado (1º envio)';
  }

  if (event.event_type === 'otp_resend') {
    if (ordinal) return `OTP reenviado (${ordinal} envio)`;
    return 'OTP reenviado';
  }

  const labels = {
    portal_start: 'Abertura inicial do portal detectada',
    portal_ctx_captured: 'Dados de contexto do portal capturados com sucesso',
    login_attempt_started: 'Fluxo de login iniciado pelo usuário',
    register_attempt_started: 'Fluxo de cadastro iniciado pelo usuário',
    otp_invalid: 'OTP inválido',
    otp_validation_blocked: 'Validação de OTP bloqueada',
    controller_authorization_failed: 'Falha de autorização na controladora',
    otp_expired: 'OTP expirado',
    sms_rate_limited: 'Envio de SMS temporariamente limitado',
    otp_verify_success: 'Código OTP validado com sucesso',
    authorize_flow_started: 'Autorização iniciada na controladora',
    session_authorized: 'Sessão autorizada com sucesso',
    session_closed: 'Sessão encerrada',
    logout_logical_completed: 'Logout lógico concluído',
    otp_flow_abandoned: 'Fluxo abandonado por timeout',
    sms_otp_login: 'Autorização iniciada após validação de OTP',
    session_denied: 'Sessão negada na etapa de autenticação',
    login_invalid_credentials: 'Credenciais inválidas'
  };

  return labels[event.event_type] || mapAuthEventLabel(event.event_type);
}

function mapSecurityEventLabel(eventType = '') {
  const labels = {
    sms_abuse_suspected: 'Excesso de envios de SMS',
    bruteforce_otp_suspected: 'Muitas tentativas inválidas de OTP',
    max_active_sessions_enforced: 'Sessão antiga encerrada por excesso de sessões ativas',
    otp_validation_blocked: 'Validação de OTP temporariamente bloqueada',
    multiple_failures_same_cpf: 'Múltiplas falhas de autenticação no mesmo CPF',
    multiple_failures_same_ip: 'Múltiplas falhas de autenticação no mesmo IP',
    multiple_failures_same_mac: 'Múltiplas falhas de autenticação no mesmo MAC',
    cpf_bruteforce_suspected: 'Força bruta suspeita por CPF',
    ip_bruteforce_suspected: 'Força bruta suspeita por IP',
    mac_bruteforce_suspected: 'Força bruta suspeita por MAC',
    login_blocked: 'Tentativa de login bloqueada'
  };
  return labels[eventType] || eventType;
}

function mapSecurityReason(reason = '') {
  const labels = {
    max_3_in_10_minutes: '3 envios de SMS em menos de 10 minutos',
    'max 3 envios em 10 minutos': '3 envios de SMS em menos de 10 minutos',
    '5 otp inválidos em 10 minutos': '5 OTP inválidos em 10 minutos',
    max_sessions_exceeded: '6ª sessão aberta para o mesmo CPF',
    max_5_invalid_in_10_minutes: '5 tentativas inválidas em 10 minutos',
    max_20_invalid_in_5_minutes: '20 tentativas inválidas em 5 minutos',
    max_10_invalid_in_10_minutes: '10 tentativas inválidas em 10 minutos',
    active_bruteforce_block: 'Tentativa bloqueada por bloqueio anti-força-bruta ativo'
  };
  return labels[reason] || reason || '-';
}

app.get('/admin/sessions', async (req, res) => {
  const cpfNormalized = cleanDigits(String(req.query.cpf || ''));
  const nameQuery = String(req.query.name || '').trim();
  const ipQuery = normalizeClientIp(String(req.query.ip || ''));
  const macRaw = String(req.query.mac || '').trim();
  const macNormalized = normalizeMacForFilter(macRaw);
  const fromRaw = String(req.query.from || '').trim();
  const toRaw = String(req.query.to || '').trim();
  const { page: requestedPage, pageSize } = parsePageAndPageSize(req.query, 20);
  const offsetRaw = Number.parseInt(String(req.query.offset || '0'), 10);
  const legacyOffset = Number.isInteger(offsetRaw) && offsetRaw > 0 ? offsetRaw : 0;
  const page = req.query.page ? requestedPage : (Math.floor(legacyOffset / pageSize) + 1);
  const offset = (page - 1) * pageSize;
  const fromIso = parseDatetimeLocal(fromRaw);
  const toIso = parseDatetimeLocal(toRaw);
  const statusFilter = normalizeAdminStatusFilter(req.query.status);

  if (cpfNormalized && cpfNormalized.length !== 11) {
    return res.status(400).render('admin_sessions', {
      title: 'Sessões administrativas',
      adminUser: req.adminSession.user,
      filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw, status: statusFilter, page_size: pageSize },
      error: 'CPF inválido para consulta.',
      sessions: [],
      pagination: { page_size: pageSize, current_page: page, offset, hasNextPage: false, nextPage: page + 1 }
    });
  }

  if (macRaw && macNormalized.length !== 12) {
    return res.status(400).render('admin_sessions', {
      title: 'Sessões administrativas',
      adminUser: req.adminSession.user,
      filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw, status: statusFilter, page_size: pageSize },
      error: 'MAC inválido para consulta.',
      sessions: [],
      pagination: { page_size: pageSize, current_page: page, offset, hasNextPage: false, nextPage: page + 1 }
    });
  }

  if ((fromRaw && !fromIso) || (toRaw && !toIso)) {
    return res.status(400).render('admin_sessions', {
      title: 'Sessões administrativas',
      adminUser: req.adminSession.user,
      filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw, status: statusFilter, page_size: pageSize },
      error: 'Intervalo de data/hora inválido.',
      sessions: [],
      pagination: { page_size: pageSize, current_page: page, offset, hasNextPage: false, nextPage: page + 1 }
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
  if (statusFilter.length > 0) {
    const placeholders = statusFilter.map((status) => {
      values.push(status);
      return `$${values.length}`;
    });
    filters.push(`LOWER(ls.status) IN (${placeholders.join(', ')})`);
  }

  values.push(pageSize + 1, offset);
  const whereClause = filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : '';
  const sessionsResult = await pool.query(
    `SELECT ls.id AS lsid,
            ls.created_at,
            ls.authorized_at,
            ls.status,
            ls.closed_at,
            ls.closed_reason,
            ls.otp_verified_at,
            ls.consumed_at,
            ls.uip,
            ls.client_mac,
            ls.ssid,
            ls.vlan,
            ls.apip,
            ls.device_type,
            ls.device_name,
            ls.user_agent,
            u.nome,
            u.cpf_formatado,
            u.cpf_normalizado,
            CASE
              WHEN ls.authorized_at IS NULL THEN NULL
              WHEN ls.status = 'OPEN' THEN EXTRACT(EPOCH FROM (NOW() - ls.authorized_at))::int
              WHEN ls.status = 'CLOSED' AND ls.closed_at IS NOT NULL THEN EXTRACT(EPOCH FROM (ls.closed_at - ls.authorized_at))::int
              ELSE NULL
            END AS duration_seconds
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     ${whereClause}
     ORDER BY ls.created_at DESC
     LIMIT $${values.length - 1}
     OFFSET $${values.length}`,
    values
  );

  const hasNextPage = sessionsResult.rows.length > pageSize;
  const sessions = sessionsResult.rows.slice(0, pageSize).map((session) => ({
    ...session,
    status: formatAdminSessionStatus(session),
    status_class: String(session.status || (session.consumed_at ? 'CLOSED' : (session.authorized_at ? 'OPEN' : 'PENDING'))).toLowerCase(),
    duration_hms: formatDurationHms(session.duration_seconds),
    created_at_label: formatDateTime(session.created_at),
    authorized_at_label: formatDateTime(session.authorized_at),
    device_display_name: resolveDeviceDisplayName(session)
  }));

  logInfo('admin_lookup', {
    cpf_normalizado: cpfNormalized || null,
    name_filter: nameQuery || null,
    ip_filter: ipQuery || null,
    mac_filter: macNormalized || null,
    from_filter: fromIso,
    to_filter: toIso,
    status_filter: statusFilter,
    current_page: page,
    page_size: pageSize,
    offset,
    result_count: sessions.length,
    admin_user: req.adminSession.user,
    request_ip: normalizeClientIp(req.ip)
  });

  return res.render('admin_sessions', {
    title: 'Sessões administrativas',
    adminUser: req.adminSession.user,
    filters: { cpf: cpfNormalized, name: nameQuery, ip: ipQuery, mac: macRaw, from: fromRaw, to: toRaw, status: statusFilter, page_size: pageSize },
    error: null,
    sessions,
    pagination: { page_size: pageSize, current_page: page, offset, hasNextPage, nextPage: page + 1, prevPage: Math.max(1, page - 1), allowedPageSizes: AUTH_EVENTS_ALLOWED_PAGE_SIZES }
  });
});

app.post('/admin/sessions/:lsid/terminate', async (req, res) => {
  const lsid = String(req.params.lsid || '').trim();
  const adminUser = String(req.adminSession?.user || '').trim();
  const adminIp = normalizeClientIp(req.ip) || String(req.ip || '').trim() || null;

  if (!lsid) {
    return res.status(400).json({ ok: false, error: 'Sessão inválida.' });
  }

  const client = await pool.connect();
  let session = null;
  try {
    await client.query('BEGIN');

    const sessionQuery = await client.query(
      `SELECT ls.id,
              ls.user_id,
              ls.status,
              ls.uip,
              ls.client_mac,
              ls.nbi_ip,
              ls.proxy,
              ls.wlan_name,
              ls.apip,
              u.cpf_normalizado,
              u.username_radius
       FROM login_sessions ls
       JOIN users u ON u.id = ls.user_id
       WHERE ls.id = $1
       FOR UPDATE`,
      [lsid]
    );

    session = sessionQuery.rows[0] || null;
    if (!session) {
      await client.query('ROLLBACK');
      return res.status(404).json({ ok: false, error: 'Sessão não encontrada.' });
    }

    if (session.status !== 'OPEN') {
      await client.query('ROLLBACK');
      return res.status(409).json({ ok: false, error: 'Apenas sessões OPEN podem ser encerradas manualmente.' });
    }

    await client.query(
      `UPDATE login_sessions
       SET status = 'CLOSED',
           closed_at = NOW(),
           consumed_at = COALESCE(consumed_at, NOW()),
           closed_reason = 'admin_terminated_session'
       WHERE id = $1`,
      [session.id]
    );

    const auditDetails = {
      session_id: session.id,
      user_id: session.user_id,
      cpf: session.cpf_normalizado || null,
      client_ip: session.uip || null,
      client_mac: session.client_mac || null,
      admin_user: adminUser || null,
      admin_ip: adminIp,
      reason: 'admin manual termination'
    };

    await client.query(
      `INSERT INTO auth_events (event_type, lsid, user_id, cpf, client_mac, client_ip, details_json, login_session_id, status, detail)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $2, 'info', $7::jsonb)`,
      [
        'admin_session_terminated',
        session.id,
        session.user_id,
        session.cpf_normalizado,
        normalizeMacIfPlain(session.client_mac),
        normalizeClientIp(session.uip),
        JSON.stringify(auditDetails)
      ]
    );

    await client.query(
      `INSERT INTO security_events (event_type, severity, correlation_type, correlation_value, description, reason, details_json)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
      [
        'admin_session_forced_disconnect',
        'info',
        session.cpf_normalizado ? 'cpf' : (session.client_mac ? 'mac' : 'ip'),
        session.cpf_normalizado || normalizeMacIfPlain(session.client_mac) || normalizeClientIp(session.uip),
        'Sessão encerrada manualmente pelo administrador',
        'admin manual termination',
        JSON.stringify(auditDetails)
      ]
    );

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    logError('admin_terminate_session_failed', { lsid, admin_user: adminUser || null, admin_ip: adminIp, error });
    return res.status(500).json({ ok: false, error: 'Falha ao encerrar sessão.' });
  } finally {
    client.release();
  }

  const disconnectAuditDetails = {
    session_id: session.id,
    user_id: session.user_id,
    cpf: session.cpf_normalizado || null,
    client_ip: session.uip || null,
    client_mac: session.client_mac || null,
    wlan_name: session.wlan_name || null,
    ap_ip: session.apip || null,
    admin_user: adminUser || null,
    admin_ip: adminIp,
    reason: 'admin manual termination'
  };

  try {
    await recordSecurityEvent({
      eventType: 'controller_disconnect_request',
      severity: 'info',
      correlationType: session.cpf_normalizado ? 'cpf' : (session.client_mac ? 'mac' : 'ip'),
      correlationValue: session.cpf_normalizado || normalizeMacIfPlain(session.client_mac) || normalizeClientIp(session.uip),
      description: 'Solicitação de desconexão enviada à controladora SmartZone.',
      reason: 'admin manual termination',
      details: disconnectAuditDetails
    });

    if (!session.nbi_ip || !session.client_mac || !session.uip) {
      await recordSecurityEvent({
        eventType: 'controller_disconnect_failed',
        severity: 'info',
        correlationType: session.cpf_normalizado ? 'cpf' : (session.client_mac ? 'mac' : 'ip'),
        correlationValue: session.cpf_normalizado || normalizeMacIfPlain(session.client_mac) || normalizeClientIp(session.uip),
        description: 'Falha ao desconectar sessão na controladora SmartZone.',
        reason: 'missing_controller_context',
        details: disconnectAuditDetails
      });
      return res.status(200).json({ ok: true, session: { id: session.id, status: 'CLOSED' }, disconnect: { success: false, reason: 'missing_controller_context' } });
    }

    const disconnectResult = await disconnectAsync({
      nbiIP: session.nbi_ip,
      ueIp: session.uip,
      ueMac: session.client_mac,
      proxy: session.proxy || '0',
      ueUsername: session.username_radius || `visitante_${session.cpf_normalizado || ''}`
    });

    const eventType = disconnectResult.success ? 'controller_disconnect_success' : 'controller_disconnect_failed';
    await recordSecurityEvent({
      eventType,
      severity: 'info',
      correlationType: session.cpf_normalizado ? 'cpf' : (session.client_mac ? 'mac' : 'ip'),
      correlationValue: session.cpf_normalizado || normalizeMacIfPlain(session.client_mac) || normalizeClientIp(session.uip),
      description: disconnectResult.success
        ? 'Sessão desconectada com sucesso na controladora SmartZone'
        : 'Falha ao desconectar sessão na controladora SmartZone',
      reason: disconnectResult.success ? 'controller disconnect success' : 'controller disconnect failed',
      details: {
        ...disconnectAuditDetails,
        request_id: disconnectResult.requestId || null,
        endpoint: disconnectResult.endpoint || null,
        host_selected: session.nbi_ip || null,
        payload: {
          RequestType: 'Disconnect',
          'UE-IP': session.uip || null,
          'UE-MAC': session.client_mac || null,
          'UE-Proxy': session.proxy || '0',
          'UE-Username': session.username_radius || `visitante_${session.cpf_normalizado || ''}`
        },
        http_status: disconnectResult.httpStatus || null,
        response_code: String(disconnectResult.detail?.ResponseCode || ''),
        reply_message: String(disconnectResult.detail?.ReplyMessage || ''),
        interpreted_result: disconnectResult.success ? 'success' : 'failure',
        interpretation_reason: disconnectResult.interpretationReason || null
      }
    });

    return res.status(200).json({ ok: true, session: { id: session.id, status: 'CLOSED' }, disconnect: { success: disconnectResult.success } });
  } catch (error) {
    await recordSecurityEvent({
      eventType: 'controller_disconnect_failed',
      severity: 'info',
      correlationType: session.cpf_normalizado ? 'cpf' : (session.client_mac ? 'mac' : 'ip'),
      correlationValue: session.cpf_normalizado || normalizeMacIfPlain(session.client_mac) || normalizeClientIp(session.uip),
      description: 'Falha ao desconectar sessão na controladora SmartZone.',
      reason: 'controller disconnect exception',
      details: {
        ...disconnectAuditDetails,
        error: String(error?.message || error || 'unknown_error')
      }
    });
    logError('admin_terminate_session_disconnect_failed', { lsid: session.id, admin_user: adminUser || null, admin_ip: adminIp, error });
    return res.status(200).json({ ok: true, session: { id: session.id, status: 'CLOSED' }, disconnect: { success: false, reason: 'disconnect_exception' } });
  }
});


app.get('/admin/lookup', (req, res) => {
  const query = new URLSearchParams(req.query || {}).toString();
  return res.redirect(query ? `/admin/sessions?${query}` : '/admin/sessions');
});

function buildAdminAuthEventsQuery(req) {
  const cpf = cleanDigits(String(req.query.cpf || ''));
  const macRaw = String(req.query.mac || '').trim();
  const mac = normalizeMacForFilter(macRaw);
  const ip = normalizeClientIp(String(req.query.ip || ''));
  const lsid = String(req.query.lsid || '').trim();
  const eventType = String(req.query.event_type || '').trim().toLowerCase();
  const fromRaw = String(req.query.from || '').trim();
  const toRaw = String(req.query.to || '').trim();
  const fromIso = parseDatetimeLocal(fromRaw);
  const toIso = parseDatetimeLocal(toRaw);

  const { page, pageSize, offset } = parsePageAndPageSize(req.query, 20);

  const filters = [];
  const values = [];
  const pushFilter = (sql, value) => {
    values.push(value);
    filters.push(sql.replace('?', `$${values.length}`));
  };

  if (cpf) pushFilter('cpf = ?', cpf);
  if (macRaw && mac.length === 12) pushFilter("UPPER(regexp_replace(COALESCE(client_mac, ''), '[^A-Fa-f0-9]', '', 'g')) = ?", mac);
  if (ip) pushFilter('client_ip = ?', ip);
  if (lsid) pushFilter('lsid = ?', lsid);
  if (eventType) pushFilter('event_type ILIKE ?', `%${eventType}%`);
  if (fromIso) pushFilter('created_at >= ?', fromIso);
  if (toIso) pushFilter('created_at <= ?', toIso);

  return {
    cpf,
    macRaw,
    ip,
    lsid,
    eventType,
    fromRaw,
    toRaw,
    page,
    pageSize,
    offset,
    filters,
    values,
    pushFilter
  };
}

app.get('/admin/auth-events', async (req, res) => {
  const query = buildAdminAuthEventsQuery(req);
  const allowedEventTypes = AUTH_OPERATIONAL_EVENT_TYPES;

  query.values.push(allowedEventTypes);
  query.filters.push(`event_type = ANY($${query.values.length}::text[])`);

  const whereClause = query.filters.length > 0 ? `WHERE ${query.filters.join(' AND ')}` : '';
  const countResult = await pool.query(
    `SELECT COUNT(*)::int AS total_count
     FROM auth_events
     ${whereClause}`,
    query.values
  );
  const totalCount = countResult.rows?.[0]?.total_count || 0;
  const paginationMeta = buildPaginationMeta({ page: query.page, pageSize: query.pageSize, totalCount });
  const offset = (paginationMeta.currentPage - 1) * paginationMeta.pageSize;
  logInfo('admin_auth_events_pagination', { current_page: paginationMeta.currentPage, page_size: paginationMeta.pageSize, offset });

  const rowsQueryValues = [...query.values, paginationMeta.pageSize, offset];
  const rows = await pool.query(
    `SELECT id, created_at, event_type, lsid, user_id, cpf, client_ip, client_mac, details_json
     FROM auth_events
     ${whereClause}
     ORDER BY created_at DESC
     LIMIT $${rowsQueryValues.length - 1} OFFSET $${rowsQueryValues.length}`,
    rowsQueryValues
  );

  const events = rows.rows;

  return res.render('admin_auth_events_all', {
    title: 'Administração · Auth Events',
    adminUser: req.adminSession.user,
    filters: {
      cpf: query.cpf,
      mac: query.macRaw,
      ip: query.ip,
      lsid: query.lsid,
      event_type: query.eventType,
      from: query.fromRaw,
      to: query.toRaw,
      page_size: query.pageSize
    },
    events: events.map((event) => ({
      ...event,
      event_label: mapAuthEventLabel(event.event_type),
      description_label: mapAuthEventDescription(event),
      created_at_label: formatDateTime(event.created_at),
      reason_label: mapSecurityReason(event.details_json?.reason || '')
    })),
    pagination: {
      page: paginationMeta.currentPage,
      current_page: paginationMeta.currentPage,
      pageSize: paginationMeta.pageSize,
      page_size: paginationMeta.pageSize,
      totalCount: paginationMeta.totalCount,
      total_count: paginationMeta.totalCount,
      totalPages: paginationMeta.totalPages,
      total_pages: paginationMeta.totalPages,
      hasNextPage: paginationMeta.hasNextPage,
      hasPrevPage: paginationMeta.hasPrevPage,
      prevPage: paginationMeta.prevPage,
      nextPage: paginationMeta.nextPage,
      firstPage: 1,
      lastPage: paginationMeta.totalPages,
      pageWindow: buildPageWindow(paginationMeta.currentPage, paginationMeta.totalPages),
      allowedPageSizes: AUTH_EVENTS_ALLOWED_PAGE_SIZES
    }
  });
});

app.get('/admin/auth-failures', async (req, res) => {
  const query = buildAdminAuthEventsQuery(req);
  query.values.push(AUTH_FAILURE_EVENT_TYPES);
  query.filters.push(`event_type = ANY($${query.values.length}::text[])`);

  const whereClause = query.filters.length > 0 ? `WHERE ${query.filters.join(' AND ')}` : '';
  const countResult = await pool.query(
    `SELECT COUNT(*)::int AS total_count
     FROM auth_events
     ${whereClause}`,
    query.values
  );
  const totalCount = countResult.rows?.[0]?.total_count || 0;
  const paginationMeta = buildPaginationMeta({ page: query.page, pageSize: query.pageSize, totalCount });
  const offset = (paginationMeta.currentPage - 1) * paginationMeta.pageSize;
  logInfo('admin_auth_failures_pagination', { current_page: paginationMeta.currentPage, page_size: paginationMeta.pageSize, offset });

  const rowsQueryValues = [...query.values, paginationMeta.pageSize, offset];
  const rows = await pool.query(
    `SELECT id, created_at, event_type, lsid, user_id, cpf, client_ip, client_mac, details_json
     FROM auth_events
     ${whereClause}
     ORDER BY created_at DESC
     LIMIT $${rowsQueryValues.length - 1} OFFSET $${rowsQueryValues.length}`,
    rowsQueryValues
  );

  const events = rows.rows;

  return res.render('admin_auth_events', {
    title: 'Administração · Auth Failures',
    adminUser: req.adminSession.user,
    filters: {
      cpf: query.cpf,
      mac: query.macRaw,
      ip: query.ip,
      lsid: query.lsid,
      event_type: query.eventType,
      from: query.fromRaw,
      to: query.toRaw,
      page_size: query.pageSize
    },
    events: events.map((event) => ({
      ...event,
      event_label: mapAuthEventLabel(event.event_type),
      description_label: mapAuthEventDescription(event),
      created_at_label: formatDateTime(event.created_at),
      reason_label: mapSecurityReason(event.details_json?.reason || '')
    })),
    pagination: {
      page: paginationMeta.currentPage,
      current_page: paginationMeta.currentPage,
      pageSize: paginationMeta.pageSize,
      page_size: paginationMeta.pageSize,
      totalCount: paginationMeta.totalCount,
      total_count: paginationMeta.totalCount,
      totalPages: paginationMeta.totalPages,
      total_pages: paginationMeta.totalPages,
      hasNextPage: paginationMeta.hasNextPage,
      hasPrevPage: paginationMeta.hasPrevPage,
      prevPage: paginationMeta.prevPage,
      nextPage: paginationMeta.nextPage,
      firstPage: 1,
      lastPage: paginationMeta.totalPages,
      pageWindow: buildPageWindow(paginationMeta.currentPage, paginationMeta.totalPages),
      allowedPageSizes: AUTH_EVENTS_ALLOWED_PAGE_SIZES
    }
  });
});

app.get('/admin/admin-audit', async (req, res) => {
  const rows = await pool.query(
    `SELECT id, created_at, event_type, lsid, cpf, client_ip, client_mac, details_json
     FROM auth_events
     WHERE event_type ILIKE 'admin_%'
     ORDER BY created_at DESC
     LIMIT 100`
  );

  return res.render('admin_audit_events', {
    title: 'Administração · Auditoria Admin',
    adminUser: req.adminSession.user,
    events: rows.rows.map((event) => ({
      ...event,
      created_at_label: formatDateTime(event.created_at),
      description_label: mapAuthEventDescription(event)
    }))
  });
});

app.get('/admin/security-events', async (req, res) => {
  const cpf = cleanDigits(String(req.query.cpf || ''));
  const macRaw = String(req.query.mac || '').trim();
  const mac = normalizeMacForFilter(macRaw);
  const ip = normalizeClientIp(String(req.query.ip || ''));
  const eventType = String(req.query.event_type || '').trim().toLowerCase();
  const severity = String(req.query.severity || '').trim().toLowerCase();
  const onlyActiveBlocks = String(req.query.only_active_blocks || '').trim().toLowerCase() === 'true';
  const fromRaw = String(req.query.from || '').trim();
  const toRaw = String(req.query.to || '').trim();
  const fromIso = parseDatetimeLocal(fromRaw);
  const toIso = parseDatetimeLocal(toRaw);
  const { page, pageSize } = parsePageAndPageSize(req.query, 20);

  const filters = [];
  const values = [];
  const pushFilter = (sql, value) => {
    values.push(value);
    filters.push(sql.replace('?', `$${values.length}`));
  };

  if (eventType) {
    values.push(`%${eventType}%`);
    const eventTypeFilterParam = `$${values.length}`;
    filters.push(`(event_type ILIKE ${eventTypeFilterParam} OR COALESCE(description, '') ILIKE ${eventTypeFilterParam} OR COALESCE(reason, '') ILIKE ${eventTypeFilterParam})`);
  }
  if (severity) pushFilter('LOWER(severity) = ?', severity);
  if (fromIso) pushFilter('created_at >= ?', fromIso);
  if (toIso) pushFilter('created_at <= ?', toIso);
  if (onlyActiveBlocks) filters.push('blocked_until IS NOT NULL AND blocked_until > NOW()');

  const correlationFilters = [];

  if (cpf) {
    values.push(cpf);
    correlationFilters.push(`(correlation_type = 'cpf' AND correlation_value = $${values.length})`);
  }
  if (macRaw && mac.length === 12) {
    values.push(mac);
    correlationFilters.push(`(correlation_type = 'mac' AND UPPER(regexp_replace(correlation_value, '[^A-Fa-f0-9]', '', 'g')) = $${values.length})`);
  }
  if (ip) {
    values.push(ip);
    correlationFilters.push(`(correlation_type = 'ip' AND correlation_value = $${values.length})`);
  }

  if (correlationFilters.length > 0) {
    filters.push(`(${correlationFilters.join(' OR ')})`);
  }

  const whereClause = filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : '';
  const countResult = await pool.query(
    `SELECT COUNT(*)::int AS total_count
     FROM security_events
     ${whereClause}`,
    values
  );
  const totalCount = countResult.rows?.[0]?.total_count || 0;
  const paginationMeta = buildPaginationMeta({ page, pageSize, totalCount });
  const offset = (paginationMeta.currentPage - 1) * paginationMeta.pageSize;
  logInfo('admin_security_events_pagination', { current_page: paginationMeta.currentPage, page_size: paginationMeta.pageSize, offset });

  const rowsQueryValues = [...values, paginationMeta.pageSize, offset];
  const rows = await pool.query(
    `SELECT id, created_at, event_type, severity, correlation_type, correlation_value, description, reason, attempt_count, window_seconds, blocked_until, details_json
     FROM security_events
     ${whereClause}
     ORDER BY created_at DESC
     LIMIT $${rowsQueryValues.length - 1} OFFSET $${rowsQueryValues.length}`,
    rowsQueryValues
  );

  return res.render('admin_security_events', {
    title: 'Administração · Security Events',
    adminUser: req.adminSession.user,
    filters: { cpf, mac: macRaw, ip, event_type: eventType, severity, from: fromRaw, to: toRaw, only_active_blocks: onlyActiveBlocks, page_size: paginationMeta.pageSize },
    events: rows.rows.map((event) => ({
      ...event,
      event_label: mapSecurityEventLabel(event.event_type),
      created_at_label: formatDateTime(event.created_at),
      blocked_until_label: formatDateTime(event.blocked_until),
      description_label: event.description || '-',
      reason_label: mapSecurityReason(event.reason || '')
    })),
    pagination: {
      page: paginationMeta.currentPage,
      current_page: paginationMeta.currentPage,
      pageSize: paginationMeta.pageSize,
      page_size: paginationMeta.pageSize,
      totalCount: paginationMeta.totalCount,
      total_count: paginationMeta.totalCount,
      totalPages: paginationMeta.totalPages,
      total_pages: paginationMeta.totalPages,
      hasNextPage: paginationMeta.hasNextPage,
      hasPrevPage: paginationMeta.hasPrevPage,
      prevPage: paginationMeta.prevPage,
      nextPage: paginationMeta.nextPage,
      firstPage: 1,
      lastPage: paginationMeta.totalPages,
      pageWindow: buildPageWindow(paginationMeta.currentPage, paginationMeta.totalPages),
      allowedPageSizes: AUTH_EVENTS_ALLOWED_PAGE_SIZES
    }
  });
});

app.post('/admin/logout', (req, res) => {
  res.clearCookie(ADMIN_SESSION_COOKIE_NAME, { httpOnly: true, sameSite: 'lax' });
  return res.redirect('/admin/login');
});

app.get('/portal', async (req, res) => {
  try {
    const wisprCtx = pickWisprParams(req.query);
    if (hasRequiredWispr(wisprCtx)) {
      const normalizedWisprIp = normalizeClientIp(wisprCtx.uip);
      const normalizedWisprMac = normalizeMacIfPlain(wisprCtx.client_mac);
      const openSessionByMac = normalizedWisprMac ? await findOpenLoginSessionByMac(normalizedWisprMac) : null;
      const status = await resolvePortalStatusFromWispr(wisprCtx);
      if (status.authorized && status.session) {
        logInfo('portal_authorization_decision', buildPortalAuthorizationDecisionLog({
          decision: 'authorized',
          source: status.source,
          lsid: status.session.id,
          originalMac: wisprCtx.client_mac,
          normalizedMac: normalizedWisprMac,
          clientIp: normalizedWisprIp,
          openSession: openSessionByMac,
          extras: {
            response_code: status.responseCode || null,
            nbi_ip: wisprCtx.nbiIP,
            ue_mac_masked: maskMac(wisprCtx.client_mac)
          }
        }));
        return renderConnectedStatus(res, status.session, wisprCtx);
      }

      const lsid = await createPortalSession(req, req.query);
      res.cookie('portal_lsid', lsid, {
        maxAge: LOGIN_SESSION_TTL_SECONDS * 1000,
        httpOnly: true,
        sameSite: 'lax'
      });
      logInfo('portal_authorization_decision', buildPortalAuthorizationDecisionLog({
        decision: 'unauthorized',
        source: status.source || status.reason || 'no_session',
        lsid,
        originalMac: wisprCtx.client_mac,
        normalizedMac: normalizedWisprMac,
        clientIp: normalizedWisprIp,
        openSession: openSessionByMac,
        extras: {
          nbi_ip: wisprCtx.nbiIP,
          ue_mac_masked: maskMac(wisprCtx.client_mac)
        }
      }));
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
    const clientMac = normalizeMacIfPlain(wisprCtx.client_mac || '');

    const portalSessionUserIdNumber = Number(portalSessionUserId);
    const hasValidUserIdCookie = Boolean(
      portalSessionUserId &&
      Number.isInteger(portalSessionUserIdNumber) &&
      portalSessionUserIdNumber > 0
    );

    let activeSession = null;
    if (hasValidUserIdCookie) {
      activeSession = await getActiveSessionByUserId(portalSessionUserIdNumber);
    }
    if (!activeSession && clientMac) {
      activeSession = await getActiveSessionByMac(clientMac);
    }

    if (activeSession) {
      await touchActiveSession(activeSession.id);
      return renderConnectedStatus(res, activeSession, { uip: clientIp });
    }

    logInfo('portal_ctx_missing_blocked', {
      request_ip: req.ip,
      params: sanitizeParams(wisprCtx),
      missing_required_fields: getMissingWisprFields(wisprCtx)
    });
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
  if (!session || session.status !== 'PENDING' || new Date(session.expires_at) < new Date()) return res.redirect('/portal');
  logCtxPresence('register_ctx_lookup', lsid, buildCtxFromSession(session));
  res.render('register', { title: 'Cadastro de visitante', error: null, values: {}, lsid });
});

app.get('/verify/sms', async (req, res) => {
  const lsid = String(req.query.lsid || '');
  if (!lsid) return res.redirect('/portal');

  const sessionQuery = await pool.query(
    `SELECT ls.id, ls.user_id, ls.status, ls.ctx_json, ls.expires_at, ls.consumed_at, ls.authorized_at, ls.nbi_ip, ls.uip, ls.client_mac, ls.proxy, ls.ssid, ls.sip, ls.dn, ls.wlan_name, ls.url, ls.apip, ls.vlan, u.phone_e164
     FROM login_sessions ls
     JOIN users u ON u.id = ls.user_id
     WHERE ls.id = $1`,
    [lsid]
  );

  if (sessionQuery.rowCount === 0) {
    logInfo('otp_step_navigation', {
      lsid,
      route_target: '/verify/sms',
      source: 'direct',
      session_found: false,
      context_loaded_from_db: false
    });
    return res.redirect('/portal');
  }
  const session = sessionQuery.rows[0];
  const sessionCtx = buildCtxFromSession(session);
  if (session.status !== 'PENDING' || session.authorized_at || session.consumed_at || new Date(session.expires_at) < new Date()) {
    logInfo('otp_step_navigation', {
      lsid,
      route_target: '/verify/sms',
      source: 'direct',
      session_found: true,
      context_loaded_from_db: false
    });
    return res.redirect('/portal');
  }

  logInfo('otp_step_navigation', {
    lsid,
    route_target: '/verify/sms',
    source: 'direct',
    session_found: true,
    context_loaded_from_db: true
  });

  logCtxPresence('verify_sms_ctx_lookup', lsid, sessionCtx);
  const cooldown = await ensureResendCooldown(session.user_id, lsid);

  return res.render('verify_sms', {
    title: 'Verificar SMS',
    error: null,
    message: 'Digite o código enviado por SMS.',
    lsid,
    maskedPhone: session.phone_e164.replace(/(\+55\d{2})\d{5}(\d{4})/, '$1*****$2'),
    resendWaitSeconds: cooldown.waitSeconds,
    contextBadge: buildContextBadge(sessionCtx)
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
  if (!session || session.status !== 'PENDING' || new Date(session.expires_at) < new Date()) {
    return res.status(400).render('portal', {
      title: 'Portal Visitantes TRT9',
      error: 'Sessão do captive expirada, volte e conecte novamente ao Wi-Fi',
      message: null,
      lsid: ''
    });
  }

  if (session.status !== 'PENDING' || session.authorized_at || session.consumed_at) {
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
      logInfo('otp_step_navigation', {
        lsid,
        route_target: '/verify/sms',
        source: 'register',
        session_found: true,
        context_loaded_from_db: Boolean(hasRequiredWispr(params))
      });
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
  if (session.status !== 'PENDING' || session.authorized_at || session.consumed_at) {
    return res.redirect(getOriginalUrl(params));
  }

  const { cpf, password } = parsed.data;
  const wispr = resolveWisprParams(params);
  try {
    const activeBruteforceBlock = await evaluateLoginBruteforceBlocks({
      cpf,
      clientIp: wispr.userIp || req.ip,
      clientMac: wispr.userMac
    });
    if (activeBruteforceBlock) {
      throw new AuthFlowError('Tentativa bloqueada por força bruta.', buildLoginBruteforceFriendlyMessage(), 429, 'login_bruteforce_blocked');
    }

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

    const hasRecentValidOtp = await hasRecentValidOtpForContext({ userId: user.id, ueIp: wispr.userIp, ueMac: wispr.userMac });
    if (!hasRecentValidOtp) {
      await sendOtpForUser({ userId: user.id, phoneE164: user.phone_e164, reason: 'login', ueIp: wispr.userIp, ueMac: wispr.userMac, lsid });
    } else {
      logInfo('otp_resend_skipped_recent_valid', { user_id: user.id, ue_ip: wispr.userIp, ue_mac: maskMac(wispr.userMac), window_seconds: OTP_VALID_REUSE_WINDOW_SECONDS });
    }

    logInfo('otp_step_navigation', {
      lsid,
      route_target: '/verify/sms',
      source: 'login',
      session_found: true,
      context_loaded_from_db: Boolean(hasRequiredWispr(params))
    });
    return res.redirect(`/verify/sms?lsid=${encodeURIComponent(lsid)}`);
  } catch (error) {
    const shouldCountAsInvalidCredential = !(error instanceof AuthFlowError && ['login_bruteforce_blocked', 'otp_send_rate_limited'].includes(error.reason));
    if (shouldCountAsInvalidCredential) {
      await registerInvalidLoginAttempt({
        cpf,
        clientIp: wispr.userIp || req.ip,
        clientMac: wispr.userMac,
        lsid,
        userAgent: req.get('user-agent') || ''
      });
    }

    logError('login_attempt_failed', { ...requestContext, reason: error.reason || undefined, error });
    if (error instanceof AuthFlowError && error.reason === 'otp_send_rate_limited') {
      return res.status(429).render('verify_sms', {
        title: 'Verificar SMS',
        error: error.userMessage,
        message: null,
        lsid,
        maskedPhone: '',
        resendWaitSeconds: OTP_RESEND_COOLDOWN_SECONDS,
        contextBadge: buildContextBadge(params)
      });
    }
    if (error instanceof AuthFlowError && error.reason === 'login_bruteforce_blocked') {
      return res.status(429).render('portal', {
        title: 'Portal Visitantes TRT9',
        error: buildLoginBruteforceFriendlyMessage(),
        message: null,
        lsid,
        contextBadge: null
      });
    }
    return genericInvalidCredentials(res, lsid, error.statusCode || 401);
  }
});

app.post('/verify/sms/resend', async (req, res) => {
  const lsid = String(req.body.lsid || '');
  const expectsJson = requestPrefersJson(req);

  try {
    const sessionQuery = await pool.query(
      `SELECT ls.id, ls.user_id, ls.status, ls.ctx_json, ls.expires_at, ls.consumed_at, ls.authorized_at, ls.nbi_ip, ls.uip, ls.client_mac, ls.proxy, ls.ssid, ls.sip, ls.dn, ls.wlan_name, ls.url, ls.apip, ls.vlan, u.phone_e164
       FROM login_sessions ls
       JOIN users u ON u.id = ls.user_id
       WHERE ls.id = $1`,
      [lsid]
    );
    if (sessionQuery.rowCount === 0) {
      if (expectsJson) return res.status(401).json({ success: false, error: 'Sessão inválida.' });
      return genericInvalidCredentials(res, lsid);
    }

    const session = sessionQuery.rows[0];
    if (session.status !== 'PENDING' || session.authorized_at || session.consumed_at || new Date(session.expires_at) < new Date()) {
      if (expectsJson) return res.status(401).json({ success: false, error: 'Sessão inválida ou expirada.' });
      return genericInvalidCredentials(res, lsid);
    }

    logCtxPresence('otp_resend_ctx_lookup', lsid, buildCtxFromSession(session));
    const cooldown = await ensureResendCooldown(session.user_id, lsid);
    if (!cooldown.allowed) {
      if (expectsJson) {
        return res.status(429).json({ success: false, error: `Aguarde ${cooldown.waitSeconds}s para reenviar o código.`, retry_after_seconds: cooldown.waitSeconds });
      }
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
      if (expectsJson) {
        return res.status(429).json({
          success: false,
          error: 'Já existe OTP validado recentemente para este dispositivo. Aguarde 2 minutos para solicitar novo código.',
          retry_after_seconds: OTP_VALID_REUSE_WINDOW_SECONDS
        });
      }
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
    if (expectsJson) {
      return res.status(200).json({ success: true, message: 'SMS reenviado com sucesso.', retry_after_seconds: OTP_RESEND_COOLDOWN_SECONDS });
    }
    return res.redirect(`/verify/sms?lsid=${encodeURIComponent(lsid)}`);
  } catch (error) {
    logError('otp_resend_failed', { lsid, error });
    if (error instanceof AuthFlowError && error.reason === 'otp_send_rate_limited') {
      if (expectsJson) {
        return res.status(429).json({ success: false, error: error.userMessage });
      }
      return res.status(429).render('verify_sms', {
        title: 'Verificar SMS',
        error: error.userMessage,
        message: null,
        lsid,
        maskedPhone: '',
        resendWaitSeconds: OTP_RESEND_COOLDOWN_SECONDS,
        contextBadge: null
      });
    }
    if (expectsJson) {
      return res.status(500).json({ success: false, error: 'Falha ao reenviar SMS. Tente novamente em instantes.', temporary_retry_after_seconds: 4 });
    }
    return res.status(500).render('verify_sms', {
      title: 'Verificar SMS',
      error: 'Falha ao reenviar SMS. Tente novamente em instantes.',
      message: null,
      lsid,
      maskedPhone: '',
      resendWaitSeconds: 4,
      contextBadge: null
    });
  }
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
    if (session.status !== 'PENDING' || session.authorized_at || session.consumed_at) return res.redirect(getOriginalUrl(sessionCtx));
    if (new Date(session.expires_at) < new Date() || session.status !== 'PENDING') throw new AuthFlowError('Sessão inválida.', 'Sessão do captive expirada, volte e conecte novamente ao Wi-Fi', 400);

    const wispr = resolveWisprParams(sessionCtx);
    const cpf = session.cpf_normalizado || null;
    const blockedValidation = await checkOtpInvalidBlock({
      cpf,
      userId: session.user_id,
      lsid: session.id,
      clientIp: wispr.userIp,
      clientMac: wispr.userMac
    });
    if (blockedValidation.blocked) {
      throw new AuthFlowError('Validação OTP bloqueada.', buildOtpInvalidFriendlyMessage(), 429, 'otp_validation_blocked');
    }

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
      await recordAuthEvent({
        eventType: 'otp_invalid',
        lsid: session.id,
        userId: session.user_id,
        cpf,
        clientIp: wispr.userIp,
        clientMac: wispr.userMac,
        ssid: session.ssid,
        apIp: session.apip,
        vlan: session.vlan,
        userAgent: req.get('user-agent') || '',
        details: {
          reason: 'otp_mismatch',
          attempt_count: attempts,
          window_seconds: OTP_INVALID_WINDOW_SECONDS
        }
      });

      const invalidWindowCountQuery = await pool.query(
        `SELECT COUNT(*)::int AS attempt_count
         FROM auth_events
         WHERE cpf = $1
           AND event_type = 'otp_invalid'
           AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
        [cpf, OTP_INVALID_WINDOW_SECONDS]
      );
      const invalidAttemptCount = invalidWindowCountQuery.rows[0]?.attempt_count || 0;

      const invalidByLsidQuery = await pool.query(
        `SELECT COUNT(*)::int AS attempt_count
         FROM auth_events
         WHERE lsid = $1
           AND event_type = 'otp_invalid'
           AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
        [session.id, OTP_INVALID_WINDOW_SECONDS]
      );
      const invalidByLsidCount = invalidByLsidQuery.rows[0]?.attempt_count || 0;

      const invalidByIpCountQuery = await pool.query(
        `SELECT COUNT(*)::int AS attempt_count
         FROM auth_events
         WHERE client_ip = $1
           AND event_type = 'otp_invalid'
           AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
        [normalizeClientIp(wispr.userIp), OTP_INVALID_WINDOW_SECONDS]
      );
      const invalidByIpCount = invalidByIpCountQuery.rows[0]?.attempt_count || 0;

      const invalidByMacCountQuery = await pool.query(
        `SELECT COUNT(*)::int AS attempt_count
         FROM auth_events
         WHERE UPPER(regexp_replace(COALESCE(client_mac, ''), '[^A-Fa-f0-9]', '', 'g')) = UPPER(regexp_replace(COALESCE($1, ''), '[^A-Fa-f0-9]', '', 'g'))
           AND event_type = 'otp_invalid'
           AND created_at >= NOW() - ($2::int * INTERVAL '1 second')`,
        [normalizeMacIfPlain(wispr.userMac), OTP_INVALID_WINDOW_SECONDS]
      );
      const invalidByMacCount = invalidByMacCountQuery.rows[0]?.attempt_count || 0;

      if (invalidByLsidCount >= 3) {
        await recordSecurityEvent({
          eventType: 'bruteforce_otp_suspected',
          severity: 'medium',
          correlationType: 'lsid',
          correlationValue: session.id,
          description: 'Repetição de OTP inválido por LSID detectada.',
          reason: 'repetição por lsid',
          attemptCount: invalidByLsidCount,
          windowSeconds: OTP_INVALID_WINDOW_SECONDS,
          blockedUntil: null,
          details: { cpf, user_id: session.user_id, lsid: session.id, client_ip: normalizeClientIp(wispr.userIp), client_mac: normalizeMacIfPlain(wispr.userMac) }
        });
      }

      if (invalidAttemptCount >= OTP_INVALID_MAX_PER_WINDOW) {
        await recordSecurityEvent({
          eventType: 'multiple_failures_same_cpf',
          severity: 'high',
          correlationType: 'cpf',
          correlationValue: cpf,
          description: 'Muitas falhas de OTP inválido para o mesmo CPF.',
          reason: '5 OTP inválidos em 10 minutos',
          attemptCount: invalidAttemptCount,
          windowSeconds: OTP_INVALID_WINDOW_SECONDS,
          blockedUntil: null,
          details: { cpf, user_id: session.user_id, lsid: session.id }
        });
        if (invalidByIpCount >= OTP_INVALID_MAX_PER_WINDOW) {
          await recordSecurityEvent({
            eventType: 'multiple_failures_same_ip',
            severity: 'medium',
            correlationType: 'ip',
            correlationValue: normalizeClientIp(wispr.userIp),
            description: 'Muitas falhas de OTP inválido para o mesmo IP.',
            reason: '5 OTP inválidos em 10 minutos',
            attemptCount: invalidByIpCount,
            windowSeconds: OTP_INVALID_WINDOW_SECONDS,
            blockedUntil: null,
            details: { cpf, user_id: session.user_id, lsid: session.id }
          });
        }
        if (invalidByMacCount >= OTP_INVALID_MAX_PER_WINDOW) {
          await recordSecurityEvent({
            eventType: 'multiple_failures_same_mac',
            severity: 'medium',
            correlationType: 'mac',
            correlationValue: normalizeMacIfPlain(wispr.userMac),
            description: 'Muitas falhas de OTP inválido para o mesmo MAC.',
            reason: '5 OTP inválidos em 10 minutos',
            attemptCount: invalidByMacCount,
            windowSeconds: OTP_INVALID_WINDOW_SECONDS,
            blockedUntil: null,
            details: { cpf, user_id: session.user_id, lsid: session.id }
          });
        }
        const blockUntilResult = await pool.query(`SELECT NOW() + ($1::int * INTERVAL '1 second') AS blocked_until`, [OTP_INVALID_BLOCK_SECONDS]);
        const blockedUntil = blockUntilResult.rows[0]?.blocked_until || null;

        await recordAuthEvent({
          eventType: 'otp_validation_blocked',
          lsid: session.id,
          userId: session.user_id,
          cpf,
          clientIp: wispr.userIp,
          clientMac: wispr.userMac,
          ssid: session.ssid,
          apIp: session.apip,
          vlan: session.vlan,
          userAgent: req.get('user-agent') || '',
          details: {
            reason: '5 otp inválidos em 10 minutos',
            attempt_count: invalidAttemptCount,
            window_seconds: OTP_INVALID_WINDOW_SECONDS,
            blocked_until: blockedUntil
          }
        });

        await recordSecurityEvent({
          eventType: 'bruteforce_otp_suspected',
          severity: 'high',
          correlationType: 'cpf',
          correlationValue: cpf,
          description: 'Tentativas inválidas repetidas de OTP por CPF.',
          reason: '5 otp inválidos em 10 minutos',
          attemptCount: invalidAttemptCount,
          windowSeconds: OTP_INVALID_WINDOW_SECONDS,
          blockedUntil,
          details: { cpf, user_id: session.user_id, lsid: session.id, client_ip: normalizeClientIp(wispr.userIp), client_mac: normalizeMacIfPlain(wispr.userMac) }
        });

        await recordSecurityEvent({
          eventType: 'otp_validation_blocked',
          severity: 'high',
          correlationType: 'cpf',
          correlationValue: cpf,
          description: 'Validação de OTP temporariamente bloqueada.',
          reason: '5 OTP inválidos em 10 minutos',
          attemptCount: invalidAttemptCount,
          windowSeconds: OTP_INVALID_WINDOW_SECONDS,
          blockedUntil,
          details: { cpf, user_id: session.user_id, lsid: session.id, client_ip: normalizeClientIp(wispr.userIp), client_mac: normalizeMacIfPlain(wispr.userMac) }
        });

        throw new AuthFlowError('Validação OTP bloqueada.', buildOtpInvalidFriendlyMessage(), 429, 'otp_validation_blocked');
      }

      logInfo('otp_verify_failed', { lsid: parsed.data.lsid, user_id: session.user_id, attempts });
      throw new AuthFlowError('OTP inválido.', 'Código inválido ou expirado.');
    }

    await pool.query(`UPDATE otp_codes SET verified_at = NOW() WHERE id = $1`, [otp.id]);
    await pool.query(
      `UPDATE login_sessions
       SET otp_verified_at = COALESCE(otp_verified_at, NOW())
       WHERE id = $1`,
      [session.id]
    );
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
    const deviceType = detectDeviceType(req.get('user-agent') || '');
    const deviceName = getDeviceNameFromRequest(req, ctx);

    logInfo('otp_verify_success', { lsid: session.id, user_id: session.user_id, ue_ip: userIp, ue_mac: maskMac(userMac) });
    logInfo('authorize_flow_started', { lsid: session.id, user_id: session.user_id });

    const nbiResult = await authorizeViaNbi(ctx, {
      sessionId: session.id,
      userId: session.user_id,
      usernameRadius: session.username_radius,
      cpf: session.cpf_normalizado
    });

    await recordAuthEvent({
      eventType: 'sms_otp_login',
      lsid: session.id,
      userId: session.user_id,
      cpf: session.cpf_normalizado,
      clientMac: session.client_mac,
      clientIp: session.uip,
      ssid: session.ssid,
      apIp: session.apip,
      vlan: session.vlan,
      userAgent: req.get('user-agent') || '',
      details: { mode: nbiResult.mode, request_id: nbiResult.requestId || null, success: nbiResult.success }
    });

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

    if (!nbiResult.authorized) {
      const eventType = nbiResult.unconfirmed ? 'controller_authorization_unconfirmed' : 'controller_authorization_failed';
      logInfo(eventType, {
        lsid: session.id,
        user_id: session.user_id,
        request_id: nbiResult.requestId || null,
        response_code: String(nbiResult.detail?.ResponseCode || ''),
        reply_message: String(nbiResult.detail?.ReplyMessage || ''),
        auth_state_key: nbiResult.authStateKey || null,
        auth_state_value: nbiResult.authStateValue || null,
        authorization_reason: nbiResult.authorizationReason || null,
        selected_host: nbiResult.nbiIP || null,
        selected_source: nbiResult.selectedSource || 'nbi_authorize_result'
      });

      throw new AuthFlowError(
        'Controladora não confirmou autorização.',
        `Falha na autorização do acesso no SmartZone (sem confirmação explícita). request_id=${nbiResult.requestId || 'n/a'}`,
        401,
        nbiResult.unconfirmed ? 'controller_authorization_unconfirmed' : 'controller_authorization_failed'
      );
    }

    const selectedHostValidation = await ensureSelectedSmartZoneHostIsValid(nbiResult.nbiIP || '');
    if (!selectedHostValidation.valid) {
      logInfo('authorize_flow_failed', {
        lsid: session.id,
        user_id: session.user_id,
        reason: 'invalid_selected_host',
        selected_host: nbiResult.nbiIP || null,
        selected_source: nbiResult.selectedSource || 'nbi_authorize_result',
        fallback_trail: nbiResult.fallbackTrail || [],
        allowlist: SMARTZONE_ALLOWLIST,
        validation_reason: selectedHostValidation.reason
      });
      throw new AuthFlowError(
        'Host SmartZone retornado inválido.',
        'Falha na autorização do acesso no SmartZone. Host inválido selecionado.',
        401,
        'invalid_selected_host'
      );
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1)', [Number(session.user_id)]);

      // Regra de negócio: após a controladora confirmar a autorização,
      // mantemos no máximo 5 sessões OPEN por usuário e fechamos a OPEN mais antiga (nunca a sessão recém-autorizada).
      await client.query(
        `UPDATE login_sessions
         SET status = 'OPEN',
             authorized_at = COALESCE(authorized_at, NOW()),
             sz_nbi_ip = $2,
             last_sz_nbi_ip = COALESCE(sz_nbi_ip, $2),
             device_type = $3,
             device_name = COALESCE($4, device_name),
             user_agent = COALESCE(NULLIF($5, ''), user_agent)
         WHERE id = $1`,
        [session.id, selectedHostValidation.normalizedHost || null, deviceType, deviceName, req.get('user-agent') || '']
      );

      const maxSessionsResult = await enforceMaxOpenSessionsTx(client, session.user_id, session.id, 5);
      if (maxSessionsResult.enforced && maxSessionsResult.closedSession) {
        logInfo('max_active_sessions_enforced', {
          event: 'max_active_sessions_enforced',
          user_id: session.user_id,
          cpf: session.cpf_normalizado || null,
          new_session_id: session.id,
          closed_session_id: maxSessionsResult.closedSession.id,
          closed_session_authorized_at: maxSessionsResult.closedSession.authorized_at,
          active_count_before: maxSessionsResult.activeCountBefore,
          active_count_after: maxSessionsResult.activeCountAfter,
          closed_reason: 'max_sessions_exceeded'
        });

        await client.query(
          `INSERT INTO security_events (event_type, severity, correlation_type, correlation_value, description, reason, attempt_count, window_seconds, blocked_until, details_json)
           VALUES ('max_active_sessions_enforced', 'medium', 'cpf', $1, $2, $3, $4, NULL, NULL, $5::jsonb)`,
          [
            session.cpf_normalizado || String(session.user_id),
            'Sessão antiga encerrada por excesso de sessões ativas',
            'max_sessions_exceeded',
            maxSessionsResult.activeCountBefore,
            JSON.stringify({
              user_id: session.user_id,
              cpf: session.cpf_normalizado || null,
              new_session_id: session.id,
              closed_session_id: maxSessionsResult.closedSession.id,
              active_count_before: maxSessionsResult.activeCountBefore,
              active_count_after: maxSessionsResult.activeCountAfter,
              closed_reason: 'max_sessions_exceeded'
            })
          ]
        );
      }

      await client.query(
        `INSERT INTO portal_active_sessions (id, user_id, ue_ip, ue_mac, ssid, authorized_at, ended_at, last_seen_at, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NULL, NOW(), NOW())
         ON CONFLICT (user_id, ue_ip, ue_mac) DO UPDATE SET
           ssid = EXCLUDED.ssid,
           authorized_at = NOW(),
           ended_at = NULL,
           last_seen_at = NOW()`,
        [crypto.randomUUID(), session.user_id, userIp, normalizeMacIfPlain(userMac), ctx.ssid || null]
      );

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    res.cookie('portal_session', String(session.user_id), { maxAge: SESSION_MAX_AGE_MS, httpOnly: true, sameSite: 'lax' });

    logInfo('controller_authorization_confirmed', {
      lsid: session.id,
      user_id: session.user_id,
      request_id: nbiResult.requestId || null,
      auth_state_key: nbiResult.authStateKey || null,
      auth_state_value: nbiResult.authStateValue || null,
      authorization_reason: nbiResult.authorizationReason || null,
      nbi_ip: selectedHostValidation.normalizedHost || null,
      selected_host: selectedHostValidation.normalizedHost,
      selected_source: nbiResult.selectedSource || 'nbi_authorize_result',
      fallback_trail: nbiResult.fallbackTrail || [],
      allowlist: SMARTZONE_ALLOWLIST,
      failover_used: Boolean(nbiResult.failoverUsed)
    });
    return res.redirect(getOriginalUrl(ctx));
  } catch (error) {
    logError('otp_verify_error', { lsid, error });

    const isMissingWispr = error instanceof AuthFlowError && error.reason === 'missing_wispr_params';
    const isNbiFailed = error instanceof AuthFlowError && ['nbi_failed', 'invalid_selected_host', 'controller_authorization_failed', 'controller_authorization_unconfirmed'].includes(error.reason);
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
  const body = normalizeBodyFields(req.body);
  const wisprCtx = pickWisprParams(body);
  const postedUeIp = normalizeClientIp(body.ue_ip || wisprCtx.uip || '');
  const postedUeMac = normalizeMacIfPlain(body.ue_mac || wisprCtx.client_mac || '');

  try {
    let activeSession = null;
    if (portalSessionUserId) {
      activeSession = await getActiveSessionByUserId(portalSessionUserId);
    }
    if (!activeSession && postedUeMac) {
      activeSession = await getActiveSessionByMac(postedUeMac);
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
         SET consumed_at = COALESCE(consumed_at, NOW()),
             status = 'CLOSED',
             closed_at = COALESCE(closed_at, NOW())
         WHERE user_id = $1
           AND authorized_at IS NOT NULL`,
        [activeSession.user_id]
      );
      logInfo('logout_logical_completed', {
        user_id: activeSession.user_id,
        portal_active_session_id: activeSession.id,
        ue_ip: activeSession.ue_ip,
        ue_mac: maskMac(activeSession.ue_mac)
      });
    } else {
      logInfo('logout_no_active_session', {
        request_ip: clientIp,
        posted_ue_ip: postedUeIp || null,
        posted_ue_mac: postedUeMac ? maskMac(postedUeMac) : null
      });
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

app.get('/success', async (req, res) => {
  const portalSessionUserId = String(req.cookies?.portal_session || '').trim();
  if (!portalSessionUserId) {
    logInfo('success_guard_blocked', { request_ip: req.ip, reason: 'missing_portal_session_cookie' });
    return res.redirect('/portal');
  }

  const portalSessionUserIdNumber = Number(portalSessionUserId);
  if (!Number.isInteger(portalSessionUserIdNumber) || portalSessionUserIdNumber <= 0) {
    logInfo('success_guard_blocked', { request_ip: req.ip, reason: 'invalid_portal_session_cookie' });
    return res.redirect('/portal');
  }

  const activeSession = await getActiveSessionByUserId(portalSessionUserIdNumber);
  if (!activeSession) {
    logInfo('success_guard_blocked', {
      request_ip: req.ip,
      reason: 'no_active_authorized_session',
      user_id: portalSessionUserIdNumber
    });
    return res.redirect('/portal');
  }

  return res.render('success', { title: 'Conectado' });
});

async function bootstrap() {
  logNbiStartupConfiguration();

  await runMigrations(pool);

  await closeStaleAuthorizedOpenSessions(24);
  await closeExpiredPendingSessions(PENDING_SESSION_TIMEOUT_MINUTES);

  setInterval(() => {
    closeStaleAuthorizedOpenSessions(24);
  }, 30 * 60 * 1000);

  setInterval(() => {
    closeExpiredPendingSessions(PENDING_SESSION_TIMEOUT_MINUTES);
  }, 5 * 60 * 1000);

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
