const VALID_MODES = new Set(['real', 'mock']);

function normalizeMode(value = '') {
  const mode = String(value || '').trim().toLowerCase();
  return VALID_MODES.has(mode) ? mode : '';
}

function resolveNbiMode() {
  const explicitMode = normalizeMode(process.env.NBI_MODE);
  if (explicitMode) return explicitMode;
  return String(process.env.NBI_MOCK || 'false').toLowerCase() === 'true' ? 'mock' : 'real';
}

function isMockMode() {
  return resolveNbiMode() === 'mock';
}

function parseSmartZoneManagementIps(rawValue = '') {
  return [...new Set(
    String(rawValue || '')
      .split(',')
      .map((item) => String(item || '').trim())
      .filter(Boolean)
  )];
}

function getSmartZoneHostsFromEnv() {
  const hosts = parseSmartZoneManagementIps(process.env.SZ_MANAGEMENT_IPS || '');
  for (const legacyHost of parseSmartZoneManagementIps(process.env.SZ_MANAGEMENT_IP || '')) {
    if (!hosts.includes(legacyHost)) hosts.push(legacyHost);
  }
  return hosts;
}

function buildNbiConfigSnapshot() {
  return {
    mode: resolveNbiMode(),
    smartZoneHosts: getSmartZoneHostsFromEnv(),
    hasUsername: Boolean(String(process.env.NBI_REQUEST_USERNAME || '').trim()),
    hasPassword: Boolean(String(process.env.NBI_REQUEST_PASSWORD || '').trim())
  };
}

function validateNbiConfigOrThrow() {
  const snapshot = buildNbiConfigSnapshot();
  if (snapshot.mode === 'mock') return snapshot;

  const issues = [];
  if (snapshot.smartZoneHosts.length === 0) issues.push('SZ_MANAGEMENT_IPS/SZ_MANAGEMENT_IP ausente');
  if (!snapshot.hasUsername) issues.push('NBI_REQUEST_USERNAME ausente');
  if (!snapshot.hasPassword) issues.push('NBI_REQUEST_PASSWORD ausente');

  if (issues.length > 0) {
    const error = new Error(`Configuração NBI real inválida: ${issues.join('; ')}.`);
    error.code = 'nbi_real_config_invalid';
    throw error;
  }

  return snapshot;
}

module.exports = {
  resolveNbiMode,
  isMockMode,
  getSmartZoneHostsFromEnv,
  validateNbiConfigOrThrow,
  buildNbiConfigSnapshot
};
