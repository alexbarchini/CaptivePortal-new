const axios = require('axios');
const { logInfo } = require('../utils/logger');
const { resolveNbiMode, isMockMode, validateNbiConfigOrThrow } = require('./nbiConfig');

const REQUEST_TIMEOUT_MS = 5000;

function getNbiTarget(redirectParams = {}) {
  const nbiIP = redirectParams.nbiIP || process.env.SZ_MANAGEMENT_IP;
  if (!nbiIP) throw new Error('Parâmetro nbiIP/SZ_MANAGEMENT_IP não informado.');
  return `https://${nbiIP}:9443/portalintf`;
}

function basePayload() {
  return {
    Vendor: 'ruckus',
    RequestUserName: process.env.NBI_REQUEST_USERNAME || 'external-portal',
    RequestPassword: process.env.NBI_REQUEST_PASSWORD || '',
    APIVersion: '1.0',
    RequestCategory: 'UserOnlineControl'
  };
}

async function doPost(url, payload) {
  const response = await axios.post(url, payload, {
    timeout: REQUEST_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json' },
    httpsAgent: new (require('https').Agent)({
      rejectUnauthorized: process.env.NBI_TLS_INSECURE !== 'true'
    })
  });
  return response.data;
}

function isSuccess(data) {
  const code = String(data?.ResponseCode ?? '').toLowerCase();
  const type = String(data?.ResponseType ?? '').toLowerCase();
  const msg = String(data?.ReplyMessage ?? '').toLowerCase();
  return code === '0' || type.includes('ack') || msg.includes('success');
}

function isFail(data) {
  const code = String(data?.ResponseCode ?? '');
  const msg = String(data?.ReplyMessage ?? '').toLowerCase();
  return (code && code !== '0') || msg.includes('fail') || msg.includes('reject') || msg.includes('error');
}

async function loginAndPoll({ ueIp, ueMac, ueProxy = '0', ueUsername, uePassword, redirectParams }) {
  const nbiMode = resolveNbiMode();
  logInfo('nbi_authorization_mode', { mode: nbiMode, operation: 'legacy_login_and_poll' });
  if (isMockMode()) {
    return { success: true, mode: 'mock', detail: { message: 'NBI mock habilitado.' } };
  }

  validateNbiConfigOrThrow();

  const endpoint = getNbiTarget(redirectParams);
  const loginPayload = {
    ...basePayload(),
    RequestType: process.env.NBI_LOGIN_TYPE || 'LoginAsync',
    'UE-IP': ueIp,
    'UE-MAC': ueMac,
    'UE-Proxy': ueProxy,
    'UE-Username': ueUsername,
    'UE-Password': uePassword
  };

  const loginResponse = await doPost(endpoint, loginPayload);
  logInfo('nbi_login_response', { response_code: String(loginResponse?.ResponseCode ?? ''), request_type: loginPayload.RequestType });
  if (isSuccess(loginResponse) && loginPayload.RequestType === 'Login') {
    return { success: true, mode: 'direct', detail: loginResponse };
  }
  if (isFail(loginResponse)) {
    return { success: false, mode: 'login', detail: loginResponse };
  }

  const timeoutMs = Number(process.env.NBI_STATUS_TIMEOUT_MS || 18000);
  const intervalMs = Number(process.env.NBI_STATUS_INTERVAL_MS || 2000);
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    const statusPayload = {
      ...basePayload(),
      RequestType: 'Status',
      'UE-IP': ueIp,
      'UE-MAC': ueMac
    };
    const statusResponse = await doPost(endpoint, statusPayload);
    logInfo('nbi_status_response', { response_code: String(statusResponse?.ResponseCode ?? '') });
    if (isSuccess(statusResponse)) {
      return { success: true, mode: 'status', detail: statusResponse };
    }
    if (isFail(statusResponse)) {
      return { success: false, mode: 'status', detail: statusResponse };
    }
  }

  return { success: false, mode: 'timeout', detail: { message: 'Timeout ao consultar status no NBI.' } };
}

module.exports = { loginAndPoll };
