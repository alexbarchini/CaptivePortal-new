const axios = require('axios');
const https = require('https');
const { logInfo } = require('../utils/logger');

const REQUEST_TIMEOUT_MS = 5000;
const STATUS_POLL_INTERVAL_MS = 1000;
const STATUS_POLL_TIMEOUT_MS = 15000;

function basePayload() {
  return {
    Vendor: 'ruckus',
    RequestUserName: process.env.NBI_REQUEST_USERNAME || 'external-portal',
    RequestPassword: process.env.NBI_REQUEST_PASSWORD || '',
    APIVersion: '1.0',
    RequestCategory: 'UserOnlineControl'
  };
}

function getEndpoints(nbiIP) {
  if (!nbiIP) throw new Error('Parâmetro nbiIP não informado.');
  return [
    `https://${nbiIP}:9443/portalintf`,
    `http://${nbiIP}:9080/portalintf`
  ];
}

function hasSuccessCode(data) {
  return String(data?.ResponseCode ?? '') === '0';
}

function hasFailureCode(data) {
  const code = String(data?.ResponseCode ?? '');
  return code !== '' && code !== '0';
}

async function postJson(url, payload) {
  const response = await axios.post(url, payload, {
    timeout: REQUEST_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json' },
    httpsAgent: new https.Agent({ rejectUnauthorized: process.env.NBI_TLS_INSECURE !== 'true' })
  });
  return response.data;
}

async function postWithFallback(nbiIP, payload) {
  let lastError = null;
  for (const endpoint of getEndpoints(nbiIP)) {
    try {
      const response = await postJson(endpoint, payload);
      return { response, endpoint };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error('Falha ao chamar endpoint NBI.');
}

async function loginAsync({ nbiIP, ueIp, ueMac, proxy, ueUsername, uePassword }) {
  if (process.env.NBI_MOCK === 'true') {
    return { success: true, mode: 'mock', detail: { ReplyMessage: 'NBI mock habilitado.' } };
  }

  const loginPayload = {
    ...basePayload(),
    RequestType: 'LoginAsync',
    'UE-IP': ueIp,
    'UE-MAC': ueMac,
    'UE-Proxy': proxy || '0',
    'UE-Username': ueUsername,
    'UE-Password': uePassword
  };

  logInfo('nbi_login_async_sent', {
    nbi_ip: nbiIP,
    response_code: null,
    reply_message: null
  });

  const loginResult = await postWithFallback(nbiIP, loginPayload);
  const loginResponse = loginResult.response;

  logInfo('nbi_login_async_sent', {
    nbi_ip: nbiIP,
    endpoint: loginResult.endpoint,
    response_code: String(loginResponse?.ResponseCode ?? ''),
    reply_message: String(loginResponse?.ReplyMessage ?? '')
  });

  if (hasFailureCode(loginResponse)) {
    logInfo('nbi_login_failed', {
      nbi_ip: nbiIP,
      endpoint: loginResult.endpoint,
      response_code: String(loginResponse?.ResponseCode ?? ''),
      reply_message: String(loginResponse?.ReplyMessage ?? '')
    });
    return { success: false, mode: 'login', detail: loginResponse };
  }

  const startedAt = Date.now();
  while (Date.now() - startedAt < STATUS_POLL_TIMEOUT_MS) {
    await new Promise((resolve) => setTimeout(resolve, STATUS_POLL_INTERVAL_MS));

    const statusPayload = {
      ...basePayload(),
      RequestType: 'Status',
      'UE-IP': ueIp,
      'UE-MAC': ueMac,
      'UE-Proxy': proxy || '0',
      'UE-Username': ueUsername,
      'UE-Password': uePassword
    };

    const statusResult = await postWithFallback(nbiIP, statusPayload);
    const statusResponse = statusResult.response;

    logInfo('nbi_status_poll', {
      nbi_ip: nbiIP,
      endpoint: statusResult.endpoint,
      response_code: String(statusResponse?.ResponseCode ?? ''),
      reply_message: String(statusResponse?.ReplyMessage ?? '')
    });

    if (hasSuccessCode(statusResponse)) {
      logInfo('nbi_login_success', {
        nbi_ip: nbiIP,
        endpoint: statusResult.endpoint,
        response_code: String(statusResponse?.ResponseCode ?? ''),
        reply_message: String(statusResponse?.ReplyMessage ?? '')
      });
      return { success: true, mode: 'status', detail: statusResponse };
    }

    if (hasFailureCode(statusResponse)) {
      logInfo('nbi_login_failed', {
        nbi_ip: nbiIP,
        endpoint: statusResult.endpoint,
        response_code: String(statusResponse?.ResponseCode ?? ''),
        reply_message: String(statusResponse?.ReplyMessage ?? '')
      });
      return { success: false, mode: 'status', detail: statusResponse };
    }
  }

  const timeoutDetail = { ResponseCode: 'TIMEOUT', ReplyMessage: 'Timeout ao consultar status no NBI.' };
  logInfo('nbi_login_failed', {
    nbi_ip: nbiIP,
    response_code: timeoutDetail.ResponseCode,
    reply_message: timeoutDetail.ReplyMessage
  });

  return { success: false, mode: 'timeout', detail: timeoutDetail };
}

module.exports = { loginAsync };
