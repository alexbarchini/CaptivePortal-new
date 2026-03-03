const axios = require('axios');
const https = require('https');
const crypto = require('crypto');
const { logInfo, logError } = require('../utils/logger');

const REQUEST_TIMEOUT_MS = 5000;
const STATUS_POLL_INTERVAL_MS = 1000;
const STATUS_POLL_TIMEOUT_MS = 15000;
const NBI_DEBUG = (process.env.NBI_DEBUG || 'false').toLowerCase() === 'true';
const MAX_BODY_LOG_BYTES = 2048;

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
  return axios.post(url, payload, {
    timeout: REQUEST_TIMEOUT_MS,
    headers: { 'Content-Type': 'application/json' },
    httpsAgent: new https.Agent({ rejectUnauthorized: process.env.NBI_TLS_INSECURE !== 'true' })
  });
}

function maskMac(mac = '') {
  const value = String(mac || '');
  if (!value) return '';
  const compact = value.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  if (compact.length < 6) return '***';
  return `${compact.slice(0, 2)}:**:**:**:${compact.slice(-2)}`;
}

function truncateBody(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value || {});
  if (Buffer.byteLength(raw, 'utf8') <= MAX_BODY_LOG_BYTES) return raw;
  return `${Buffer.from(raw, 'utf8').subarray(0, MAX_BODY_LOG_BYTES).toString('utf8')}...(truncated)`;
}

function summarizeBody(data) {
  return {
    response_code: String(data?.ResponseCode ?? ''),
    reply_message: String(data?.ReplyMessage ?? ''),
    session_id: data?.SessionId || null,
    transaction_id: data?.TransactionId || null
  };
}

async function postWithFallback({ nbiIP, payload, requestType, requestId, ueIp, ueMac, ueUsername, proxy }) {
  let lastError = null;
  for (const endpoint of getEndpoints(nbiIP)) {
    logInfo('nbi_request_prepared', {
      request_id: requestId,
      nbi_ip: nbiIP,
      endpoint,
      request_type: requestType,
      ue_ip: ueIp,
      ue_mac: maskMac(ueMac),
      ue_username: ueUsername,
      proxy: proxy || '0',
      timeout_ms: REQUEST_TIMEOUT_MS
    });

    try {
      logInfo('nbi_http_request_sent', { request_id: requestId, timestamp: new Date().toISOString() });
      const response = await postJson(endpoint, payload);
      const responseData = response?.data || {};
      const selectedHeaders = {
        'content-type': response?.headers?.['content-type'] || null,
        server: response?.headers?.server || null
      };

      logInfo('nbi_http_response', NBI_DEBUG
        ? {
            request_id: requestId,
            http_status: response.status,
            headers: selectedHeaders,
            body: truncateBody(responseData),
            parsed: summarizeBody(responseData)
          }
        : {
            request_id: requestId,
            http_status: response.status,
            response_code: String(responseData?.ResponseCode ?? '')
          });

      return { response: responseData, endpoint, httpStatus: response.status };
    } catch (error) {
      lastError = error;
      logError('nbi_http_error', NBI_DEBUG
        ? {
            request_id: requestId,
            code: error?.code || null,
            message: error?.message || 'Erro desconhecido no NBI.',
            stack: error?.stack || null,
            config: {
              url: error?.config?.url || endpoint,
              method: error?.config?.method || 'post',
              timeout: error?.config?.timeout || REQUEST_TIMEOUT_MS
            }
          }
        : {
            request_id: requestId,
            code: error?.code || null,
            message: error?.message || 'Erro desconhecido no NBI.'
          });
    }
  }
  throw lastError || new Error('Falha ao chamar endpoint NBI.');
}

async function loginAsync({ nbiIP, ueIp, ueMac, proxy, ueUsername, uePassword }) {
  if (process.env.NBI_MOCK === 'true') {
    return { success: true, mode: 'mock', detail: { ReplyMessage: 'NBI mock habilitado.' } };
  }

  const requestId = crypto.randomUUID();
  const loginPayload = {
    ...basePayload(),
    RequestType: 'LoginAsync',
    'UE-IP': ueIp,
    'UE-MAC': ueMac,
    'UE-Proxy': proxy || '0',
    'UE-Username': ueUsername,
    'UE-Password': uePassword
  };

  const loginResult = await postWithFallback({
    nbiIP,
    payload: loginPayload,
    requestType: 'LoginAsync',
    requestId,
    ueIp,
    ueMac,
    ueUsername,
    proxy
  });
  const loginResponse = loginResult.response;

  logInfo('nbi_login_async_result', {
    request_id: requestId,
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
    return { success: false, mode: 'login', detail: loginResponse, requestId };
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

    const statusResult = await postWithFallback({
      nbiIP,
      payload: statusPayload,
      requestType: 'Status',
      requestId,
      ueIp,
      ueMac,
      ueUsername,
      proxy
    });
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
      return { success: true, mode: 'status', detail: statusResponse, requestId };
    }

    if (hasFailureCode(statusResponse)) {
      logInfo('nbi_login_failed', {
        nbi_ip: nbiIP,
        endpoint: statusResult.endpoint,
        response_code: String(statusResponse?.ResponseCode ?? ''),
        reply_message: String(statusResponse?.ReplyMessage ?? '')
      });
      return { success: false, mode: 'status', detail: statusResponse, requestId };
    }
  }

  const timeoutDetail = { ResponseCode: 'TIMEOUT', ReplyMessage: 'Timeout ao consultar status no NBI.' };
  logInfo('nbi_login_failed', {
    nbi_ip: nbiIP,
    response_code: timeoutDetail.ResponseCode,
    reply_message: timeoutDetail.ReplyMessage
  });

  return { success: false, mode: 'timeout', detail: timeoutDetail, requestId };
}

module.exports = { loginAsync };
