const axios = require('axios');
const https = require('https');
const crypto = require('crypto');
const { logInfo, logError } = require('../utils/logger');
const { resolveNbiMode, isMockMode, validateNbiConfigOrThrow } = require('./nbiConfig');

const REQUEST_TIMEOUT_MS = Number(process.env.NBI_REQUEST_TIMEOUT_MS || 3000);
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

function responseCode(data) {
  return String(data?.ResponseCode ?? '').trim();
}

function isSuccess(data) {
  const code = responseCode(data);
  return code === '101' || code === '201';
}

function hasHttpSuccessStatus(httpStatus) {
  const status = Number(httpStatus);
  return Number.isFinite(status) && status >= 200 && status < 300;
}

function interpretControllerDisconnect(detail = {}, { httpStatus } = {}) {
  const code = responseCode(detail);
  const replyMessage = String(detail?.ReplyMessage || '').trim();
  const normalizedReply = replyMessage.toLowerCase();
  const failureReplyPattern = /fail|failed|failure|error|invalid|denied|reject|unauthori|timeout|not\s+found/;

  if (isSuccess(detail)) {
    return {
      success: true,
      reason: 'response_code_success',
      responseCode: code,
      replyMessage,
      httpStatus
    };
  }

  if (normalizedReply === 'ok') {
    return {
      success: true,
      reason: 'reply_message_ok',
      responseCode: code,
      replyMessage,
      httpStatus
    };
  }

  if (hasHttpSuccessStatus(httpStatus) && replyMessage && !failureReplyPattern.test(normalizedReply)) {
    return {
      success: true,
      reason: 'http_success_with_compatible_reply_message',
      responseCode: code,
      replyMessage,
      httpStatus
    };
  }

  if (!hasHttpSuccessStatus(httpStatus)) {
    return {
      success: false,
      reason: 'http_status_not_success',
      responseCode: code,
      replyMessage,
      httpStatus
    };
  }

  if (replyMessage && failureReplyPattern.test(normalizedReply)) {
    return {
      success: false,
      reason: 'reply_message_indicates_failure',
      responseCode: code,
      replyMessage,
      httpStatus
    };
  }

  return {
    success: false,
    reason: 'no_success_evidence',
    responseCode: code,
    replyMessage,
    httpStatus
  };
}

function isApiCallAccepted(data) {
  const code = responseCode(data);
  return code === '101' || code === '201' || code === '202';
}

function isPending(data) {
  return responseCode(data) === '202';
}

function isFailed(data) {
  const code = Number(responseCode(data));
  return Number.isFinite(code) && code >= 301;
}

function isRetryableNbiError(error) {
  const statusCode = Number(error?.response?.status || 0);
  if (Number.isFinite(statusCode) && statusCode >= 500) return true;

  const code = String(error?.code || '').toUpperCase();
  return code === 'ECONNABORTED'
    || code === 'ECONNREFUSED'
    || code === 'EHOSTUNREACH'
    || code === 'ENETUNREACH'
    || code === 'ETIMEDOUT'
    || code === 'ERR_NETWORK';
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
  const isPlainHexMac = /^[A-F0-9]{12}$/.test(compact);
  if (!isPlainHexMac) {
    if (value.length <= 6) return '***';
    return `${value.slice(0, 3)}...${value.slice(-3)}`;
  }
  return `${compact.slice(0, 2)}:**:**:**:${compact.slice(-2)}`;
}

function macToControllerFormat(mac = '') {
  const compact = String(mac || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  if (!/^[A-F0-9]{12}$/.test(compact)) return String(mac || '');
  return compact.match(/.{1,2}/g).join(':');
}

function sanitizePayloadForLog(payload = {}) {
  const copy = { ...(payload || {}) };
  if (copy.RequestPassword) copy.RequestPassword = '***';
  if (copy['UE-Password']) copy['UE-Password'] = '***';
  return copy;
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

function extractControllerAuthState(detail = {}) {
  const authKeys = ['AuthState', 'AuthorizationStatus', 'AuthStatus', 'UserState', 'UserStatus', 'ClientState', 'ClientStatus', 'SessionStatus', 'Status'];
  for (const key of authKeys) {
    if (detail[key] !== undefined && detail[key] !== null && String(detail[key]).trim()) {
      return { key, value: String(detail[key]).trim() };
    }
  }

  const reply = String(detail?.ReplyMessage || '').trim();
  if (reply) return { key: 'ReplyMessage', value: reply };
  return { key: null, value: '' };
}

function interpretControllerAuthorization(detail = {}) {
  const code = responseCode(detail);
  const authState = extractControllerAuthState(detail);
  const normalized = String(authState.value || '').toLowerCase();

  const explicitlyAuthorized = /\bauthorized\b|\bonline\b|\blogged\s*in\b|\bauthenticated\b|\blogin\s*succeeded\b/.test(normalized)
    && !/unauthorized|not\s+authorized|failed|denied|reject/.test(normalized);
  const explicitlyUnauthorized = /unauthorized|not\s+authorized|denied|reject|failed|offline/.test(normalized);

  if (explicitlyAuthorized) {
    return {
      authorized: true,
      unconfirmed: false,
      reason: 'explicit_authorized_state',
      responseCode: code,
      authStateKey: authState.key,
      authStateValue: authState.value
    };
  }

  if (explicitlyUnauthorized) {
    return {
      authorized: false,
      unconfirmed: false,
      reason: 'explicit_unauthorized_state',
      responseCode: code,
      authStateKey: authState.key,
      authStateValue: authState.value
    };
  }

  return {
    authorized: false,
    unconfirmed: true,
    reason: 'unconfirmed_controller_state',
    responseCode: code,
    authStateKey: authState.key,
    authStateValue: authState.value
  };
}

function logStatusInterpretation({ requestId, endpoint, interpretation }) {
  logInfo('nbi_status_authorization_interpreted', {
    request_id: requestId,
    endpoint,
    response_code: interpretation.responseCode,
    auth_state_key: interpretation.authStateKey,
    auth_state_value: interpretation.authStateValue,
    interpreted_authorized: interpretation.authorized,
    interpretation_unconfirmed: interpretation.unconfirmed,
    interpretation_reason: interpretation.reason
  });
}

async function postWithFallback({ nbiIP, payload, requestType, requestId, ueIp, ueMac, ueUsername, proxy }) {
  let lastError = null;
  for (const endpoint of getEndpoints(nbiIP)) {
    logInfo('nbi_request_prepared', {
      request_id: requestId,
      host_selected: nbiIP,
      endpoint,
      method: 'POST',
      request_type: requestType,
      payload: sanitizePayloadForLog(payload),
      ue_ip: ueIp,
      ue_mac: maskMac(ueMac),
      ue_username: ueUsername,
      proxy: proxy || '0',
      timeout_ms: REQUEST_TIMEOUT_MS
    });

    try {
      const response = await postJson(endpoint, payload);
      const responseData = response?.data || {};
      const selectedHeaders = {
        'content-type': response?.headers?.['content-type'] || null,
        server: response?.headers?.server || null
      };

      logInfo('nbi_http_response', NBI_DEBUG
        ? {
            request_id: requestId,
            endpoint,
            method: 'POST',
            http_status: response.status,
            headers: selectedHeaders,
            body: truncateBody(responseData),
            parsed: summarizeBody(responseData)
          }
        : {
            request_id: requestId,
            endpoint,
            method: 'POST',
            http_status: response.status,
            response_code: String(responseData?.ResponseCode ?? ''),
            raw_body: truncateBody(responseData)
          });

      return { response: responseData, endpoint, httpStatus: response.status };
    } catch (error) {
      lastError = error;
      logError('nbi_http_error', NBI_DEBUG
        ? {
            request_id: requestId,
            endpoint,
            method: 'POST',
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
            endpoint,
            method: 'POST',
            code: error?.code || null,
            message: error?.message || 'Erro desconhecido no NBI.'
          });
    }
  }
  throw lastError || new Error('Falha ao chamar endpoint NBI.');
}

async function loginAsync({ nbiIP, ueIp, ueMac, proxy, ueUsername, uePassword }) {
  const nbiMode = resolveNbiMode();
  logInfo('nbi_authorization_mode', { mode: nbiMode, operation: 'login_async' });
  if (isMockMode()) {
    const detail = { ResponseCode: '101', ReplyMessage: 'Login accepted (mock).', AuthState: 'UNAUTHORIZED' };
    const interpretation = interpretControllerAuthorization(detail);
    logStatusInterpretation({ requestId: 'nbi-mock', endpoint: 'mock://nbi/login', interpretation });
    return {
      success: true,
      authorized: interpretation.authorized,
      unconfirmed: interpretation.unconfirmed,
      authorizationReason: interpretation.reason,
      authStateKey: interpretation.authStateKey,
      authStateValue: interpretation.authStateValue,
      mode: 'mock',
      detail,
      requestId: 'nbi-mock'
    };
  }

  validateNbiConfigOrThrow();

  const requestId = crypto.randomUUID();
  const ueMacController = macToControllerFormat(ueMac);
  const loginPayload = {
    ...basePayload(),
    RequestType: 'LoginAsync',
    'UE-IP': ueIp,
    'UE-MAC': ueMacController,
    'UE-Proxy': proxy || '0',
    'UE-Username': ueUsername,
    'UE-Password': uePassword
  };

  const loginResult = await postWithFallback({ nbiIP, payload: loginPayload, requestType: 'LoginAsync', requestId, ueIp, ueMac: ueMacController, ueUsername, proxy });
  const loginResponse = loginResult.response;

  logInfo('nbi_login_async_result', {
    request_id: requestId,
    nbi_ip: nbiIP,
    endpoint: loginResult.endpoint,
    response_code: responseCode(loginResponse),
    reply_message: String(loginResponse?.ReplyMessage ?? ''),
    session_id: loginResponse?.SessionId || null,
    transaction_id: loginResponse?.TransactionId || null
  });

  if (!isApiCallAccepted(loginResponse) || isFailed(loginResponse)) {
    logInfo('nbi_login_failed', {
      request_id: requestId,
      nbi_ip: nbiIP,
      endpoint: loginResult.endpoint,
      response_code: responseCode(loginResponse),
      reply_message: String(loginResponse?.ReplyMessage ?? ''),
      session_id: loginResponse?.SessionId || null,
      transaction_id: loginResponse?.TransactionId || null
    });
    return { success: false, authorized: false, unconfirmed: false, mode: 'login', detail: loginResponse, requestId };
  }

  const startedAt = Date.now();
  while (Date.now() - startedAt < STATUS_POLL_TIMEOUT_MS) {
    await new Promise((resolve) => setTimeout(resolve, STATUS_POLL_INTERVAL_MS));

    const statusPayload = {
      ...basePayload(),
      RequestType: 'Status',
      'UE-IP': ueIp,
      'UE-MAC': ueMacController,
      'UE-Proxy': proxy || '0',
      'UE-Username': ueUsername,
      'UE-Password': uePassword
    };

    const statusResult = await postWithFallback({ nbiIP, payload: statusPayload, requestType: 'Status', requestId, ueIp, ueMac: ueMacController, ueUsername, proxy });
    const statusResponse = statusResult.response;

    logInfo('nbi_status_poll', {
      request_id: requestId,
      nbi_ip: nbiIP,
      endpoint: statusResult.endpoint,
      response_code: responseCode(statusResponse),
      http_call_accepted: isApiCallAccepted(statusResponse),
      reply_message: String(statusResponse?.ReplyMessage ?? ''),
      session_id: statusResponse?.SessionId || null,
      transaction_id: statusResponse?.TransactionId || null
    });

    if (isPending(statusResponse)) continue;

    const interpretation = interpretControllerAuthorization(statusResponse);
    logStatusInterpretation({ requestId, endpoint: statusResult.endpoint, interpretation });

    if (isApiCallAccepted(statusResponse)) {
      return {
        success: true,
        authorized: interpretation.authorized,
        unconfirmed: interpretation.unconfirmed,
        authorizationReason: interpretation.reason,
        authStateKey: interpretation.authStateKey,
        authStateValue: interpretation.authStateValue,
        mode: 'status',
        detail: statusResponse,
        requestId
      };
    }

    const failedDetail = {
      ResponseCode: responseCode(statusResponse),
      ReplyMessage: String(statusResponse?.ReplyMessage || 'Resposta inválida no polling de status.')
    };

    logInfo('nbi_status_poll_failed', {
      request_id: requestId,
      nbi_ip: nbiIP,
      endpoint: statusResult.endpoint,
      response_code: failedDetail.ResponseCode,
      reply_message: failedDetail.ReplyMessage,
      controller_decision_fields: {
        auth_state_key: interpretation.authStateKey,
        auth_state_value: interpretation.authStateValue
      }
    });

    return {
      success: false,
      authorized: false,
      unconfirmed: false,
      mode: 'status',
      detail: failedDetail,
      requestId
    };
  }

  const timeoutDetail = { ResponseCode: 'TIMEOUT', ReplyMessage: 'Timeout ao consultar status no NBI.' };
  logInfo('nbi_login_failed', {
    request_id: requestId,
    nbi_ip: nbiIP,
    response_code: timeoutDetail.ResponseCode,
    reply_message: timeoutDetail.ReplyMessage
  });

  return { success: false, authorized: false, unconfirmed: false, mode: 'timeout', detail: timeoutDetail, requestId };
}

async function disconnectAsync({ nbiIP, ueIp, ueMac, proxy, ueUsername }) {
  const nbiMode = resolveNbiMode();
  logInfo('nbi_authorization_mode', { mode: nbiMode, operation: 'disconnect_async' });
  if (isMockMode()) {
    return { success: true, mode: 'mock', detail: { ReplyMessage: 'NBI mock habilitado.' } };
  }

  validateNbiConfigOrThrow();

  const requestId = crypto.randomUUID();
  const ueMacController = macToControllerFormat(ueMac);
  const disconnectPayload = {
    ...basePayload(),
    RequestType: 'Disconnect',
    'UE-IP': ueIp,
    'UE-MAC': ueMacController,
    'UE-Proxy': proxy || '0',
    ...(ueUsername ? { 'UE-Username': ueUsername } : {})
  };

  const disconnectResult = await postWithFallback({ nbiIP, payload: disconnectPayload, requestType: 'Disconnect', requestId, ueIp, ueMac: ueMacController, proxy, ueUsername });
  const disconnectResponse = disconnectResult.response;
  const interpretation = interpretControllerDisconnect(disconnectResponse, { httpStatus: disconnectResult.httpStatus });

  logInfo('nbi_disconnect_result', {
    request_id: requestId,
    nbi_ip: nbiIP,
    host_selected: nbiIP,
    endpoint: disconnectResult.endpoint,
    payload: sanitizePayloadForLog(disconnectPayload),
    http_status: disconnectResult.httpStatus || null,
    response_code: responseCode(disconnectResponse),
    reply_message: String(disconnectResponse?.ReplyMessage ?? ''),
    session_id: disconnectResponse?.SessionId || null,
    transaction_id: disconnectResponse?.TransactionId || null,
    interpreted_result: interpretation.success ? 'success' : 'failure',
    interpretation_reason: interpretation.reason
  });

  return {
    success: interpretation.success,
    mode: 'disconnect',
    detail: disconnectResponse,
    requestId,
    endpoint: disconnectResult.endpoint,
    httpStatus: disconnectResult.httpStatus || null,
    interpretationReason: interpretation.reason
  };
}

async function statusAsync({ nbiIP, ueIp, ueMac, proxy, ueUsername, uePassword }) {
  const nbiMode = resolveNbiMode();
  logInfo('nbi_authorization_mode', { mode: nbiMode, operation: 'status_async' });
  if (isMockMode()) {
    const detail = { ResponseCode: '101', ReplyMessage: 'Status checked (mock).', AuthState: 'UNAUTHORIZED' };
    const interpretation = interpretControllerAuthorization(detail);
    logStatusInterpretation({ requestId: 'nbi-mock', endpoint: 'mock://nbi/status', interpretation });
    return {
      success: true,
      authorized: interpretation.authorized,
      unconfirmed: interpretation.unconfirmed,
      authorizationReason: interpretation.reason,
      authStateKey: interpretation.authStateKey,
      authStateValue: interpretation.authStateValue,
      mode: 'mock',
      detail
    };
  }

  validateNbiConfigOrThrow();

  const requestId = crypto.randomUUID();
  const ueMacController = macToControllerFormat(ueMac);
  const statusPayload = {
    ...basePayload(),
    RequestType: 'Status',
    'UE-IP': ueIp,
    'UE-MAC': ueMacController,
    'UE-Proxy': proxy || '0',
    ...(ueUsername ? { 'UE-Username': ueUsername } : {}),
    ...(uePassword ? { 'UE-Password': uePassword } : {})
  };

  const statusResult = await postWithFallback({ nbiIP, payload: statusPayload, requestType: 'Status', requestId, ueIp, ueMac: ueMacController, ueUsername, proxy });

  const statusResponse = statusResult.response;
  logInfo('nbi_status_result', {
    request_id: requestId,
    nbi_ip: nbiIP,
    endpoint: statusResult.endpoint,
    response_code: responseCode(statusResponse),
    reply_message: String(statusResponse?.ReplyMessage ?? ''),
    session_id: statusResponse?.SessionId || null,
    transaction_id: statusResponse?.TransactionId || null
  });

  const interpretation = interpretControllerAuthorization(statusResponse);
  logStatusInterpretation({ requestId, endpoint: statusResult.endpoint, interpretation });

  return {
    success: isApiCallAccepted(statusResponse),
    authorized: interpretation.authorized,
    unconfirmed: interpretation.unconfirmed,
    authorizationReason: interpretation.reason,
    authStateKey: interpretation.authStateKey,
    authStateValue: interpretation.authStateValue,
    mode: 'status',
    detail: statusResponse,
    requestId
  };
}

module.exports = { loginAsync, disconnectAsync, statusAsync, isRetryableNbiError };
