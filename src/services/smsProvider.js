const axios = require('axios');
const { logInfo, logError } = require('../utils/logger');

function safeMessagePreview(message) {
  return String(message || '')
    .replace(/\d/g, '*')
    .slice(0, 24);
}

function isSmsApiDebugEnabled() {
  return (process.env.SMS_API_DEBUG || '').toLowerCase() === 'true';
}

function shouldRetrySmsApiError(error) {
  const retriableCodes = ['ECONNRESET', 'ENOTFOUND'];
  const timeoutCode = error?.code === 'ECONNABORTED';
  const timeoutMessage = /timeout/i.test(String(error?.message || ''));

  return Boolean(timeoutCode || timeoutMessage || retriableCodes.includes(error?.code));
}

class StubSmsProvider {
  async send(toE164, message) {
    logInfo('sms_stub_send', {
      destination: toE164,
      message_preview: safeMessagePreview(message)
    });
    return { ok: true, provider: 'stub' };
  }
}

class ClasseA360SmsProvider {
  constructor({ url, username, password, carteiraCode, providerCode }) {
    this.url = url;
    this.username = username;
    this.password = password;
    this.carteiraCode = carteiraCode;
    this.providerCode = providerCode;
  }

  async send(toE164, message) {
    const payload = new URLSearchParams({
      telefone: toE164,
      texto: message,
      login: this.username,
      senha: this.password,
      cod_carteira: this.carteiraCode,
      cod_fornecedor: this.providerCode
    });

    logInfo('sms_api_send', {
      provider: 'classea360',
      destination: toE164,
      message_preview: safeMessagePreview(message)
    });

    const payloadKeys = Array.from(payload.keys());
    const maxAttempts = 2;
    let attempt = 0;

    while (attempt < maxAttempts) {
      try {
        const response = await axios.post(this.url, payload.toString(), {
          timeout: 5000,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        });

        logInfo('sms_api_response', {
          provider: 'classea360',
          destination: toE164,
          status: response.status,
          response_preview: String(response.data || '').slice(0, 120)
        });

        return { ok: true, provider: 'classea360' };
      } catch (error) {
        const shouldRetry = shouldRetrySmsApiError(error) && attempt < (maxAttempts - 1);

        if (isSmsApiDebugEnabled()) {
          logError('sms_api_error', {
            provider: 'classea360',
            status_code: error?.response?.status,
            response_headers: error?.response?.headers,
            response_body: String(error?.response?.data || '').slice(0, 1000),
            request_payload_keys: payloadKeys,
            destination: toE164,
            message_preview: safeMessagePreview(message),
            code: error?.code,
            retry_scheduled: shouldRetry,
            attempt: attempt + 1,
            error
          });
        }

        if (!shouldRetry) {
          throw error;
        }

        attempt += 1;
      }
    }
  }
}

function isSmsApiEnabled() {
  return (process.env.SMS_API_ENABLED || '').toLowerCase() === 'true';
}

function hasClasseA360Config() {
  return Boolean(
    process.env.SMS_API_URL
    && process.env.SMS_API_USERNAME
    && process.env.SMS_API_PASSWORD
    && process.env.SMS_API_COD_CARTEIRA
    && process.env.SMS_API_COD_FORNECEDOR
  );
}

function buildClasseA360SmsProvider() {
  return new ClasseA360SmsProvider({
    url: process.env.SMS_API_URL,
    username: process.env.SMS_API_USERNAME,
    password: process.env.SMS_API_PASSWORD,
    carteiraCode: process.env.SMS_API_COD_CARTEIRA,
    providerCode: process.env.SMS_API_COD_FORNECEDOR
  });
}

function buildStubWithConfigLog(reason) {
  logError('sms_provider_invalid_config', {
    provider: 'stub',
    error: new Error(reason)
  });

  return new StubSmsProvider();
}

function buildSmsProvider() {
  if (!isSmsApiEnabled()) {
    return new StubSmsProvider();
  }

  if (!process.env.SMS_API_URL) {
    return buildStubWithConfigLog('SMS_API_ENABLED=true mas SMS_API_URL ausente, usando stub');
  }

  if (!hasClasseA360Config()) {
    return buildStubWithConfigLog('Configuração ClasseA360 incompleta, usando stub');
  }

  return buildClasseA360SmsProvider();
}

module.exports = {
  StubSmsProvider,
  ClasseA360SmsProvider,
  buildSmsProvider
};
