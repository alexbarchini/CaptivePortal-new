const axios = require('axios');
const { logInfo, logError } = require('../utils/logger');
const { normalizeBrazilianPhone, cleanDigits } = require('../utils/validators');

const DEFAULT_SMS_API_URL = 'https://api360.classeaservicos.com.br/api/send.php';
const RESPONSE_BODY_LOG_LIMIT = 1024;
const NETWORK_RETRY_LIMIT = 2;

function truncateForLog(value, limit = RESPONSE_BODY_LOG_LIMIT) {
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? '');
  return text.length <= limit ? text : `${text.slice(0, limit)}...`;
}

function normalizeToE164(phoneInput = '') {
  const asString = String(phoneInput || '').trim();
  if (asString.startsWith('+')) {
    const digits = `+${cleanDigits(asString)}`;
    if (/^\+\d{10,15}$/.test(digits)) return digits;
  }

  const normalizedBr = normalizeBrazilianPhone(asString);
  if (!normalizedBr) {
    throw new Error('Telefone inválido para envio de SMS.');
  }

  return normalizedBr;
}

function shouldRetryNetworkError(error) {
  if (error.response) return false;
  if (error.code === 'ECONNABORTED') return true;

  const retryableCodes = new Set([
    'ENOTFOUND',
    'ECONNRESET',
    'ECONNREFUSED',
    'ETIMEDOUT',
    'EAI_AGAIN',
    'EPIPE'
  ]);

  return retryableCodes.has(error.code);
}

class StubSmsProvider {
  async sendSms(toE164, message) {
    const destination = normalizeToE164(toE164);
    logInfo('sms_mock_sent', {
      destination,
      message_preview: String(message || '').slice(0, 60),
      note: 'SMS mock sent'
    });

    return { ok: true, provider: 'stub' };
  }
}

class ClasseA360SmsProvider {
  constructor({
    apiUrl,
    username,
    password,
    codCarteira,
    codFornecedor,
    fieldNames = {}
  }) {
    this.apiUrl = apiUrl;
    this.username = username;
    this.password = password;
    this.codCarteira = codCarteira;
    this.codFornecedor = codFornecedor;
    this.fieldNames = {
      username: fieldNames.username || 'username',
      password: fieldNames.password || 'password',
      to: fieldNames.to || 'to',
      message: fieldNames.message || 'message',
      codCarteira: fieldNames.codCarteira || 'cod_carteira',
      codFornecedor: fieldNames.codFornecedor || 'cod_fornecedor',
      cpf: fieldNames.cpf || 'cpf'
    };
  }

  buildPayload({ destination, message, cpfOptional }) {
    const payload = {
      [this.fieldNames.username]: this.username,
      [this.fieldNames.password]: this.password,
      [this.fieldNames.to]: destination,
      [this.fieldNames.message]: message,
      [this.fieldNames.codCarteira]: this.codCarteira,
      [this.fieldNames.codFornecedor]: this.codFornecedor
    };

    if (cpfOptional) {
      payload[this.fieldNames.cpf] = cleanDigits(cpfOptional);
    }

    return payload;
  }

  async sendSms(toE164, message, cpfOptional) {
    const destination = normalizeToE164(toE164);
    const payload = this.buildPayload({ destination, message, cpfOptional });

    for (let attempt = 0; attempt <= NETWORK_RETRY_LIMIT; attempt++) {
      try {
        const response = await axios.post(this.apiUrl, new URLSearchParams(payload).toString(), {
          timeout: 5000,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          validateStatus: () => true
        });

        logInfo('sms_classea360_response', {
          provider: 'classea360',
          attempt: attempt + 1,
          status_code: response.status,
          body: truncateForLog(response.data)
        });

        if (response.status >= 200 && response.status < 300) {
          return { ok: true, provider: 'classea360', status: response.status };
        }

        throw new Error(`ClasseA 360 retornou status ${response.status}`);
      } catch (error) {
        if (error.response) {
          logError('sms_classea360_http_error', {
            provider: 'classea360',
            attempt: attempt + 1,
            status_code: error.response.status,
            body: truncateForLog(error.response.data),
            error: new Error(`Falha HTTP no envio de SMS (status ${error.response.status})`)
          });
          throw error;
        }

        if (shouldRetryNetworkError(error) && attempt < NETWORK_RETRY_LIMIT) {
          logError('sms_classea360_network_retry', {
            provider: 'classea360',
            attempt: attempt + 1,
            error_code: error.code,
            error: new Error(`Erro de rede ao enviar SMS (tentando novamente): ${error.code || 'UNKNOWN'}`)
          });
          continue;
        }

        logError('sms_classea360_network_error', {
          provider: 'classea360',
          attempt: attempt + 1,
          error_code: error.code,
          error: new Error(`Erro de rede ao enviar SMS: ${error.code || error.message}`)
        });
        throw error;
      }
    }

    throw new Error('Falha inesperada no envio de SMS.');
  }
}

function buildSmsProvider() {
  const smsApiEnabled = (process.env.SMS_API_ENABLED || 'false').toLowerCase() === 'true';
  if (!smsApiEnabled) return new StubSmsProvider();

  const requiredVars = ['SMS_API_USERNAME', 'SMS_API_PASSWORD', 'SMS_API_COD_CARTEIRA'];
  const missing = requiredVars.filter((key) => !process.env[key]);

  if (missing.length > 0) {
    logError('sms_provider_invalid_config', {
      provider: 'classea360',
      missing,
      error: new Error('Configuração de SMS incompleta, usando stub')
    });
    return new StubSmsProvider();
  }

  return new ClasseA360SmsProvider({
    apiUrl: process.env.SMS_API_URL || DEFAULT_SMS_API_URL,
    username: process.env.SMS_API_USERNAME,
    password: process.env.SMS_API_PASSWORD,
    codCarteira: process.env.SMS_API_COD_CARTEIRA,
    codFornecedor: process.env.SMS_API_COD_FORNECEDOR || 'classea_token',
    fieldNames: {
      username: process.env.SMS_API_FIELD_USERNAME,
      password: process.env.SMS_API_FIELD_PASSWORD,
      to: process.env.SMS_API_FIELD_TO,
      message: process.env.SMS_API_FIELD_MESSAGE,
      codCarteira: process.env.SMS_API_FIELD_COD_CARTEIRA,
      codFornecedor: process.env.SMS_API_FIELD_COD_FORNECEDOR,
      cpf: process.env.SMS_API_FIELD_CPF
    }
  });
}

module.exports = {
  StubSmsProvider,
  ClasseA360SmsProvider,
  buildSmsProvider,
  normalizeToE164
};
