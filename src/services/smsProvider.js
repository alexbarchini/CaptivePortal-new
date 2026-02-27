const axios = require('axios');
const { logInfo, logError } = require('../utils/logger');

class StubSmsProvider {
  async send(toE164, message) {
    logInfo('sms_stub_send', {
      destination: toE164,
      message_preview: String(message || '').slice(0, 40)
    });
    return { ok: true, provider: 'stub' };
  }
}

class HttpSmsProvider {
  constructor({ url, token, fromName }) {
    this.url = url;
    this.token = token;
    this.fromName = fromName;
  }

  async send(toE164, message) {
    const payload = {
      to: toE164,
      from: this.fromName,
      message
    };

    await axios.post(this.url, payload, {
      timeout: 8000,
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      }
    });

    logInfo('sms_http_send_success', {
      destination: toE164,
      provider: 'http'
    });

    return { ok: true, provider: 'http' };
  }
}

function buildSmsProvider() {
  const providerMode = (process.env.SMS_PROVIDER || 'stub').toLowerCase();
  if (providerMode === 'http') {
    if (!process.env.SMS_HTTP_URL || !process.env.SMS_HTTP_TOKEN) {
      logError('sms_provider_invalid_config', {
        provider: 'http',
        error: new Error('SMS_HTTP_URL/SMS_HTTP_TOKEN ausentes, usando stub')
      });
      return new StubSmsProvider();
    }

    return new HttpSmsProvider({
      url: process.env.SMS_HTTP_URL,
      token: process.env.SMS_HTTP_TOKEN,
      fromName: process.env.SMS_FROM_NAME || 'TRT9'
    });
  }

  return new StubSmsProvider();
}

module.exports = {
  StubSmsProvider,
  HttpSmsProvider,
  buildSmsProvider
};
