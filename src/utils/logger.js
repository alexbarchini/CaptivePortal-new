const fs = require('fs');
const path = require('path');

const DEFAULT_LOG_PATH = path.resolve(process.cwd(), 'logs', 'auth-process.log');
const LOG_PATH = process.env.AUTH_LOG_FILE_PATH || DEFAULT_LOG_PATH;

function ensureLogDir() {
  fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
}

function serializeError(error) {
  if (!error) return null;
  return {
    name: error.name,
    message: error.message,
    stack: error.stack
  };
}

function writeLog(level, event, payload = {}) {
  try {
    ensureLogDir();
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      event,
      ...payload
    };
    fs.appendFileSync(LOG_PATH, `${JSON.stringify(entry)}\n`, 'utf8');
  } catch (error) {
    console.error('Falha ao escrever log de autenticação:', error);
  }
}

function logInfo(event, payload) {
  writeLog('info', event, payload);
}

function logError(event, payload = {}) {
  writeLog('error', event, {
    ...payload,
    error: serializeError(payload.error)
  });
}

module.exports = {
  LOG_PATH,
  logInfo,
  logError
};
