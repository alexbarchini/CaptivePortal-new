const fs = require('fs');
const path = require('path');

const LOG_TZ = process.env.LOG_TZ || 'America/Sao_Paulo';
const AUTH_LOG_FILE_PATH = process.env.AUTH_LOG_FILE_PATH || './logs/auth-process.log';

function ensureLogDirectory(logFilePath) {
  if (!logFilePath) return;
  const resolvedPath = path.resolve(logFilePath);
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
}

ensureLogDirectory(AUTH_LOG_FILE_PATH);

function getTimestampInZone(timeZone) {
  const date = new Date();
  const parts = new Intl.DateTimeFormat('sv-SE', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
    hourCycle: 'h23',
    timeZoneName: 'shortOffset'
  }).formatToParts(date);

  const get = (type) => parts.find((part) => part.type === type)?.value;
  const tzName = get('timeZoneName') || 'GMT-03:00';
  const offsetRaw = (tzName.replace('GMT', '') || '-03:00').replace('−', '-');
  const normalizedRaw = /^[+-]/.test(offsetRaw) ? offsetRaw : `+${offsetRaw}`;
  const offset = /^[+-]\d{2}:\d{2}$/.test(normalizedRaw)
    ? normalizedRaw
    : `${normalizedRaw.startsWith('-') ? '-' : '+'}${normalizedRaw.replace(/[-+]/, '').padStart(2, '0')}:00`;
  return `${get('year')}-${get('month')}-${get('day')}T${get('hour')}:${get('minute')}:${get('second')}.${get('fractionalSecond')}${offset}`;
}

function serializeError(error) {
  if (!error) return null;
  return {
    name: error.name,
    message: error.message,
    stack: error.stack
  };
}

function logger(level, event, payloadObject = {}) {
  try {
    const ts = getTimestampInZone(LOG_TZ);

    const entry = {
      level,
      event,
      ...payloadObject
    };
    delete entry.timestamp;
    const line = `${ts},${JSON.stringify(entry)}\n`;
    process.stdout.write(line);

    if (AUTH_LOG_FILE_PATH) {
      fs.appendFileSync(path.resolve(AUTH_LOG_FILE_PATH), line, 'utf8');
    }
  } catch (error) {
    console.error('Falha ao escrever log de autenticação:', error);
  }
}

function logInfo(event, payload) {
  logger('info', event, payload);
}

function logError(event, payload = {}) {
  logger('error', event, {
    ...payload,
    error: serializeError(payload.error)
  });
}

module.exports = {
  logger,
  logInfo,
  logError,
  LOG_TZ,
  AUTH_LOG_FILE_PATH
};
