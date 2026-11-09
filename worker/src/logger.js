const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const min = LEVELS[process.env.LOG_LEVEL || 'info'] ?? 20;

function emit(level, msg, fields) {
  if (LEVELS[level] < min) return;
  const line = { ts: new Date().toISOString(), level, svc: 'worker', msg, ...(fields || {}) };
  console.log(JSON.stringify(line));
}

export const logger = {
  debug: (msg, fields) => emit('debug', msg, fields),
  info: (msg, fields) => emit('info', msg, fields),
  warn: (msg, fields) => emit('warn', msg, fields),
  error: (msg, fields) => emit('error', msg, fields),
};
