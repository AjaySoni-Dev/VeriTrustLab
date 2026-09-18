function write(level, event, fields = {}) {
  const record = {
    timestamp: new Date().toISOString(),
    level,
    service: 'veritrust-gateway',
    environment: process.env.VERCEL_ENV || process.env.NODE_ENV || 'development',
    event,
    ...fields,
  };
  const line = JSON.stringify(record);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

module.exports = {
  error(event, fields) { write('error', event, fields); },
  info(event, fields) { write('info', event, fields); },
  warn(event, fields) { write('warn', event, fields); },
};
