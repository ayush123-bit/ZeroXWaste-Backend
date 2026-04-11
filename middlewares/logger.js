const fs = require('fs');
const path = require('path');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const logFile = path.join(logsDir, 'app.log');
const errorFile = path.join(logsDir, 'error.log');

const formatLog = (level, message, meta = {}) => {
  return JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta,
  }) + '\n';
};

const writeLog = (file, content) => {
  fs.appendFile(file, content, (err) => {
    if (err) console.error('Log write failed:', err);
  });
};

const logger = {
  info: (message, meta = {}) => {
    const log = formatLog('INFO', message, meta);
    process.stdout.write(log);
    writeLog(logFile, log);
  },
  error: (message, meta = {}) => {
    const log = formatLog('ERROR', message, meta);
    process.stderr.write(log);
    writeLog(errorFile, log);
    writeLog(logFile, log);
  },
  warn: (message, meta = {}) => {
    const log = formatLog('WARN', message, meta);
    process.stdout.write(log);
    writeLog(logFile, log);
  },
};

/**
 * Express middleware — logs every incoming request.
 */
const requestLogger = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logger.info('API Request', {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${Date.now() - start}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent')?.substring(0, 80),
    });
  });
  next();
};

module.exports = { logger, requestLogger };