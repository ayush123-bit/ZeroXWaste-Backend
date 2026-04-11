/**
 * In-memory rate limiter middleware.
 * Prevents spam submissions — no Redis required.
 * Production: replace Map with Redis for multi-instance support.
 */

const requestCounts = new Map();

/**
 * Factory — creates a rate limiter with custom settings.
 * @param {Object} options
 * @param {number} options.windowMs   - Time window in ms
 * @param {number} options.maxRequests - Max requests per window
 * @param {string} options.message    - Error message to return
 */
const createRateLimiter = ({ windowMs = 60000, maxRequests = 10, message = 'Too many requests. Please try again later.' }) => {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const key = `${ip}:${req.path}`;
    const now = Date.now();

    if (!requestCounts.has(key)) {
      requestCounts.set(key, { count: 1, windowStart: now });
      return next();
    }

    const record = requestCounts.get(key);

    // Reset window if expired
    if (now - record.windowStart > windowMs) {
      requestCounts.set(key, { count: 1, windowStart: now });
      return next();
    }

    record.count += 1;

    if (record.count > maxRequests) {
      return res.status(429).json({
        status: 'error',
        message,
        retryAfter: Math.ceil((record.windowStart + windowMs - now) / 1000),
      });
    }

    return next();
  };
};

// Clean up old entries every 5 minutes to prevent memory leak
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of requestCounts.entries()) {
    if (now - record.windowStart > 300000) requestCounts.delete(key);
  }
}, 300000);

// Pre-built limiters for common use cases
const reportSubmitLimiter   = createRateLimiter({ windowMs: 60 * 60 * 1000, maxRequests: 5,  message: 'You can only submit 5 reports per hour.' });
const apiLimiter            = createRateLimiter({ windowMs: 60 * 1000,       maxRequests: 60, message: 'API rate limit exceeded. Please slow down.' });
const authLimiter           = createRateLimiter({ windowMs: 15 * 60 * 1000, maxRequests: 10, message: 'Too many login attempts. Try again in 15 minutes.' });

module.exports = { createRateLimiter, reportSubmitLimiter, apiLimiter, authLimiter };