/**
 * Simple in-memory cache with TTL (Time To Live).
 * Avoids repeated expensive DB aggregation queries for stats/leaderboard.
 * In production, replace with Redis using the same interface.
 */

const cache = new Map();

/**
 * Get a cached value. Returns null if expired or missing.
 */
const get = (key) => {
  if (!cache.has(key)) return null;
  const { value, expiresAt } = cache.get(key);
  if (Date.now() > expiresAt) {
    cache.delete(key);
    return null;
  }
  return value;
};

/**
 * Set a cache value with TTL in seconds.
 */
const set = (key, value, ttlSeconds = 60) => {
  cache.set(key, {
    value,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
};

/**
 * Invalidate a specific key (call this when data changes).
 */
const invalidate = (key) => {
  cache.delete(key);
};

/**
 * Invalidate all keys matching a prefix pattern.
 */
const invalidatePattern = (prefix) => {
  for (const key of cache.keys()) {
    if (key.startsWith(prefix)) cache.delete(key);
  }
};

const stats = () => ({
  size: cache.size,
  keys: Array.from(cache.keys()),
});

module.exports = { get, set, invalidate, invalidatePattern, stats };