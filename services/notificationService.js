/**
 * Server-Sent Events (SSE) notification service.
 * Clients connect to GET /api/notifications/stream
 * and receive real-time updates when report status changes.
 *
 * No external dependencies — pure Node.js streams.
 */

// Store active SSE connections keyed by userId
const connections = new Map();

/**
 * Register a new SSE client connection.
 */
const addConnection = (userId, res) => {
  if (!connections.has(userId)) {
    connections.set(userId, new Set());
  }
  connections.get(userId).add(res);
  console.log(`[SSE] Client connected: ${userId} (total: ${connections.size} users)`);
};

/**
 * Remove a closed SSE connection.
 */
const removeConnection = (userId, res) => {
  if (connections.has(userId)) {
    connections.get(userId).delete(res);
    if (connections.get(userId).size === 0) {
      connections.delete(userId);
    }
  }
};

/**
 * Send a notification to a specific user.
 * @param {string} userId
 * @param {Object} payload - { type, title, message, data }
 */
const sendToUser = (userId, payload) => {
  if (!connections.has(userId)) return;

  const message = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of connections.get(userId)) {
    try {
      res.write(message);
    } catch {
      connections.get(userId).delete(res);
    }
  }
};

/**
 * Broadcast a notification to ALL connected clients (e.g. new high priority report).
 */
const broadcast = (payload) => {
  const message = `data: ${JSON.stringify(payload)}\n\n`;
  for (const [userId, clients] of connections) {
    for (const res of clients) {
      try {
        res.write(message);
      } catch {
        clients.delete(res);
      }
    }
  }
};

module.exports = { addConnection, removeConnection, sendToUser, broadcast };