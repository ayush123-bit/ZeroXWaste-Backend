const { addConnection, removeConnection } = require('../services/notificationService');
const jwt = require('jsonwebtoken');

/**
 * GET /api/notifications/stream
 * Client connects here to receive real-time SSE notifications.
 */
const streamNotifications = (req, res) => {
  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'http://localhost:5173');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.flushHeaders();

  // Extract userId from JWT cookie
  let userId = 'anonymous';
  try {
    const token = req.cookies?.ZeroXtoken;
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      userId = decoded.userId;
    }
  } catch { /* anonymous user */ }

  // Send initial connection confirmation
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'Real-time notifications active' })}\n\n`);

  addConnection(userId, res);

  // Heartbeat every 30s to keep connection alive through proxies
  const heartbeat = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, 30000);

  // Cleanup on disconnect
  req.on('close', () => {
    clearInterval(heartbeat);
    removeConnection(userId, res);
  });
};

module.exports = { streamNotifications };