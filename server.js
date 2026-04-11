const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();

const { requestLogger, logger } = require('./middlewares/logger');
const { apiLimiter } = require('./middlewares/rateLimiter');
const { runEscalation } = require('./services/escalationService');

const app = express();

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5173', credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(requestLogger);
app.use(apiLimiter); // global rate limit

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api', require('./routes/authRoutes'));
app.use('/api/reports', require('./routes/reportRoutes'));
app.use('/api/gamification', require('./routes/gamificationRoutes'));
app.use('/api/notifications', require('./routes/notificationRoutes'));

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() }));

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, path: req.path });
  res.status(500).json({ status: 'error', message: 'Internal server error' });
});

// ─── DB + Server start ────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    logger.info('MongoDB connected');
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));

    // ─── Cron: Run escalation every hour ──────────────────────────────────
    const HOUR = 60 * 60 * 1000;
    setInterval(async () => {
      const result = await runEscalation();
      logger.info('Escalation cron completed', result);
    }, HOUR);

    // Run once on startup too
    runEscalation().then(r => logger.info('Initial escalation run', r));
  })
  .catch((err) => {
    logger.error('MongoDB connection failed', { error: err.message });
    process.exit(1);
  });