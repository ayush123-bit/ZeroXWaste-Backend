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
app.use(cors({
  origin: (origin, callback) => {
    const allowed = [
      process.env.FRONTEND_URL || 'http://localhost:5173',
      'http://localhost:5173',
      'http://localhost:3000',
    ];
    // Allow requests with no origin (mobile apps, Postman)
    if (!origin || allowed.includes(origin)) callback(null, true);
    else callback(null, true); // allow all origins in development
  },
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use(requestLogger);
app.use(apiLimiter); // global rate limit

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api', require('./routes/authRoutes'));
app.use('/api/reports', require('./routes/reportRoutes'));
app.use('/api/gamification', require('./routes/gamificationRoutes'));
app.use('/api/notifications', require('./routes/notificationRoutes'));
app.use('/api/workers', require('./routes/workerRoutes'));
app.use('/api/chatbot',  require('./routes/chatbotRoutes'));
app.use('/api/campaigns', require('./routes/campaignRoutes')); 
app.use('/api/sub-admin',  require('./routes/subAdminRoutes'));
app.use('/api/workers-portal', require('./routes/workerPortalRoutes'));
app.use('/api/analytics',    require('./routes/analyticsRoutes'));

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