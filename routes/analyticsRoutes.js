const express = require('express');
const router  = express.Router();
const User    = require('../models/User');
const Report  = require('../models/Report');
const jwt     = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

// GET /api/analytics/workers — worker performance stats
router.get('/workers', async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const workers = await User.find({ role: 'worker' })
      .select('name email picture workerProfile points')
      .lean();

    // For each worker, count their reports
    const workerStats = await Promise.all(workers.map(async (w) => {
      const [assigned, resolved, inProgress] = await Promise.all([
        Report.countDocuments({ 'assignedWorker.workerId': w._id.toString() }),
        Report.countDocuments({ 'assignedWorker.workerId': w._id.toString(), status: 'resolved' }),
        Report.countDocuments({ 'assignedWorker.workerId': w._id.toString(), status: 'in-progress' }),
      ]);
      const completionRate = assigned > 0 ? Math.round((resolved / assigned) * 100) : 0;
      return {
        _id:            w._id,
        name:           w.name,
        email:          w.email,
        picture:        w.picture,
        area:           w.workerProfile?.area || 'Unassigned',
        isAvailable:    w.workerProfile?.isAvailable ?? true,
        completedTasks: w.workerProfile?.completedTasks || resolved,
        assignedTasks:  assigned,
        inProgress,
        resolved,
        completionRate,
        points:         w.points || 0,
      };
    }));

    // Sort by completion rate desc
    workerStats.sort((a, b) => b.completionRate - a.completionRate);

    return res.status(200).json({ status: 'success', data: workerStats });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// GET /api/analytics/areas — area-wise performance
router.get('/areas', async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    // Get all area heads
    const areaHeads = await User.find({ role: 'area_head' })
      .select('name email adminProfile')
      .lean();

    // Get report stats grouped by address keywords
    const allReports = await Report.find({})
      .select('location status priorityLevel priorityScore createdAt')
      .lean();

    const areaStats = areaHeads.map(ah => {
      const areaName = ah.adminProfile?.area || '';
      const areaKeyword = areaName.split(',')[0].toLowerCase().trim();

      const areaReports = allReports.filter(r =>
        r.location?.address?.toLowerCase().includes(areaKeyword)
      );

      const total    = areaReports.length;
      const resolved = areaReports.filter(r => r.status === 'resolved').length;
      const pending  = areaReports.filter(r => r.status === 'pending').length;
      const high     = areaReports.filter(r => r.priorityLevel === 'High').length;
      const avgScore = total > 0
        ? Math.round(areaReports.reduce((s, r) => s + (r.priorityScore || 0), 0) / total)
        : 0;

      return {
        areaHead:       ah.name,
        areaHeadEmail:  ah.email,
        areaHeadId:     ah._id,
        area:           areaName,
        total, resolved, pending, high, avgScore,
        resolutionRate: total > 0 ? Math.round((resolved/total)*100) : 0,
      };
    });

    areaStats.sort((a, b) => b.resolutionRate - a.resolutionRate);

    return res.status(200).json({ status: 'success', data: areaStats });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// POST /api/analytics/message/:areaHeadId — admin sends message to area head
router.post('/message/:areaHeadId', async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ status: 'error', message: 'Message is required' });

    const { sendToUser } = require('../services/notificationService');
    sendToUser(req.params.areaHeadId, {
      type:    'ADMIN_MESSAGE',
      title:   '📩 Message from Super Admin',
      message,
      from:    'Super Admin',
    });

    return res.status(200).json({ status: 'success', message: 'Message sent' });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = router;