const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Report = require('../models/Report');
const { sendToUser } = require('../services/notificationService');
const jwt = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

// GET /api/workers — list all workers (admin use)
router.get('/', async (req, res) => {
  try {
    const workers = await User.find({ role: 'worker' })
      .select('name email picture workerProfile points')
      .lean();
    return res.status(200).json({ status: 'success', data: workers });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// POST /api/workers/promote/:userId — make a user a worker (admin use)
router.post('/promote/:userId', async (req, res) => {
  try {
    const { area } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { role: 'worker', 'workerProfile.area': area || '' },
      { new: true }
    );
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
    return res.status(200).json({ status: 'success', data: user });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// PATCH /api/workers/assign/:reportId — assign a worker to a report
router.patch('/assign/:reportId', async (req, res) => {
  try {
    const { workerId } = req.body;
    if (!workerId) return res.status(400).json({ status: 'error', message: 'workerId required' });

    const worker = await User.findById(workerId);
    if (!worker || worker.role !== 'worker') {
      return res.status(400).json({ status: 'error', message: 'User is not a worker' });
    }

    // Assign report to worker
    const report = await Report.findByIdAndUpdate(
      req.params.reportId,
      {
        assignedWorker: { workerId, workerName: worker.name, assignedAt: new Date() },
        status: 'in-progress',
      },
      { new: true, runValidators: false }
    );
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    // Add to worker's task list
    await User.findByIdAndUpdate(workerId, {
      $addToSet: { 'workerProfile.assignedTasks': report._id },
      'workerProfile.isAvailable': false,
    });

    // Notify worker
    sendToUser(workerId, {
      type: 'TASK_ASSIGNED',
      title: 'New task assigned to you',
      message: `You have been assigned a ${report.category} waste report`,
      reportId: report._id,
    });

    // Notify reporter
    if (report.userId) {
      sendToUser(report.userId, {
        type: 'STATUS_UPDATE',
        title: 'Worker assigned to your report',
        message: `${worker.name} has been assigned to handle your complaint`,
        reportId: report._id,
      });
    }

    return res.status(200).json({ status: 'success', data: { report, worker: { _id: worker._id, name: worker.name, area: worker.workerProfile?.area } } });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// PATCH /api/workers/complete/:reportId — worker marks task done
router.patch('/complete/:reportId', async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const report = await Report.findByIdAndUpdate(
      req.params.reportId,
      { status: 'resolved' },
      { new: true, runValidators: false }
    );
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    // Update worker stats
    await User.findByIdAndUpdate(user.userId, {
      $pull:  { 'workerProfile.assignedTasks': report._id },
      $inc:   { 'workerProfile.completedTasks': 1 },
      'workerProfile.isAvailable': true,
    });

    // Notify reporter
    if (report.userId) {
      sendToUser(report.userId, {
        type:    'STATUS_UPDATE',
        title:   'Your complaint has been resolved ✅',
        message: 'The assigned worker has marked your report as resolved',
        reportId: report._id,
        newStatus: 'resolved',
      });
    }

    return res.status(200).json({ status: 'success', data: report });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = router;