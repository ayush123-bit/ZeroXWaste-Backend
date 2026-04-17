const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Report = require('../models/Report');
const { sendToUser } = require('../services/notificationService');
const upload = require('../middlewares/upload');
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

// POST /api/workers/submit-proof/:reportId — worker uploads completion proof with location
router.post('/submit-proof/:reportId', upload.single('proof'), async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const { workerLat, workerLng } = req.body;
    const report = await Report.findById(req.params.reportId);
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    // Upload proof image to Cloudinary
    const { uploadToCloudinary } = require('../config/cloudinary');
    const proofImage = await uploadToCloudinary(req.file.buffer, req.file.originalname);

    // Compare locations — calculate distance in meters using Haversine formula
    const reportLat = report.location.coordinates[1];
    const reportLng = report.location.coordinates[0];
    const wLat = parseFloat(workerLat);
    const wLng = parseFloat(workerLng);

    const R = 6371000; // Earth radius in meters
    const dLat = (wLat - reportLat) * Math.PI / 180;
    const dLng = (wLng - reportLng) * Math.PI / 180;
    const a = Math.sin(dLat/2)**2 + Math.cos(reportLat * Math.PI/180) * Math.cos(wLat * Math.PI/180) * Math.sin(dLng/2)**2;
    const distanceMeters = Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)));

    const locationVerified = distanceMeters <= 500; // within 500 meters

    // Update report with proof and auto-resolve if location verified
    const updateData = {
      'completionProof.imageUrl':    proofImage.url,
      'completionProof.publicId':    proofImage.publicId,
      'completionProof.uploadedAt':  new Date(),
      'completionProof.workerLat':   wLat,
      'completionProof.workerLng':   wLng,
      'completionProof.locationVerified': locationVerified,
      'completionProof.distanceMeters':   distanceMeters,
    };

    if (locationVerified) {
      updateData.status = 'resolved';
      updateData.progressPercentage = 100;
      updateData.currentStage = 'Resolved';
    }

    const updatedReport = await Report.findByIdAndUpdate(
      req.params.reportId,
      updateData,
      { new: true, runValidators: false }
    );

    // Update worker stats
    if (locationVerified) {
      await User.findByIdAndUpdate(user.userId, {
        $pull: { 'workerProfile.assignedTasks': report._id },
        $inc:  { 'workerProfile.completedTasks': 1 },
        'workerProfile.isAvailable': true,
      });

      // Award points to reporter
      const { awardPoints } = require('../services/gamificationService');
      if (report.userId) await awardPoints(report.userId, 'REPORT_RESOLVED');

      // Send resolution notification with proof
      if (report.userId) {
        sendToUser(report.userId, {
          type:        'COMPLAINT_RESOLVED',
          title:       '✅ Your complaint has been resolved!',
          message:     `Your ${report.category} waste complaint has been cleaned up and verified. View the proof!`,
          reportId:    report._id,
          proofImage:  proofImage.url,
          newStatus:   'resolved',
        });
      }

      // Send resolution email
      const { sendResolutionEmail } = require('../services/emailService');
      if (report.userEmail) {
        sendResolutionEmail({
          to:       report.userEmail,
          name:     report.userName || 'Citizen',
          report:   updatedReport,
          proofUrl: proofImage.url,
        }).catch(err => console.error('[Email] Resolution email failed:', err.message));
      }
    }

    return res.status(200).json({
      status:  'success',
      message: locationVerified
        ? 'Proof submitted. Complaint auto-resolved! ✅'
        : `Proof submitted but location mismatch (${distanceMeters}m away). Admin will review.`,
      data: { locationVerified, distanceMeters, status: updatedReport.status },
    });
  } catch (error) {
    console.error('[Worker] submit-proof failed:', error.message);
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// GET /api/workers/my-tasks — worker sees their assigned tasks
router.get('/my-tasks', async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });
    const reports = await Report.find({ 'assignedWorker.workerId': user.userId })
      .sort({ createdAt: -1 });
    return res.status(200).json({ status: 'success', data: reports });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = router;

module.exports = router;