const User     = require('../models/User');
const Report   = require('../models/Report');
const { sendToUser } = require('../services/notificationService');
const jwt      = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

const listWorkers = async (req, res) => {
  try {
    const workers = await User.find({ role: 'worker' })
      .select('name email picture workerProfile points')
      .lean();
    return res.status(200).json({ status: 'success', data: workers });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const promoteToWorker = async (req, res) => {
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
};

const assignWorkerToReport = async (req, res) => {
  try {
    const { workerId } = req.body;
    if (!workerId) return res.status(400).json({ status: 'error', message: 'workerId required' });

    const worker = await User.findById(workerId);
    if (!worker || worker.role !== 'worker') {
      return res.status(400).json({ status: 'error', message: 'User is not a worker' });
    }

    const report = await Report.findByIdAndUpdate(
      req.params.reportId,
      {
        assignedWorker: { workerId, workerName: worker.name, assignedAt: new Date() },
        status: 'in-progress',
      },
      { new: true, runValidators: false }
    );
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    await User.findByIdAndUpdate(workerId, {
      $addToSet: { 'workerProfile.assignedTasks': report._id },
      'workerProfile.isAvailable': false,
    });

    sendToUser(workerId, {
      type:    'TASK_ASSIGNED',
      title:   'New task assigned to you',
      message: `You have been assigned a ${report.category} waste report`,
      reportId: report._id,
    });

    if (report.userId) {
      sendToUser(report.userId, {
        type:    'STATUS_UPDATE',
        title:   'Worker assigned to your report',
        message: `${worker.name} has been assigned to handle your complaint`,
        reportId: report._id,
      });
    }

    return res.status(200).json({
      status: 'success',
      data: { report, worker: { _id: worker._id, name: worker.name, area: worker.workerProfile?.area } },
    });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const completeTask = async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const report = await Report.findByIdAndUpdate(
      req.params.reportId,
      { status: 'resolved' },
      { new: true, runValidators: false }
    );
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    await User.findByIdAndUpdate(user.userId, {
      $pull: { 'workerProfile.assignedTasks': report._id },
      $inc:  { 'workerProfile.completedTasks': 1 },
      'workerProfile.isAvailable': true,
    });

    if (report.userId) {
      sendToUser(report.userId, {
        type:      'STATUS_UPDATE',
        title:     'Your complaint has been resolved ✅',
        message:   'The assigned worker has marked your report as resolved',
        reportId:  report._id,
        newStatus: 'resolved',
      });
    }

    return res.status(200).json({ status: 'success', data: report });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const submitProofViaWorkerRoute = async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const { workerLat, workerLng } = req.body;
    const report = await Report.findById(req.params.reportId);
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    const { uploadToCloudinary } = require('../config/cloudinary');
    const proofImage = await uploadToCloudinary(req.file.buffer, req.file.originalname);

    const reportLat = report.location.coordinates[1];
    const reportLng = report.location.coordinates[0];
    const wLat = parseFloat(workerLat);
    const wLng = parseFloat(workerLng);

    const R    = 6371000;
    const dLat = (wLat - reportLat) * Math.PI / 180;
    const dLng = (wLng - reportLng) * Math.PI / 180;
    const a    = Math.sin(dLat/2)**2 + Math.cos(reportLat * Math.PI/180) * Math.cos(wLat * Math.PI/180) * Math.sin(dLng/2)**2;
    const distanceMeters  = Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)));
    const locationVerified = distanceMeters <= 500;

    const updateData = {
      'completionProof.imageUrl':         proofImage.url,
      'completionProof.publicId':         proofImage.publicId,
      'completionProof.uploadedAt':       new Date(),
      'completionProof.workerLat':        wLat,
      'completionProof.workerLng':        wLng,
      'completionProof.locationVerified': locationVerified,
      'completionProof.distanceMeters':   distanceMeters,
    };

    if (locationVerified) {
      updateData.status             = 'resolved';
      updateData.progressPercentage = 100;
      updateData.currentStage       = 'Resolved';
    }

    const updatedReport = await Report.findByIdAndUpdate(
      req.params.reportId, updateData, { new: true, runValidators: false }
    );

    if (locationVerified) {
      await User.findByIdAndUpdate(user.userId, {
        $pull: { 'workerProfile.assignedTasks': report._id },
        $inc:  { 'workerProfile.completedTasks': 1 },
        'workerProfile.isAvailable': true,
      });

      const { awardPoints } = require('../services/gamificationService');
      if (report.userId) await awardPoints(report.userId, 'REPORT_RESOLVED');

      if (report.userId) {
        sendToUser(report.userId, {
          type:       'COMPLAINT_RESOLVED',
          title:      '✅ Your complaint has been resolved!',
          message:    `Your ${report.category} waste complaint has been cleaned up and verified. View the proof!`,
          reportId:   report._id,
          proofImage: proofImage.url,
          newStatus:  'resolved',
        });
      }

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
};

const getMyTasks = async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });
    const reports = await Report.find({ 'assignedWorker.workerId': user.userId })
      .sort({ createdAt: -1 });
    return res.status(200).json({ status: 'success', data: reports });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

module.exports = {
  listWorkers,
  promoteToWorker,
  assignWorkerToReport,
  completeTask,
  submitProofViaWorkerRoute,
  getMyTasks,
};