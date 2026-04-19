const User     = require('../models/User');
const Report   = require('../models/Report');
const { sendToUser } = require('../services/notificationService');
const { validateWasteImage } = require('../services/imageValidationService');
const jwt      = require('jsonwebtoken');

const extractWorker = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded.role === 'worker' ? decoded : null;
  } catch { return null; }
};

const getWorkerDashboard = async (req, res) => {
  try {
    const worker = extractWorker(req);
    if (!worker) return res.status(401).json({ status: 'error', message: 'Worker authentication required' });

    const [assigned, completed, pending] = await Promise.all([
      Report.countDocuments({ 'assignedWorker.workerId': worker.userId }),
      Report.countDocuments({ 'assignedWorker.workerId': worker.userId, status: 'resolved' }),
      Report.countDocuments({ 'assignedWorker.workerId': worker.userId, status: 'in-progress' }),
    ]);

    const recentTasks = await Report.find({ 'assignedWorker.workerId': worker.userId })
      .sort({ 'assignedWorker.assignedAt': -1 })
      .limit(5)
      .select('description category status location priorityLevel priorityScore assignedWorker completionProof createdAt');

    const workerUser = await User.findById(worker.userId)
      .select('name email workerProfile picture');

    return res.status(200).json({
      status: 'success',
      data: {
        stats: {
          assigned,
          completed,
          pending,
          completionRate: assigned > 0 ? Math.round((completed / assigned) * 100) : 0,
        },
        recentTasks,
        profile: workerUser,
      },
    });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const getWorkerTasks = async (req, res) => {
  try {
    const worker = extractWorker(req);
    if (!worker) return res.status(401).json({ status: 'error', message: 'Worker authentication required' });

    const { status } = req.query;
    const query = { 'assignedWorker.workerId': worker.userId };
    if (status) query.status = status;

    const tasks = await Report.find(query)
      .sort({ 'assignedWorker.assignedAt': -1 });

    return res.status(200).json({ status: 'success', data: tasks });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const submitProof = async (req, res) => {
  try {
    const worker = extractWorker(req);
    if (!worker) return res.status(401).json({ status: 'error', message: 'Worker authentication required' });
    if (!req.file) return res.status(400).json({ status: 'error', message: 'Proof image is required' });

    const { workerLat, workerLng } = req.body;
    if (!workerLat || !workerLng) {
      return res.status(400).json({ status: 'error', message: 'Worker GPS coordinates are required' });
    }

    const report = await Report.findById(req.params.reportId);
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });
    if (report.assignedWorker?.workerId !== worker.userId) {
      return res.status(403).json({ status: 'error', message: 'This task is not assigned to you' });
    }

    const { uploadToCloudinary } = require('../config/cloudinary');
    const proofImage = await uploadToCloudinary(req.file.buffer, `proof_${req.params.reportId}`);

    try {
      const proofValidation = await validateWasteImage(proofImage.url, 'proof');
      if (!proofValidation.valid && proofValidation.confidence > 75) {
        const { deleteFromCloudinary } = require('../config/cloudinary');
        await deleteFromCloudinary(proofImage.publicId).catch(() => {});
        return res.status(400).json({
          status:  'error',
          message: `Proof image does not appear to show a cleaned area. Please upload a clear photo of the cleaned location. (${proofValidation.reason})`,
        });
      }
    } catch (validErr) {
      console.error('[ProofValidation] Skipped:', validErr.message);
    }

    const reportLat = report.location.coordinates[1];
    const reportLng = report.location.coordinates[0];
    const wLat = parseFloat(workerLat);
    const wLng = parseFloat(workerLng);
    const R    = 6371000;
    const dLat = (wLat - reportLat) * Math.PI / 180;
    const dLon = (wLng - reportLng) * Math.PI / 180;
    const a    = Math.sin(dLat/2)**2 + Math.cos(reportLat * Math.PI/180) * Math.cos(wLat * Math.PI/180) * Math.sin(dLon/2)**2;
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
      updateData.resolutionNotified = false;
    }

    const updated = await Report.findByIdAndUpdate(
      req.params.reportId, updateData, { new: true, runValidators: false }
    );

    if (locationVerified) {
      await User.findByIdAndUpdate(worker.userId, {
        $pull: { 'workerProfile.assignedTasks': report._id },
        $inc:  { 'workerProfile.completedTasks': 1 },
        'workerProfile.isAvailable': true,
      });

      if (report.userId) {
        const { awardPoints } = require('../services/gamificationService');
        await awardPoints(report.userId, 'REPORT_RESOLVED');
      }

      if (report.userId) {
        sendToUser(report.userId, {
          type:       'COMPLAINT_RESOLVED',
          title:      '✅ Your complaint has been resolved!',
          message:    `Your ${report.category} waste complaint at ${report.location?.address || 'reported location'} has been cleaned and verified.`,
          reportId:   report._id,
          proofImage: proofImage.url,
          newStatus:  'resolved',
        });
      }

      if (report.userEmail) {
        const { sendResolutionEmail } = require('../services/emailService');
        sendResolutionEmail({
          to:       report.userEmail,
          name:     report.userName || 'Citizen',
          report:   updated,
          proofUrl: proofImage.url,
        }).catch(e => console.error('[Email] Resolution failed:', e.message));
      }
    }

    return res.status(200).json({
      status:  'success',
      message: locationVerified
        ? '✅ Proof verified! Complaint marked as resolved. Reporter has been notified.'
        : `⚠️ Proof uploaded but location mismatch detected (${distanceMeters}m from complaint). Admin will review.`,
      data: { locationVerified, distanceMeters, proofUrl: proofImage.url, newStatus: updated.status },
    });
  } catch (error) {
    console.error('[WorkerPortal] submit-proof error:', error.message);
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

module.exports = { getWorkerDashboard, getWorkerTasks, submitProof };