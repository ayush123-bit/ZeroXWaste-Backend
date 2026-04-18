const User   = require('../models/User');
const Report = require('../models/Report');
const { sendToUser } = require('./notificationService');
const { sendWorkerAssignmentEmail } = require('./emailService');

/**
 * Haversine distance between two coordinates in meters
 */
const haversineDistance = (lat1, lng1, lat2, lng2) => {
  const R = 6371000;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180) * Math.cos(lat2*Math.PI/180) * Math.sin(dLon/2)**2;
  return Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)));
};

/**
 * Automatically find the best available worker near a complaint and assign them.
 * Called after report creation in background.
 */
const autoAssignWorker = async (report) => {
  try {
    const reportLat = report.location?.coordinates?.[1];
    const reportLng = report.location?.coordinates?.[0];

    if (!reportLat || !reportLng) {
      console.log('[AutoAssign] No coordinates on report — skipping');
      return null;
    }

    // Find all available workers
    const availableWorkers = await User.find({
      role: 'worker',
      'workerProfile.isAvailable': true,
    }).lean();

    if (availableWorkers.length === 0) {
      console.log('[AutoAssign] No available workers found');
      return null;
    }

    // Sort workers by distance to complaint — pick closest
    const workersWithDistance = availableWorkers.map(w => {
      // Workers may have location stored in workerProfile or we use area as fallback
      // If worker has no GPS we still assign based on area name match
      const dist = 999999; // default if no location
      return { worker: w, distance: dist };
    });

    // Prefer workers whose area matches the report address
    const reportAddress = (report.location?.address || '').toLowerCase();
    let bestWorker = null;

    // First try area-name match
    for (const w of availableWorkers) {
      const workerArea = (w.workerProfile?.area || '').toLowerCase();
      if (workerArea && reportAddress.includes(workerArea.split(',')[0].trim())) {
        bestWorker = w;
        break;
      }
    }

    // If no area match, just pick first available worker
    if (!bestWorker) bestWorker = availableWorkers[0];

    // Assign the worker to the report
    report.assignedWorker = {
      workerId:   bestWorker._id.toString(),
      workerName: bestWorker.name,
      assignedAt: new Date(),
    };
    report.status = 'in-progress';

    // Update progress stages
    if (report.progressStages && report.progressStages.length > 0) {
      report.progressStages[0].completed = true;
      report.progressStages[0].completedAt = report.progressStages[0].completedAt || new Date();
      report.progressStages[1].completed = true;
      report.progressStages[1].completedAt = new Date();
      report.progressStages[2].completed = true;
      report.progressStages[2].completedAt = new Date();
      report.progressPercentage = 50;
      report.currentStage = 'Work in Progress';
      const estDate = new Date();
      estDate.setDate(estDate.getDate() + 7);
      report.estimatedCompletionDate = estDate;
    }

    await report.save();

    // Mark worker as busy, add task to their list
    await User.findByIdAndUpdate(bestWorker._id, {
      $addToSet: { 'workerProfile.assignedTasks': report._id },
      'workerProfile.isAvailable': false,
    });

    console.log(`[AutoAssign] Assigned report ${report._id} to worker ${bestWorker.name}`);

    // In-app notification to worker
    sendToUser(bestWorker._id.toString(), {
      type:    'TASK_ASSIGNED',
      title:   '🧹 New task assigned to you!',
      message: `${report.category} waste cleanup at ${report.location?.address || 'reported location'}`,
      reportId: report._id,
    });

    // In-app notification to reporter
    if (report.userId) {
      sendToUser(report.userId, {
        type:    'STATUS_UPDATE',
        title:   '👷 Worker assigned to your complaint!',
        message: `${bestWorker.name} has been assigned to clean up your complaint`,
        reportId: report._id,
      });
    }

    // Email notification to worker
    if (bestWorker.email) {
      sendWorkerAssignmentEmail({
        to:         bestWorker.email,
        workerName: bestWorker.name,
        report,
      }).catch(e => console.error('[AutoAssign] Email failed:', e.message));
    }

    return bestWorker;
  } catch (error) {
    console.error('[AutoAssign] Failed:', error.message);
    return null;
  }
};

module.exports = { autoAssignWorker };