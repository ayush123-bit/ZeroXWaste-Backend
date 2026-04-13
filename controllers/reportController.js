const Report = require('../models/Report');
const { uploadToCloudinary, deleteFromCloudinary } = require('../config/cloudinary');
const { calculatePriorityScore } = require('../services/priorityService');
const { classifyWaste } = require('../services/wasteClassifierService');
const { getRecommendations } = require('../services/recommendationService');
const { awardPoints } = require('../services/gamificationService');
const { broadcast } = require('../services/notificationService');
const { invalidatePattern, get, set } = require('../services/cacheService');
const { logger } = require('../middlewares/logger');
const jwt = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

const createReport = async (req, res) => {
  try {
    const { description, category, latitude, longitude, address } = req.body;
    if (!description || !category || !latitude || !longitude) {
      return res.status(400).json({ status: 'error', message: 'Required: description, category, latitude, longitude' });
    }
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ status: 'error', message: 'Upload at least one image' });
    }
    const uploadedImages = await Promise.all(req.files.map((f) => uploadToCloudinary(f.buffer, f.originalname)));
    const user = extractUser(req);
    const report = await Report.create({
      description, category: category.toLowerCase(),
      location: { type: 'Point', coordinates: [parseFloat(longitude), parseFloat(latitude)], address: address || '' },
      images: uploadedImages,
      reportedBy: user?.name || 'Anonymous',
      userId: user?.userId || null,
      userEmail: user?.email || null,
      userName: user?.name || null,
    });
    logger.info('Report created', { reportId: report._id, category, userId: user?.userId });
    invalidatePattern('stats:');

    setImmediate(async () => {
      try {
        const [priorityResult, classificationResult, recommendationResult] = await Promise.all([
          calculatePriorityScore({ imageUrl: uploadedImages[0]?.url, latitude: parseFloat(latitude), longitude: parseFloat(longitude), address: address || '', description, category}),
          classifyWaste(uploadedImages[0]?.url, category, description),
          getRecommendations({ category, priorityLevel: null, address: address || '', wasteType: null, latitude: parseFloat(latitude), longitude: parseFloat(longitude) }),
        ]);
      await Report.findByIdAndUpdate(report._id, {
  priorityScore: priorityResult.priorityScore,
  priorityLevel: priorityResult.priorityLevel,
  priorityBreakdown: priorityResult.breakdown,
  wasteClassification: classificationResult.data,
  recommendations: recommendationResult.data,
}, { runValidators: false }); // ← add this
        if (user?.userId) {
          await awardPoints(user.userId, 'SUBMIT_REPORT');
          if (priorityResult.priorityLevel === 'High') await awardPoints(user.userId, 'HIGH_PRIORITY_REPORT');
        }
        if (priorityResult.priorityLevel === 'High') {
          broadcast({ type: 'NEW_HIGH_PRIORITY', title: 'New High Priority Report', message: `${category} waste reported near ${address || 'unknown location'}`, reportId: report._id, score: priorityResult.priorityScore });
        }
        invalidatePattern('stats:');
       logger.info('Background processing complete', { reportId: report._id, priority: priorityResult.priorityLevel, score: priorityResult.priorityScore, breakdown: priorityResult.breakdown });
      } catch (err) {
        logger.error('Background processing failed', { reportId: report._id, error: err.message });
      }
    });
    return res.status(201).json({ status: 'success', message: 'Report submitted. AI analysis in progress.', data: report });
  } catch (error) {
    logger.error('createReport failed', { error: error.message });
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const getAllReports = async (req, res) => {
  try {
    const { category, status, priorityLevel, page = 1, limit = 10, sortBy = 'priorityScore', order = 'desc' } = req.query;
    const query = {};
    if (category) query.category = category.toLowerCase();
    if (status) query.status = status.toLowerCase();
    if (priorityLevel) query.priorityLevel = priorityLevel;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const reports = await Report.find(query).sort({ [sortBy]: order === 'asc' ? 1 : -1 }).skip(skip).limit(parseInt(limit));
    const total = await Report.countDocuments(query);
    return res.status(200).json({ status: 'success', results: reports.length, pagination: { currentPage: parseInt(page), totalPages: Math.ceil(total / parseInt(limit)), totalReports: total }, data: reports });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching reports' });
  }
};

const getMyReports = async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user?.userId) return res.status(401).json({ status: 'error', message: 'Not authenticated' });
    const reports = await Report.find({ userId: user.userId }).sort({ createdAt: -1 });
    return res.status(200).json({ status: 'success', results: reports.length, data: reports });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching your reports' });
  }
};

const getHeatmapData = async (req, res) => {
  try {
    const reports = await Report.find({ 'location.coordinates': { $exists: true } })
      .select('location priorityScore priorityLevel category status clusterSize').limit(500);
    const points = reports.map(r => ({
      lat: r.location.coordinates[1], lng: r.location.coordinates[0],
      weight: (r.priorityScore || 30) / 100, priorityLevel: r.priorityLevel,
      category: r.category, status: r.status, clusterSize: r.clusterSize || 1,
    }));
    return res.status(200).json({ status: 'success', data: points });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching heatmap data' });
  }
};

// ── FIXED: getReportStats — was broken due to require() inside function ──
const getReportStats = async (req, res) => {
  try {
    const CACHE_KEY = 'stats:main';
    const cached = get(CACHE_KEY);
    if (cached) return res.status(200).json({ status: 'success', data: cached, cached: true });

    const [overallArr, byCategory, byPriority, trend] = await Promise.all([
      Report.aggregate([{
        $group: {
          _id: null,
          totalReports:      { $sum: 1 },
          pendingReports:    { $sum: { $cond: [{ $eq: ['$status', 'pending'] },     1, 0] } },
          inProgressReports: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } },
          resolvedReports:   { $sum: { $cond: [{ $eq: ['$status', 'resolved'] },    1, 0] } },
          avgPriorityScore:  { $avg: '$priorityScore' },
        },
      }]),
      Report.aggregate([{ $group: { _id: '$category', count: { $sum: 1 } } }]),
      Report.aggregate([
        { $group: { _id: '$priorityLevel', count: { $sum: 1 }, avgScore: { $avg: '$priorityScore' } } },
        { $sort: { avgScore: -1 } },
      ]),
      Report.aggregate([
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: -1 } },
        { $limit: 14 },
      ]),
    ]);

    const overall = overallArr[0] || { totalReports: 0, pendingReports: 0, inProgressReports: 0, resolvedReports: 0, avgPriorityScore: 0 };
    const result = { overall, byCategory, byPriority, trend: trend.reverse() };

    set(CACHE_KEY, result, 60);
    return res.status(200).json({ status: 'success', data: result });
  } catch (error) {
    logger.error('getReportStats failed', { error: error.message });
    return res.status(500).json({ status: 'error', message: 'Error fetching stats' });
  }
};

const getNearbyReports = async (req, res) => {
  try {
    const { latitude, longitude, maxDistance = 5000 } = req.query;
    if (!latitude || !longitude) return res.status(400).json({ status: 'error', message: 'Provide latitude and longitude' });
    const reports = await Report.find({ location: { $near: { $geometry: { type: 'Point', coordinates: [parseFloat(longitude), parseFloat(latitude)] }, $maxDistance: parseInt(maxDistance) } } }).limit(50);
    return res.status(200).json({ status: 'success', results: reports.length, data: reports });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching nearby reports' });
  }
};

const getReportById = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });
    return res.status(200).json({ status: 'success', data: report });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching report' });
  }
};

const updateReportStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const valid = ['pending', 'in-progress', 'resolved', 'rejected'];
    if (!status || !valid.includes(status)) return res.status(400).json({ status: 'error', message: `Status must be one of: ${valid.join(', ')}` });
    const report = await Report.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });
    const { sendToUser } = require('../services/notificationService');
    if (report.userId) {
  console.log(`[Notification] Sending status update to userId: ${report.userId}`);
  sendToUser(report.userId, {
    type: 'STATUS_UPDATE',
    title: 'Your report was updated',
    message: `Report status changed to: ${status}`,
    reportId: report._id,
    newStatus: status,
  });
} else {
  console.log('[Notification] No userId on report — cannot notify');
}
    if (status === 'resolved' && report.userId) await awardPoints(report.userId, 'REPORT_RESOLVED');
    invalidatePattern('stats:');
    return res.status(200).json({ status: 'success', message: 'Status updated', data: report });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error updating status' });
  }
};

const assignWorker = async (req, res) => {
  try {
    const { workerId, workerName } = req.body;
    const report = await Report.findByIdAndUpdate(req.params.id, { assignedWorker: { workerId, workerName, assignedAt: new Date() }, status: 'in-progress' }, { new: true });
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });
    const { sendToUser } = require('../services/notificationService');
    sendToUser(workerId, { type: 'TASK_ASSIGNED', title: 'New task assigned', message: 'You have a new waste pickup task', reportId: report._id });
    if (report.userId) sendToUser(report.userId, { type: 'STATUS_UPDATE', title: 'Worker assigned', message: 'A worker has been assigned to your complaint', reportId: report._id });
    return res.status(200).json({ status: 'success', data: report });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error assigning worker' });
  }
};

const deleteReport = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });
    await Promise.all(report.images.map((img) => deleteFromCloudinary(img.publicId)));
    await Report.findByIdAndDelete(req.params.id);
    invalidatePattern('stats:');
    return res.status(200).json({ status: 'success', message: 'Deleted successfully' });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error deleting report' });
  }
};

module.exports = { createReport, getAllReports, getMyReports, getReportById, getNearbyReports, getHeatmapData, updateReportStatus, assignWorker, deleteReport, getReportStats };