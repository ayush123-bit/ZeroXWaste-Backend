const express = require('express');
const router = express.Router();
const upload = require('../middlewares/upload');
const { reportSubmitLimiter, apiLimiter } = require('../middlewares/rateLimiter');
const {
  createReport, getAllReports, getMyReports, getReportById,
  getNearbyReports, getHeatmapData, updateReportStatus,
  assignWorker, deleteReport, getReportStats,
} = require('../controllers/reportController');

router.post('/',              reportSubmitLimiter, upload.array('images', 10), createReport);
router.get('/',               apiLimiter, getAllReports);
router.get('/stats',          apiLimiter, getReportStats);
router.get('/heatmap',        apiLimiter, getHeatmapData);
router.get('/nearby',         apiLimiter, getNearbyReports);
router.get('/my',             getMyReports);
router.get('/:id',            getReportById);
router.patch('/:id/status',   updateReportStatus);
router.patch('/:id/assign',   assignWorker);
router.delete('/:id',         deleteReport);

module.exports = router;