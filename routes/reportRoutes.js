const express = require('express');
const router = express.Router();
const upload = require('../middlewares/upload');
const {
  createReport,
  getAllReports,
  getReportById,
  getNearbyReports,
  updateReportStatus,
  deleteReport,
  getReportStats
} = require('../controllers/reportController');

// Create a new report (with multiple image uploads)
router.post('/', upload.array('images', 10), createReport);

// Get all reports with filters and pagination
router.get('/', getAllReports);

// Get statistics
router.get('/stats', getReportStats);

// Get nearby reports
router.get('/nearby', getNearbyReports);

// Get single report by ID
router.get('/:id', getReportById);

// Update report status
router.patch('/:id/status', updateReportStatus);

// Delete report
router.delete('/:id', deleteReport);

module.exports = router;