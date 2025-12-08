const Report = require('../models/Report');
const { uploadToCloudinary, deleteFromCloudinary } = require('../config/cloudinary');

// @desc    Create new waste report
// @route   POST /api/reports
// @access  Public
const createReport = async (req, res) => {
  try {
    const { description, category, latitude, longitude, address } = req.body;

    // Validate required fields
    if (!description || !category || !latitude || !longitude) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide all required fields: description, category, latitude, longitude'
      });
    }

    // Validate that files were uploaded
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'Please upload at least one image'
      });
    }

    // Upload images to Cloudinary
    const uploadPromises = req.files.map(file => 
      uploadToCloudinary(file.buffer, file.originalname)
    );

    const uploadedImages = await Promise.all(uploadPromises);

    // Create report object
    const reportData = {
      description,
      category: category.toLowerCase(),
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)], // [lng, lat] for GeoJSON
        address: address || ''
      },
      images: uploadedImages
    };

    // Save to database
    const report = await Report.create(reportData);

    res.status(201).json({
      status: 'success',
      message: 'Report created successfully',
      data: report
    });

  } catch (error) {
    console.error('Error creating report:', error);
    res.status(500).json({
      status: 'error',
      message: error.message || 'Error creating report'
    });
  }
};

const getAllReports = async (req, res) => {
  try {
    const { 
      category, 
      status, 
      page = 1, 
      limit = 10,
      sortBy = 'createdAt',
      order = 'desc'
    } = req.query;

    // Build query
    const query = {};
    if (category) query.category = category.toLowerCase();
    if (status) query.status = status.toLowerCase();

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOrder = order === 'asc' ? 1 : -1;

    // Execute query
    const reports = await Report.find(query)
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const total = await Report.countDocuments(query);

    res.status(200).json({
      status: 'success',
      results: reports.length,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        totalReports: total,
        limit: parseInt(limit)
      },
      data: reports
    });

  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error fetching reports'
    });
  }
};

// @desc    Get single report by ID
// @route   GET /api/reports/:id
// @access  Public
const getReportById = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);

    if (!report) {
      return res.status(404).json({
        status: 'error',
        message: 'Report not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: report
    });

  } catch (error) {
    console.error('Error fetching report:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error fetching report'
    });
  }
};

// @desc    Get reports near a location
// @route   GET /api/reports/nearby
// @access  Public
const getNearbyReports = async (req, res) => {
  try {
    const { latitude, longitude, maxDistance = 5000 } = req.query; // maxDistance in meters (default 5km)

    if (!latitude || !longitude) {
      return res.status(400).json({
        status: 'error',
        message: 'Please provide latitude and longitude'
      });
    }

    const reports = await Report.find({
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: [parseFloat(longitude), parseFloat(latitude)]
          },
          $maxDistance: parseInt(maxDistance)
        }
      }
    }).limit(50);

    res.status(200).json({
      status: 'success',
      results: reports.length,
      data: reports
    });

  } catch (error) {
    console.error('Error fetching nearby reports:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error fetching nearby reports'
    });
  }
};

// @desc    Update report status
// @route   PATCH /api/reports/:id/status
// @access  Public (should be protected in production)
const updateReportStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = ['pending', 'in-progress', 'resolved', 'rejected'];

    if (!status || !validStatuses.includes(status)) {
      return res.status(400).json({
        status: 'error',
        message: `Status must be one of: ${validStatuses.join(', ')}`
      });
    }

    const report = await Report.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, runValidators: true }
    );

    if (!report) {
      return res.status(404).json({
        status: 'error',
        message: 'Report not found'
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Report status updated successfully',
      data: report
    });

  } catch (error) {
    console.error('Error updating report status:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error updating report status'
    });
  }
};

// @desc    Delete report
// @route   DELETE /api/reports/:id
// @access  Public (should be protected in production)
const deleteReport = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);

    if (!report) {
      return res.status(404).json({
        status: 'error',
        message: 'Report not found'
      });
    }

    // Delete images from Cloudinary
    const deletePromises = report.images.map(image => 
      deleteFromCloudinary(image.publicId)
    );
    await Promise.all(deletePromises);

    // Delete report from database
    await Report.findByIdAndDelete(req.params.id);

    res.status(200).json({
      status: 'success',
      message: 'Report deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting report:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error deleting report'
    });
  }
};

// @desc    Get report statistics
// @route   GET /api/reports/stats
// @access  Public
const getReportStats = async (req, res) => {
  try {
    const stats = await Report.aggregate([
      {
        $group: {
          _id: null,
          totalReports: { $sum: 1 },
          pendingReports: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          inProgressReports: {
            $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] }
          },
          resolvedReports: {
            $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] }
          }
        }
      }
    ]);

    const categoryStats = await Report.aggregate([
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      }
    ]);

    res.status(200).json({
      status: 'success',
      data: {
        overall: stats[0] || {
          totalReports: 0,
          pendingReports: 0,
          inProgressReports: 0,
          resolvedReports: 0
        },
        byCategory: categoryStats
      }
    });

  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error fetching statistics'
    });
  }
};

module.exports = {
  createReport,
  getAllReports,
  getReportById,
  getNearbyReports,
  updateReportStatus,
  deleteReport,
  getReportStats
};