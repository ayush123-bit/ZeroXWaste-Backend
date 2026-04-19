const mongoose = require('mongoose');
const User     = require('../models/User');
const Report   = require('../models/Report');

const listSubAdmins = async (req, res) => {
  try {
    const subAdmins = await User.find({
      role: { $in: ['category_head', 'area_head'] },
    }).select('name email role adminProfile picture createdAt').lean();
    return res.status(200).json({ status: 'success', data: subAdmins });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const promoteToSubAdmin = async (req, res) => {
  try {
    const { userId, role, category, area, permissions } = req.body;
    const validRoles = ['category_head', 'area_head'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ status: 'error', message: `Role must be one of: ${validRoles.join(', ')}` });
    }

    const defaultPermissions = {
      canAssignWorkers:   true,
      canChangeStatus:    true,
      canCreateCampaigns: role === 'category_head',
      canViewReports:     true,
      canDeleteReports:   false,
      ...permissions,
    };

    const user = await User.findByIdAndUpdate(
      userId,
      {
        role,
        adminProfile: {
          category: role === 'category_head' ? category : null,
          area:     role === 'area_head'     ? area     : null,
          permissions: defaultPermissions,
        },
      },
      { new: true }
    );
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
    return res.status(200).json({ status: 'success', data: user });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const demoteSubAdmin = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { role: 'user', adminProfile: null },
      { new: true }
    );
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
    return res.status(200).json({ status: 'success', message: 'User demoted to regular user' });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const getSubAdminReports = async (req, res) => {
  try {
    const userId = req.currentUser.userId;

    const user = await User.findOne({
      _id: mongoose.Types.ObjectId.isValid(userId)
        ? new mongoose.Types.ObjectId(userId)
        : userId,
    });
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });

    const query = {};

    if (user.role === 'category_head' && user.adminProfile?.category) {
      const categoryMap = {
        waste_collection:   ['plastic', 'organic', 'other', 'construction'],
        recycling:          ['paper', 'metal', 'glass', 'textiles'],
        hazardous:          ['batteries', 'chemical', 'medical', 'oil', 'lightbulbs'],
        public_cleanliness: ['furniture', 'garden', 'other'],
        campaigns:          [],
      };
      const cats = categoryMap[user.adminProfile.category];
      if (cats && cats.length > 0) query.category = { $in: cats };
    }

    const { status, priority, limit = 100, sortBy = 'priorityScore', order = 'desc' } = req.query;
    if (status)   query.status        = status;
    if (priority) query.priorityLevel = priority;

    const reports = await Report.find(query)
      .sort({ [sortBy]: order === 'asc' ? 1 : -1, createdAt: -1 })
      .limit(parseInt(limit));

    const total    = reports.length;
    const pending  = reports.filter(r => r.status === 'pending').length;
    const inProg   = reports.filter(r => r.status === 'in-progress').length;
    const resolved = reports.filter(r => r.status === 'resolved').length;

    return res.status(200).json({
      status: 'success',
      data:   reports,
      total,
      stats: {
        total, pending, inProgress: inProg, resolved,
        resolutionRate: total > 0 ? Math.round((resolved / total) * 100) : 0,
      },
    });
  } catch (error) {
    console.error('[SubAdmin] reports error:', error.message);
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const updateSubAdminReportStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const valid = ['pending', 'in-progress', 'resolved', 'rejected'];
    if (!valid.includes(status)) {
      return res.status(400).json({ status: 'error', message: 'Invalid status' });
    }

    const report = await Report.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true, runValidators: false }
    );
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    const { sendToUser } = require('../services/notificationService');
    if (report.userId) {
      sendToUser(report.userId, {
        type:      'STATUS_UPDATE',
        title:     'Your report was updated',
        message:   `Report status changed to: ${status}`,
        reportId:  report._id,
        newStatus: status,
      });
    }

    if (status === 'resolved' && report.userId) {
      const { awardPoints } = require('../services/gamificationService');
      await awardPoints(report.userId, 'REPORT_RESOLVED');
    }

    const { invalidatePattern } = require('../services/cacheService');
    invalidatePattern('stats:');

    return res.status(200).json({ status: 'success', data: report });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const getSubAdminProfile = async (req, res) => {
  try {
    const userId = req.currentUser.userId;

    const user = await User.findOne({
      _id: mongoose.Types.ObjectId.isValid(userId)
        ? new mongoose.Types.ObjectId(userId)
        : userId,
    }).select('name email role adminProfile picture');

    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
    return res.status(200).json({ status: 'success', data: user });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

const listUsersForPromotion = async (req, res) => {
  try {
    const users = await User.find({ role: 'user' })
      .select('name email picture createdAt')
      .sort({ createdAt: -1 })
      .limit(100);
    return res.status(200).json({ status: 'success', data: users });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

module.exports = {
  listSubAdmins,
  promoteToSubAdmin,
  demoteSubAdmin,
  getSubAdminReports,
  updateSubAdminReportStatus,
  getSubAdminProfile,
  listUsersForPromotion,
};