const express = require('express');
const router  = express.Router();
const User    = require('../models/User');
const Report  = require('../models/Report');
const jwt     = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

const requireRole = (...roles) => (req, res, next) => {
  const user = extractUser(req);
  if (!user) return res.status(401).json({ status: 'error', message: 'Not authenticated' });
  if (!roles.includes(user.role)) return res.status(403).json({ status: 'error', message: 'Insufficient permissions' });
  req.currentUser = user;
  next();
};

// ── GET /api/sub-admin/list — Super Admin: list all sub-admins
router.get('/list', requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const subAdmins = await User.find({
      role: { $in: ['category_head', 'area_head'] }
    }).select('name email role adminProfile picture createdAt').lean();
    return res.status(200).json({ status: 'success', data: subAdmins });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// ── POST /api/sub-admin/promote — Super Admin: promote user to sub-admin role
router.post('/promote', requireRole('admin', 'super_admin'), async (req, res) => {
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
});

// ── DELETE /api/sub-admin/demote/:userId — Super Admin: remove sub-admin role
router.delete('/demote/:userId', requireRole('admin', 'super_admin'), async (req, res) => {
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
});

// ── GET /api/sub-admin/reports — Category/Area head: view their filtered reports
router.get('/reports', requireRole('category_head', 'area_head', 'admin', 'super_admin'), async (req, res) => {
  try {
    const mongoose = require('mongoose');
    const userId = req.currentUser.userId;
    
    // Handle both string and ObjectId
    const user = await User.findOne({
      _id: mongoose.Types.ObjectId.isValid(userId) ? new mongoose.Types.ObjectId(userId) : userId
    });
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });

    const query = {};
    
    if (user.role === 'category_head' && user.adminProfile?.category) {
      const categoryMap = {
        waste_collection:   ['plastic', 'organic', 'other', 'construction'],
        recycling:          ['paper', 'metal', 'glass', 'textiles'],
        hazardous:          ['batteries', 'chemical', 'medical', 'oil', 'lightbulbs'],
        public_cleanliness: ['furniture', 'garden', 'other'],
        campaigns:          [], // all categories
      };
      const cats = categoryMap[user.adminProfile.category];
      if (cats && cats.length > 0) query.category = { $in: cats };
      // campaigns sees everything — no category filter
    }
    // area_head sees all categories in their area — we match by address
    // (location-based filtering would need geospatial — skip for now, show all)

    const { status, priority, limit = 100, sortBy = 'priorityScore', order = 'desc' } = req.query;
    if (status) query.status = status;
    if (priority) query.priorityLevel = priority;

    const reports = await Report.find(query)
      .sort({ [sortBy]: order === 'asc' ? 1 : -1, createdAt: -1 })
      .limit(parseInt(limit));

    // Build stats
    const total    = reports.length;
    const pending  = reports.filter(r => r.status === 'pending').length;
    const inProg   = reports.filter(r => r.status === 'in-progress').length;
    const resolved = reports.filter(r => r.status === 'resolved').length;

    return res.status(200).json({
      status: 'success',
      data: reports,
      total,
      stats: { total, pending, inProgress: inProg, resolved,
               resolutionRate: total > 0 ? Math.round((resolved/total)*100) : 0 }
    });
  } catch (error) {
    console.error('[SubAdmin] reports error:', error.message);
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// ── PATCH /api/sub-admin/reports/:id/status — sub-admin updates status of their report
router.patch('/reports/:id/status', requireRole('category_head', 'area_head', 'admin', 'super_admin'), async (req, res) => {
  try {
    const { status } = req.body;
    const valid = ['pending', 'in-progress', 'resolved', 'rejected'];
    if (!valid.includes(status)) return res.status(400).json({ status: 'error', message: 'Invalid status' });

    const report = await Report.findByIdAndUpdate(
      req.params.id, { status }, { new: true, runValidators: false }
    );
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    // Notify reporter
    const { sendToUser } = require('../services/notificationService');
    if (report.userId) {
      sendToUser(report.userId, {
        type: 'STATUS_UPDATE',
        title: 'Your report was updated',
        message: `Report status changed to: ${status}`,
        reportId: report._id, newStatus: status,
      });
    }

    // Award points if resolved
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
});

// ── GET /api/sub-admin/me — sub-admin gets their own profile and scope info
router.get('/me', requireRole('category_head', 'area_head', 'admin', 'super_admin'), async (req, res) => {
  try {
    const mongoose = require('mongoose');
    const userId = req.currentUser.userId;
    const user = await User.findOne({
      _id: mongoose.Types.ObjectId.isValid(userId) ? new mongoose.Types.ObjectId(userId) : userId
    }).select('name email role adminProfile picture');
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
    return res.status(200).json({ status: 'success', data: user });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

// ── GET /api/sub-admin/users — Super Admin: list all users for promotion
router.get('/users', requireRole('admin', 'super_admin'), async (req, res) => {
  try {
    const users = await User.find({ role: 'user' })
      .select('name email picture createdAt')
      .sort({ createdAt: -1 })
      .limit(100);
    return res.status(200).json({ status: 'success', data: users });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = router;