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
    const user = await User.findById(req.currentUser.userId);
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });

    const query = {};
    if (user.role === 'category_head' && user.adminProfile?.category) {
      // Map category_head category to report categories
      const categoryMap = {
        waste_collection:   ['plastic', 'organic', 'other'],
        recycling:          ['paper', 'metal', 'glass', 'textiles'],
        hazardous:          ['batteries', 'chemical', 'medical', 'oil'],
        public_cleanliness: ['furniture', 'garden', 'construction', 'other'],
        campaigns:          [], // all
      };
      const cats = categoryMap[user.adminProfile.category];
      if (cats && cats.length > 0) query.category = { $in: cats };
    }

    const { status, priority, limit = 50 } = req.query;
    if (status) query.status = status;
    if (priority) query.priorityLevel = priority;

    const reports = await Report.find(query)
      .sort({ priorityScore: -1, createdAt: -1 })
      .limit(parseInt(limit));

    return res.status(200).json({ status: 'success', data: reports, total: reports.length });
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