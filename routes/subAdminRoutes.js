const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const {
  listSubAdmins,
  promoteToSubAdmin,
  demoteSubAdmin,
  getSubAdminReports,
  updateSubAdminReportStatus,
  getSubAdminProfile,
  listUsersForPromotion,
} = require('../controllers/subAdminController');

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

router.get('/list',                requireRole('admin', 'super_admin'),                                listSubAdmins);
router.post('/promote',            requireRole('admin', 'super_admin'),                                promoteToSubAdmin);
router.delete('/demote/:userId',   requireRole('admin', 'super_admin'),                                demoteSubAdmin);
router.get('/reports',             requireRole('category_head', 'area_head', 'admin', 'super_admin'),  getSubAdminReports);
router.patch('/reports/:id/status',requireRole('category_head', 'area_head', 'admin', 'super_admin'),  updateSubAdminReportStatus);
router.get('/me',                  requireRole('category_head', 'area_head', 'admin', 'super_admin'),  getSubAdminProfile);
router.get('/users',               requireRole('admin', 'super_admin'),                                listUsersForPromotion);

module.exports = router;