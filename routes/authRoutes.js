const express = require('express');
const router = express.Router();
const { googleLogin, checkAuth, logout } = require('../controllers/authController');

router.post('/auth/google',  googleLogin);
router.get('/auth/check',    checkAuth);
router.post('/auth/logout',  logout);

module.exports = router;