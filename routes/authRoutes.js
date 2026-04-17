const express = require('express');
const router = express.Router();
const { googleLogin, checkAuth, logout, devLogin } = require('../controllers/authController');

router.post('/auth/google',  googleLogin);
router.get('/auth/check',    checkAuth);
router.post('/auth/logout',  logout);
router.post('/auth/dev-login', devLogin);

module.exports = router;