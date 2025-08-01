const express = require('express');
const router = express.Router();
const { googleLogin, checkAuth } = require('../controllers/authController');

router.post('/auth/google', googleLogin);
router.get('/auth/check', checkAuth);

module.exports = router;
