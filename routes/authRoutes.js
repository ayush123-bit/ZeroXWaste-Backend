const express = require('express');
const router = express.Router();
const { googleLogin, checkAuth } = require('../controllers/authController');

router.post('/auth/google', googleLogin);
router.get('/auth/check', checkAuth);

router.post('/auth/logout', (req, res) => {
  res.clearCookie('ZeroXtoken', {
    httpOnly: true,
    secure: true,
    sameSite: 'None',
  });
  res.status(200).json({ message: 'Logged out successfully' });
});

module.exports = router;
