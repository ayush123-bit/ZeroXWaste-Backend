const express = require('express');
const router = express.Router();
const { streamNotifications } = require('../controllers/notificationController');

router.get('/stream', streamNotifications);

module.exports = router;