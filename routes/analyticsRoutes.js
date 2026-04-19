const express = require('express');
const router  = express.Router();
const {
  getWorkerStats,
  getAreaStats,
  sendMessageToAreaHead,
} = require('../controllers/analyticsController');

router.get('/workers',              getWorkerStats);
router.get('/areas',                getAreaStats);
router.post('/message/:areaHeadId', sendMessageToAreaHead);

module.exports = router;