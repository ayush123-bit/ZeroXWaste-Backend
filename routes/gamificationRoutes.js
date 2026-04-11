const express = require('express');
const router = express.Router();
const { getLeaderboardHandler, getMyStats } = require('../controllers/gamificationController');

router.get('/leaderboard', getLeaderboardHandler);
router.get('/my-stats',    getMyStats);

module.exports = router;