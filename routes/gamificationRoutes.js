const express = require('express');
const router = express.Router();
const { getLeaderboardHandler, getMyStats, syncMyPoints } = require('../controllers/gamificationController');

router.get('/leaderboard', getLeaderboardHandler);
router.get('/my-stats',    getMyStats);
router.post('/sync',       syncMyPoints);

module.exports = router;