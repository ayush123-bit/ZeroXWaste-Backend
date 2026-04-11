const { getLeaderboard, BADGES } = require('../services/gamificationService');
const { get, set } = require('../services/cacheService');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

// GET /api/gamification/leaderboard
const getLeaderboardHandler = async (req, res) => {
  try {
    const CACHE_KEY = 'leaderboard:top10';
    const cached = get(CACHE_KEY);
    if (cached) return res.status(200).json({ status: 'success', data: cached, cached: true });

    const data = await getLeaderboard();
    set(CACHE_KEY, data, 120); // cache 2 minutes
    return res.status(200).json({ status: 'success', data });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching leaderboard' });
  }
};

// GET /api/gamification/my-stats
const getMyStats = async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user?.userId) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const dbUser = await User.findById(user.userId).select('name picture points badges totalReports');
    if (!dbUser) return res.status(404).json({ status: 'error', message: 'User not found' });

    // Get user's rank
    const rank = await User.countDocuments({ points: { $gt: dbUser.points || 0 } }) + 1;

    const badgeDetails = BADGES.filter(b => (dbUser.badges || []).includes(b.id));
    const nextBadge = BADGES.find(b => !(dbUser.badges || []).includes(b.id));

    return res.status(200).json({
      status: 'success',
      data: {
        name: dbUser.name,
        picture: dbUser.picture,
        points: dbUser.points || 0,
        totalReports: dbUser.totalReports || 0,
        rank,
        badges: badgeDetails,
        nextBadge: nextBadge || null,
      },
    });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching stats' });
  }
};

module.exports = { getLeaderboardHandler, getMyStats };