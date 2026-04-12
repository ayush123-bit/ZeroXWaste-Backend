const { getLeaderboard, BADGES, awardPoints } = require('../services/gamificationService');
const { get, set } = require('../services/cacheService');
const User = require('../models/User');
const Report = require('../models/Report');
const jwt = require('jsonwebtoken');

const extractUser = (req) => {
  try {
    const token = req.cookies?.ZeroXtoken;
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch { return null; }
};

const getLeaderboardHandler = async (req, res) => {
  try {
    const CACHE_KEY = 'leaderboard:top10';
    const cached = get(CACHE_KEY);
    if (cached) return res.status(200).json({ status: 'success', data: cached, cached: true });
    const data = await getLeaderboard();
    set(CACHE_KEY, data, 60);
    return res.status(200).json({ status: 'success', data });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching leaderboard' });
  }
};

const getMyStats = async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user?.userId) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const dbUser = await User.findById(user.userId).select('name picture points badges totalReports');
    if (!dbUser) {
      return res.status(200).json({
        status: 'success',
        data: { name: user.name, picture: null, points: 0, totalReports: 0, rank: 1, badges: [], nextBadge: BADGES[0] },
      });
    }

    const rank = await User.countDocuments({ points: { $gt: dbUser.points || 0 } }) + 1;
    const earnedIds = dbUser.badges || [];
    const badgeDetails = BADGES.filter(b => earnedIds.includes(b.id));
    const nextBadge = BADGES.find(b => !earnedIds.includes(b.id)) || null;

    return res.status(200).json({
      status: 'success',
      data: { name: dbUser.name, picture: dbUser.picture, points: dbUser.points || 0, totalReports: dbUser.totalReports || 0, rank, badges: badgeDetails, nextBadge },
    });
  } catch (error) {
    return res.status(500).json({ status: 'error', message: 'Error fetching stats' });
  }
};

/**
 * POST /api/gamification/sync
 * Retroactively award points for all reports the user submitted before gamification was set up.
 * Safe to call multiple times — checks if points were already synced.
 */
const syncMyPoints = async (req, res) => {
  try {
    const user = extractUser(req);
    if (!user?.userId) return res.status(401).json({ status: 'error', message: 'Not authenticated' });

    const dbUser = await User.findById(user.userId);
    if (!dbUser) return res.status(404).json({ status: 'error', message: 'User not found' });

    // Find all reports submitted by this user
    const reports = await Report.find({ userId: user.userId });
    const reportCount = reports.length;

    if (reportCount === 0) {
      return res.status(200).json({ status: 'success', data: { reportCount: 0, pointsAdded: 0, message: 'No reports found to sync' } });
    }

    // Calculate what points they SHOULD have based on their reports
    const POINTS_PER_REPORT = 10;
    const POINTS_PER_HIGH   = 15;
    const FIRST_REPORT_BONUS = 20;

    let expectedPoints = reportCount * POINTS_PER_REPORT;
    if (reportCount >= 1) expectedPoints += FIRST_REPORT_BONUS;

    // Add high priority bonuses
    const highPriorityReports = reports.filter(r => r.priorityLevel === 'High');
    expectedPoints += highPriorityReports.length * POINTS_PER_HIGH;

    // Add resolved bonuses
    const resolvedReports = reports.filter(r => r.status === 'resolved');
    expectedPoints += resolvedReports.length * 25;

    const currentPoints = dbUser.points || 0;
    const pointsAdded = Math.max(0, expectedPoints - currentPoints);

    // Compute correct badges
    const newBadges = BADGES
      .filter(b => expectedPoints >= b.minPoints && reportCount >= b.minReports)
      .map(b => b.id);

    await User.findByIdAndUpdate(user.userId, {
      points:       expectedPoints,
      totalReports: reportCount,
      badges:       newBadges,
      lastActivity: new Date(),
    });

    // Invalidate leaderboard cache
    const { invalidate } = require('../services/cacheService');
    invalidate('leaderboard:top10');

    return res.status(200).json({
      status: 'success',
      data: { reportCount, pointsAdded, newTotal: expectedPoints, badges: newBadges, message: 'Points synced successfully' },
    });
  } catch (error) {
    console.error('[SyncPoints]', error.message);
    return res.status(500).json({ status: 'error', message: 'Sync failed' });
  }
};

module.exports = { getLeaderboardHandler, getMyStats, syncMyPoints };