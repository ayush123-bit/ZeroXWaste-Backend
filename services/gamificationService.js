const User = require('../models/User');
const Report = require('../models/Report');

const POINTS = {
  SUBMIT_REPORT: 10,
  REPORT_RESOLVED: 25,
  HIGH_PRIORITY_REPORT: 15,  // bonus for finding a real issue
  FIRST_REPORT: 20,           // welcome bonus
  FIVE_REPORTS: 30,           // milestone bonus
};

const BADGES = [
  { id: 'first_report',    label: 'First Reporter',   description: 'Submitted your first complaint',  minReports: 1,  minPoints: 0   },
  { id: 'eco_warrior',     label: 'Eco Warrior',      description: 'Submitted 5 complaints',          minReports: 5,  minPoints: 0   },
  { id: 'green_champion',  label: 'Green Champion',   description: 'Submitted 10 complaints',         minReports: 10, minPoints: 0   },
  { id: 'point_collector', label: 'Point Collector',  description: 'Earned 100 points',               minReports: 0,  minPoints: 100 },
  { id: 'super_reporter',  label: 'Super Reporter',   description: 'Earned 250+ points',              minReports: 0,  minPoints: 250 },
];

/**
 * Award points to a user for an action.
 */
const awardPoints = async (userId, action, metadata = {}) => {
  try {
    if (!userId) return null;

    const points = POINTS[action] || 0;
    if (points === 0) return null;

    const user = await User.findById(userId);
    if (!user) return null;

    const currentPoints = user.points || 0;
    const currentReports = user.totalReports || 0;
    const newPoints = currentPoints + points;
    const newReports = action === 'SUBMIT_REPORT' ? currentReports + 1 : currentReports;

    // Compute earned badges
    const newBadges = BADGES
      .filter(b => newPoints >= b.minPoints && newReports >= b.minReports)
      .map(b => b.id);

    await User.findByIdAndUpdate(userId, {
      points: newPoints,
      totalReports: newReports,
      badges: newBadges,
      lastActivity: new Date(),
    });

    return { points, newTotal: newPoints, badges: newBadges };
  } catch (error) {
    console.error('[Gamification] awardPoints failed:', error.message);
    return null;
  }
};

/**
 * Get top 10 users by points for leaderboard.
 */
const getLeaderboard = async () => {
  try {
    const leaders = await User.find({ points: { $gt: 0 } })
      .sort({ points: -1 })
      .limit(10)
      .select('name picture points badges totalReports');

    return leaders.map((u, idx) => ({
      rank: idx + 1,
      name: u.name || 'Anonymous',
      picture: u.picture || null,
      points: u.points || 0,
      badges: u.badges || [],
      totalReports: u.totalReports || 0,
    }));
  } catch (error) {
    console.error('[Gamification] getLeaderboard failed:', error.message);
    return [];
  }
};

module.exports = { awardPoints, getLeaderboard, BADGES, POINTS };