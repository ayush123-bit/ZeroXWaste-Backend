const Report = require('../models/Report');

/**
 * Escalation rules:
 * - High priority unresolved > 24 hrs → escalate score by +10 (cap 100)
 * - Medium priority unresolved > 72 hrs → bump to High
 * - Multiple complaints in 500m radius → increase all their scores
 *
 * Run this on a schedule (cron job in server.js)
 */
const runEscalation = async () => {
  const now = new Date();
  let escalated = 0;

  try {
    // Rule 1: High priority unresolved > 24 hours → boost score
    const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);
    const highUnresolved = await Report.find({
      priorityLevel: 'High',
      status: { $in: ['pending', 'in-progress'] },
      createdAt: { $lt: oneDayAgo },
      escalated: { $ne: true },
    });

    for (const report of highUnresolved) {
      const newScore = Math.min(100, (report.priorityScore || 70) + 10);
      await Report.findByIdAndUpdate(report._id, {
        priorityScore: newScore,
        escalated: true,
        escalationReason: 'High priority unresolved > 24 hours',
        escalatedAt: now,
      });
      escalated++;
    }

    // Rule 2: Medium unresolved > 72 hours → upgrade to High
    const threeDaysAgo = new Date(now - 72 * 60 * 60 * 1000);
    const mediumUnresolved = await Report.find({
      priorityLevel: 'Medium',
      status: { $in: ['pending', 'in-progress'] },
      createdAt: { $lt: threeDaysAgo },
    });

    for (const report of mediumUnresolved) {
      await Report.findByIdAndUpdate(report._id, {
        priorityLevel: 'High',
        priorityScore: Math.min(100, (report.priorityScore || 50) + 20),
        escalationReason: 'Medium priority unresolved > 72 hours',
        escalatedAt: now,
      });
      escalated++;
    }

    // Rule 3: Cluster detection — boost priority of grouped complaints
    // Find all pending reports, group those within ~500m of each other
    const pendingReports = await Report.find({
      status: 'pending',
      'location.coordinates': { $exists: true },
    }).select('_id location priorityScore priorityLevel');

    const boosted = new Set();
    for (let i = 0; i < pendingReports.length; i++) {
      if (boosted.has(String(pendingReports[i]._id))) continue;

      const nearby = await Report.find({
        _id: { $ne: pendingReports[i]._id },
        status: 'pending',
        location: {
          $near: {
            $geometry: {
              type: 'Point',
              coordinates: pendingReports[i].location.coordinates,
            },
            $maxDistance: 500, // 500 meters
          },
        },
      }).select('_id priorityScore');

      if (nearby.length >= 2) {
        // 3+ complaints in 500m → boost all of them
        const idsToBoost = [pendingReports[i]._id, ...nearby.map(r => r._id)];
        for (const id of idsToBoost) {
          if (!boosted.has(String(id))) {
            await Report.findByIdAndUpdate(id, {
              $inc: { priorityScore: 5 },
              clusterSize: nearby.length + 1,
              clusterBoosted: true,
            });
            boosted.add(String(id));
            escalated++;
          }
        }
      }
    }

    console.log(`[Escalation] Ran at ${now.toISOString()} — ${escalated} reports escalated`);
    return { success: true, escalated };
  } catch (error) {
    console.error('[Escalation] Failed:', error.message);
    return { success: false, error: error.message };
  }
};

module.exports = { runEscalation };