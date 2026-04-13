const Report = require('../models/Report');
const { calculatePriorityScore } = require('../services/priorityService');
const { classifyWaste } = require('../services/wasteClassifierService');
const { getRecommendations } = require('../services/recommendationService');
const { sendToUser } = require('../services/notificationService');

const recalculatePriority = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ status: 'error', message: 'Report not found' });

    const lat      = report.location.coordinates[1];
    const lng      = report.location.coordinates[0];
    const imageUrl = report.images[0]?.url || null;
    const category = report.category || 'other';

    const [priorityResult, classificationResult, recommendationResult] = await Promise.all([
      calculatePriorityScore({
        imageUrl, latitude: lat, longitude: lng,
        address: report.location.address || '',
        description: report.description,
        category,  // critical — enables fallback scoring
      }),
      classifyWaste(imageUrl, category, report.description),
      getRecommendations({
        category, priorityLevel: null,
        address: report.location.address || '',
        wasteType: null, latitude: lat, longitude: lng,
      }),
    ]);

    const updated = await Report.findByIdAndUpdate(
      req.params.id,
      {
        priorityScore:       priorityResult.priorityScore,
        priorityLevel:       priorityResult.priorityLevel,
        priorityBreakdown:   priorityResult.breakdown,
        wasteClassification: classificationResult.data,
        recommendations:     recommendationResult.data,
      },
      { new: true , runValidators: false}
    );

    // Notify reporter that their report has been analyzed
    if (updated.userId) {
      sendToUser(updated.userId, {
        type:    'PRIORITY_CALCULATED',
        title:   'Your report has been analyzed',
        message: `Priority level: ${priorityResult.priorityLevel} (Score: ${priorityResult.priorityScore}/100)`,
        reportId: updated._id,
      });
    }

    return res.status(200).json({ status: 'success', message: 'Priority recalculated', data: updated });
  } catch (error) {
    console.error('[recalculatePriority]', error.message);
    return res.status(500).json({ status: 'error', message: error.message });
  }
};

module.exports = { recalculatePriority };