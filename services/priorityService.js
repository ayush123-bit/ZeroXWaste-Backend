const { getWeatherScore } = require('./weatherService');
const { getSentimentScore } = require('./sentimentService');
const { getImageResourceScore } = require('./imageAnalysisService');
const { getLocationScore } = require('./locationService');

// Weights must sum to 1.0
const WEIGHTS = {
  resource: 0.35,
  location: 0.25,
  weather: 0.20,
  sentiment: 0.20,
};

/**
 * Calculates composite priority score (0–100) from 4 analyses run in parallel.
 *
 * @param {Object} params
 * @param {string} params.imageUrl     - First image Cloudinary URL
 * @param {number} params.latitude
 * @param {number} params.longitude
 * @param {string} params.address      - Human-readable address string
 * @param {string} params.description  - User complaint text
 * @returns {Object} { priorityScore, priorityLevel, breakdown }
 */
const calculatePriorityScore = async ({ imageUrl, latitude, longitude, address, description }) => {
  const [resourceResult, locationResult, weatherResult, sentimentResult] = await Promise.all([
    getImageResourceScore(imageUrl),
    getLocationScore(latitude, longitude, address),
    getWeatherScore(latitude, longitude),
    getSentimentScore(description),
  ]);

  const raw =
    WEIGHTS.resource  * resourceResult.score  +
    WEIGHTS.location  * locationResult.score  +
    WEIGHTS.weather   * weatherResult.score   +
    WEIGHTS.sentiment * sentimentResult.score;

  const priorityScore = Math.round(Math.min(100, Math.max(0, raw)));

  const priorityLevel =
    priorityScore >= 70 ? 'High' :
    priorityScore >= 40 ? 'Medium' : 'Low';

  return {
    priorityScore,
    priorityLevel,
    breakdown: {
      resourceScore:  Math.round(resourceResult.score),
      locationScore:  Math.round(locationResult.score),
      weatherScore:   Math.round(weatherResult.score),
      sentimentScore: Math.round(sentimentResult.score),
      materials:      resourceResult.materials,
      weatherDetails: weatherResult.details,
      sentimentLabel: sentimentResult.label,
    },
  };
};

module.exports = { calculatePriorityScore };