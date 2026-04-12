const { getWeatherScore } = require('./weatherService');
const { getSentimentScore } = require('./sentimentService');
const { getImageResourceScore } = require('./imageAnalysisService');
const { getLocationScore } = require('./locationService');

const WEIGHTS = {
  resource:  0.35,
  location:  0.25,
  weather:   0.20,
  sentiment: 0.20,
};

const calculatePriorityScore = async ({ imageUrl, latitude, longitude, address, description, category = 'other' }) => {
  // Run all 4 analyses in parallel with individual error catching
  const [resourceResult, locationResult, weatherResult, sentimentResult] = await Promise.all([
    getImageResourceScore(imageUrl, category).catch(e => {
      console.error('[Priority] Image score failed:', e.message);
      return { score: 40, materials: [], reasoning: 'fallback' };
    }),
    getLocationScore(latitude, longitude, address).catch(e => {
      console.error('[Priority] Location score failed:', e.message);
      return { score: 25, reasoning: 'fallback' };
    }),
    getWeatherScore(latitude, longitude).catch(e => {
      console.error('[Priority] Weather score failed:', e.message);
      return { score: 30, details: { condition: 'unavailable', temp: null } };
    }),
    getSentimentScore(description).catch(e => {
      console.error('[Priority] Sentiment score failed:', e.message);
      return { score: 30, label: 'moderate', reasoning: 'fallback' };
    }),
  ]);

  // Guarantee all scores are valid numbers — never null or undefined
  const rScore = Math.round(Math.min(100, Math.max(0, Number(resourceResult.score)  || 40)));
  const lScore = Math.round(Math.min(100, Math.max(0, Number(locationResult.score)  || 25)));
  const wScore = Math.round(Math.min(100, Math.max(0, Number(weatherResult.score)   || 30)));
  const sScore = Math.round(Math.min(100, Math.max(0, Number(sentimentResult.score) || 30)));

  const raw = WEIGHTS.resource * rScore + WEIGHTS.location * lScore + WEIGHTS.weather * wScore + WEIGHTS.sentiment * sScore;
  const priorityScore = Math.round(Math.min(100, Math.max(0, raw)));

  const priorityLevel = priorityScore >= 70 ? 'High' : priorityScore >= 40 ? 'Medium' : 'Low';

  return {
    priorityScore,
    priorityLevel,
    breakdown: {
      resourceScore:  rScore,
      locationScore:  lScore,
      weatherScore:   wScore,
      sentimentScore: sScore,
      materials:      resourceResult.materials || [],
      weatherDetails: weatherResult.details   || {},
      sentimentLabel: sentimentResult.label   || 'moderate',
    },
  };
};

module.exports = { calculatePriorityScore };