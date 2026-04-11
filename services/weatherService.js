const axios = require('axios');

const OPENWEATHER_API_KEY = process.env.OPENWEATHER_API_KEY;

const getWeatherScore = async (latitude, longitude) => {
  try {
    if (!OPENWEATHER_API_KEY) {
      console.warn('[WeatherService] OPENWEATHER_API_KEY not set, using default score 30');
      return { score: 30, details: { condition: 'unknown', temp: null } };
    }

    const url = `https://api.openweathermap.org/data/2.5/weather?lat=${latitude}&lon=${longitude}&appid=${OPENWEATHER_API_KEY}&units=metric`;
    const { data } = await axios.get(url, { timeout: 8000 });

    const weatherId = data.weather[0]?.id || 800;
    const temp = data.main?.temp || 25;
    const humidity = data.main?.humidity || 50;
    const condition = data.weather[0]?.main || 'Clear';

    let score = 0;

    if (weatherId >= 200 && weatherId < 300) score += 55;      // Thunderstorm
    else if (weatherId >= 300 && weatherId < 400) score += 35; // Drizzle
    else if (weatherId >= 500 && weatherId < 600) score += 50; // Rain
    else if (weatherId >= 600 && weatherId < 700) score += 25; // Snow
    else if (weatherId >= 700 && weatherId < 800) score += 20; // Fog/Mist
    else score += 10;                                           // Clear

    if (temp > 38) score += 30;
    else if (temp > 32) score += 20;
    else if (temp > 26) score += 10;

    if (humidity > 80 && temp > 28) score += 15;

    return {
      score: Math.min(100, Math.max(0, score)),
      details: { condition, temp, humidity, weatherId }
    };
  } catch (error) {
    console.error('[WeatherService] Failed:', error.message);
    return { score: 30, details: { condition: 'unavailable', temp: null } };
  }
};

module.exports = { getWeatherScore };