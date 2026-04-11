const axios = require('axios');

const getLocationScore = async (latitude, longitude, address = '') => {
  try {
    let score = 20;
    const text = address.toLowerCase();

    const criticalKeywords = [
      'hospital', 'clinic', 'health centre', 'medical', 'school',
      'college', 'university', 'kindergarten', 'nursery',
    ];
    const highKeywords = [
      'market', 'bazaar', 'mall', 'station', 'railway', 'metro',
      'bus stand', 'airport', 'park', 'playground', 'temple',
      'mosque', 'church', 'gurudwara',
    ];
    const moderateKeywords = [
      'road', 'street', 'marg', 'avenue', 'sector', 'colony',
      'nagar', 'residential', 'housing',
    ];

    const hasCritical = criticalKeywords.some(kw => text.includes(kw));
    const hasHigh = highKeywords.some(kw => text.includes(kw));
    const hasModerate = moderateKeywords.some(kw => text.includes(kw));

    if (hasCritical) score += 60;
    else if (hasHigh) score += 40;
    else if (hasModerate) score += 20;

    // Enrich with Nominatim if address is not specific enough
    if (!hasCritical && !hasHigh && latitude && longitude) {
      try {
        const { data } = await axios.get(
          `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${latitude}&lon=${longitude}&zoom=17`,
          {
            timeout: 6000,
            headers: { 'User-Agent': 'GreenMind-WasteApp/1.0' },
          }
        );

        const enriched = (data.display_name || '').toLowerCase();
        const osmType = (data.type || '').toLowerCase();
        const osmCategory = (data.category || '').toLowerCase();

        const enrichedCritical = criticalKeywords.some(kw => enriched.includes(kw));
        const enrichedHigh = highKeywords.some(kw => enriched.includes(kw));

        if (enrichedCritical) score += 30;
        else if (enrichedHigh) score += 20;

        if (['hospital', 'school', 'university'].includes(osmType)) score += 20;
        else if (['marketplace', 'station', 'park'].includes(osmType)) score += 15;
        else if (osmCategory === 'amenity') score += 10;
      } catch {
        // Nominatim failed — not critical, skip silently
      }
    }

    return {
      score: Math.min(100, Math.max(0, score)),
      reasoning: hasCritical
        ? 'Near hospital or school'
        : hasHigh
        ? 'Near public gathering point'
        : 'Standard urban location',
    };
  } catch (error) {
    console.error('[LocationService] Failed:', error.message);
    return { score: 25, reasoning: 'Location analysis unavailable' };
  }
};

module.exports = { getLocationScore };