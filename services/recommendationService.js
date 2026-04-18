const Groq = require('groq-sdk');
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

/**
 * Generates actionable recommendations for a complaint.
 * Includes nearest recycling centers (simulated with realistic Indian data),
 * suggested action steps, and authority to contact.
 */
const getRecommendations = async ({ category, priorityLevel, address, wasteType, latitude, longitude }) => {
  try {
    // Simulated recycling centers based on region keyword matching
    // In production, replace with Google Places API or a real centers database
    const recyclingCenters = getNearbyCenters(address, category);

    const prompt = `You are a municipal waste management advisor. Generate action recommendations.

Waste Details:
- Category: ${category}
- Type: ${wasteType || 'Unknown'}
- Priority: ${priorityLevel || 'Medium'}
- Location: ${address || 'Unknown area'}

Return ONLY this JSON (no markdown):
{
  "immediateActions": ["action1", "action2", "action3"],
  "authorityToContact": "<Municipal corporation / PCB / CPCB / Private agency>",
  "contactMethod": "<how to contact authority>",
  "estimatedResolutionTime": "<realistic timeframe>",
  "preventionTips": ["tip1", "tip2"],
  "communityRole": "<what nearby residents can do>"
}`;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.1-8b-instant',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2,
      max_tokens: 400,
    });

    const raw = completion.choices[0]?.message?.content?.trim() || '';
    const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const aiResult = JSON.parse(cleaned);

    return {
      success: true,
      data: {
        ...aiResult,
        recyclingCenters,
      },
    };
  } catch (error) {
    console.error('[RecommendationService] Failed:', error.message);
    return {
      success: false,
      data: {
        immediateActions: ['Report to municipal corporation', 'Avoid touching waste', 'Keep area cordoned off'],
        authorityToContact: 'Local Municipal Corporation',
        contactMethod: 'Visit nearest ward office or call 1533 (Swachh Bharat helpline)',
        estimatedResolutionTime: '2-3 working days',
        preventionTips: ['Use designated dustbins', 'Segregate waste at source'],
        communityRole: 'Inform neighbors and local ward member',
        recyclingCenters: getNearbyCenters('', category),
      },
    };
  }
};

// Realistic recycling center data for major Indian cities
// Matches address keywords to return relevant centers
const getNearbyCenters = (address = '', category = '') => {
  const addr = address.toLowerCase();

  const centersByCity = {
    delhi: [
      { name: 'ITC WOW (Wealth Out of Waste)', area: 'Multiple Delhi locations', accepts: ['plastic', 'paper', 'metal'], phone: '1800-345-5678' },
      { name: 'Kabadiwala Network Delhi', area: 'Karol Bagh, Lajpat Nagar', accepts: ['all'], phone: '011-4567-8901' },
    ],
    mumbai: [
      { name: 'Stree Mukti Sanghatana', area: 'Chembur, Mumbai', accepts: ['plastic', 'organic'], phone: '022-2521-4434' },
      { name: 'E-Parisara (E-waste)', area: 'Andheri East', accepts: ['electronic'], phone: '022-2834-5678' },
    ],
    bangalore: [
      { name: 'Hasiru Dala Innovations', area: 'Indiranagar, Bangalore', accepts: ['all'], phone: '080-4567-8901' },
      { name: 'E-Parisara Bangalore', area: 'Bommanahalli', accepts: ['electronic'], phone: '080-2573-1305' },
    ],
    prayagraj: [
      { name: 'Prayagraj Nagar Nigam Collection', area: 'Civil Lines, Prayagraj', accepts: ['all'], phone: '0532-2501-234' },
      { name: 'UP Pollution Control Board', area: 'Lukerganj, Prayagraj', accepts: ['hazardous', 'electronic'], phone: '0532-2506-070' },
    ],
    default: [
      { name: 'Municipal Corporation Waste Center', area: 'Contact local ward office', accepts: ['all'], phone: '1533 (Swachh Bharat)' },
      { name: 'Kabadiwala Network', area: 'Search on www.kabadiwala.com', accepts: ['plastic', 'paper', 'metal'], phone: '1800-123-4567' },
    ],
  };

  let centers = centersByCity.default;
  for (const city of Object.keys(centersByCity)) {
    if (addr.includes(city)) {
      centers = centersByCity[city];
      break;
    }
  }

  // Filter by category relevance
  return centers.filter(c =>
    c.accepts.includes('all') ||
    c.accepts.includes(category) ||
    (category === 'electronic' && c.accepts.includes('electronic'))
  );
};

module.exports = { getRecommendations };