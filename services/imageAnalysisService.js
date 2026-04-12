const Groq = require('groq-sdk');
const axios = require('axios');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const fetchImageAsBase64 = async (imageUrl) => {
  const response = await axios.get(imageUrl, {
    responseType: 'arraybuffer',
    timeout: 12000,
  });
  const base64 = Buffer.from(response.data).toString('base64');
  const contentType = response.headers['content-type'] || 'image/jpeg';
  return { base64, mediaType: contentType };
};

// Fallback scoring when vision model unavailable — uses category heuristic
const getCategoryFallbackScore = (category) => {
  const scores = {
    electronic: 80, batteries: 85, chemical: 90, medical: 88,
    metal: 70, plastic: 60, glass: 55, construction: 50,
    organic: 35, garden: 30, textiles: 40, furniture: 45,
    paper: 40, oil: 65, other: 40,
  };
  return scores[category?.toLowerCase()] || 40;
};

const getImageResourceScore = async (imageUrl, category = 'other') => {
  // If no image URL, use category-based fallback immediately
  if (!imageUrl) {
    const score = getCategoryFallbackScore(category);
    return { score, materials: [category], reasoning: 'No image — category-based score' };
  }

  try {
    const { base64, mediaType } = await fetchImageAsBase64(imageUrl);

    const completion = await groq.chat.completions.create({
      model: 'meta-llama/llama-4-scout-17b-16e-instruct',
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'image_url',
              image_url: { url: `data:${mediaType};base64,${base64}` },
            },
            {
              type: 'text',
              text: `Analyze this waste image. Return ONLY valid JSON, no markdown, no explanation:
{"resourceScore":<0-100>,"detectedMaterials":["material1"],"reasoning":"<15 words max>"}

Score: E-waste/batteries=85-100, Metal=70-85, Plastic=55-70, Mixed=50-65, Organic=30-45, General=25-35`,
            },
          ],
        },
      ],
      temperature: 0.1,
      max_tokens: 150,
    });

    const raw = completion.choices[0]?.message?.content?.trim() || '';
    const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const result = JSON.parse(cleaned);

    return {
      score: Math.min(100, Math.max(0, Number(result.resourceScore) || getCategoryFallbackScore(category))),
      materials: Array.isArray(result.detectedMaterials) ? result.detectedMaterials : [category],
      reasoning: result.reasoning || '',
    };
  } catch (error) {
    console.error('[ImageAnalysis] Vision failed, using category fallback:', error.message);
    const score = getCategoryFallbackScore(category);
    return { score, materials: [category], reasoning: `Category fallback (${category})` };
  }
};

module.exports = { getImageResourceScore };