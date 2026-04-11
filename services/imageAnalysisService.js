const Groq = require('groq-sdk');
const axios = require('axios');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const fetchImageAsBase64 = async (imageUrl) => {
  const response = await axios.get(imageUrl, {
    responseType: 'arraybuffer',
    timeout: 15000,
  });
  const base64 = Buffer.from(response.data).toString('base64');
  const contentType = response.headers['content-type'] || 'image/jpeg';
  return { base64, mediaType: contentType };
};

const getImageResourceScore = async (imageUrl) => {
  try {
    if (!imageUrl) {
      return { score: 30, materials: [], reasoning: 'No image provided' };
    }

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
              text: `Analyze this waste image. Return ONLY a JSON object, no markdown:
{
  "resourceScore": <number 0-100>,
  "detectedMaterials": ["material1", "material2"],
  "reasoning": "<max 15 words>"
}

Score guide:
- E-waste (phones, batteries, electronics): 85-100
- Metal (cans, pipes, scrap metal): 70-85
- Plastic (bottles, bags, containers): 55-70
- Mixed recyclables: 50-65
- Organic waste (food, leaves): 30-45
- Construction debris: 35-50
- General/unidentifiable waste: 25-35
- Minor/tiny waste: 10-25`,
            },
          ],
        },
      ],
      temperature: 0.2,
      max_tokens: 200,
    });

    const raw = completion.choices[0]?.message?.content?.trim() || '';
    const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const result = JSON.parse(cleaned);

    return {
      score: Math.min(100, Math.max(0, Number(result.resourceScore) || 30)),
      materials: Array.isArray(result.detectedMaterials) ? result.detectedMaterials : [],
      reasoning: result.reasoning || '',
    };
  } catch (error) {
    console.error('[ImageAnalysisService] Failed:', error.message);
    return { score: 40, materials: [], reasoning: 'Vision analysis unavailable' };
  }
};

module.exports = { getImageResourceScore };