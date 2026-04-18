const Groq = require('groq-sdk');
const axios = require('axios');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

/**
 * Validate whether an image actually shows waste/garbage.
 * Returns { valid: boolean, reason: string, confidence: number }
 */
const validateWasteImage = async (imageUrl, type = 'complaint') => {
  if (!imageUrl) return { valid: false, reason: 'No image provided', confidence: 0 };

  try {
    const response = await axios.get(imageUrl, { responseType: 'arraybuffer', timeout: 12000 });
    const base64 = Buffer.from(response.data).toString('base64');
    const mediaType = response.headers['content-type'] || 'image/jpeg';

    const prompt = type === 'complaint'
      ? `Analyze this image. Is it showing waste, garbage, litter, pollution, or any kind of environmental problem outdoors?
         Return ONLY valid JSON: {"isWaste":true/false,"confidence":0-100,"reason":"<10 words>","category":"plastic/organic/electronic/other/none"}`
      : `Analyze this image. Is it showing a clean, cleared, or improved outdoor area (cleaned up, cleared waste, better environment)?
         Return ONLY valid JSON: {"isCleaned":true/false,"confidence":0-100,"reason":"<10 words>"}`;

    const completion = await groq.chat.completions.create({
      model: 'meta-llama/llama-4-scout-17b-16e-instruct',
      messages: [{
        role: 'user',
        content: [
          { type: 'image_url', image_url: { url: `data:${mediaType};base64,${base64}` } },
          { type: 'text', text: prompt },
        ],
      }],
      temperature: 0.1,
      max_tokens: 100,
    });

    const raw = completion.choices[0]?.message?.content?.trim() || '{}';
    const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const result = JSON.parse(cleaned);

    if (type === 'complaint') {
      return {
        valid:      result.isWaste === true,
        confidence: result.confidence || 50,
        reason:     result.reason || 'Unknown',
        category:   result.category || 'other',
      };
    } else {
      return {
        valid:      result.isCleaned === true,
        confidence: result.confidence || 50,
        reason:     result.reason || 'Unknown',
      };
    }
  } catch (error) {
    console.error('[ImageValidation] Failed:', error.message);
    // On failure, allow submission (don't block due to API issues)
    return { valid: true, confidence: 50, reason: 'Validation unavailable — allowed by default' };
  }
};

module.exports = { validateWasteImage };