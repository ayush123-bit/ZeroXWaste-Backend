const Groq = require('groq-sdk');
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

/**
 * Classifies waste from image + category into type with disposal guidance.
 * Returns structured classification used in report detail view and recommendations.
 */
const classifyWaste = async (imageUrl, category, description) => {
  try {
    const prompt = `You are an expert waste management AI. Based on the waste category "${category}" and description "${description}", provide classification and disposal guidance.

Return ONLY this JSON (no markdown, no extra text):
{
  "wasteType": "<Dry|Wet|Hazardous|E-waste|Biomedical|Construction>",
  "subType": "<specific type like PET Plastic, Lead Battery, Food Waste etc>",
  "hazardLevel": "<Low|Medium|High|Critical>",
  "disposalMethod": "<exact disposal method in 1-2 sentences>",
  "recyclingPossibility": "<Yes|No|Partial>",
  "recyclingInstructions": "<how to recycle in 1-2 sentences>",
  "environmentalImpact": "<brief impact if not disposed properly, 1 sentence>",
  "estimatedDecompositionDays": <number or -1 if non-biodegradable>,
  "actionRequired": "<Immediate|Within 24hrs|Within 1 week|Routine>"
}

Category context:
- plastic → Dry waste, recyclable
- organic → Wet waste, compostable  
- electronic → E-waste, hazardous
- other → Classify based on description`;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.1-8b-instant',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1,
      max_tokens: 400,
    });

    const raw = completion.choices[0]?.message?.content?.trim() || '';
    const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const result = JSON.parse(cleaned);

    return { success: true, data: result };
  } catch (error) {
    console.error('[WasteClassifier] Failed:', error.message);
    return {
      success: false,
      data: {
        wasteType: 'Unknown',
        subType: 'Unclassified',
        hazardLevel: 'Low',
        disposalMethod: 'Take to nearest waste collection center.',
        recyclingPossibility: 'No',
        recyclingInstructions: 'Check with local municipality.',
        environmentalImpact: 'May cause soil and water contamination.',
        estimatedDecompositionDays: -1,
        actionRequired: 'Routine',
      },
    };
  }
};

module.exports = { classifyWaste };