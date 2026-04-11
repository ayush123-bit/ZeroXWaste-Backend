const Groq = require('groq-sdk');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const getSentimentScore = async (description) => {
  try {
    if (!description || description.trim().length === 0) {
      return { score: 30, label: 'neutral', reasoning: 'No description provided' };
    }

    const prompt = `You are a waste complaint urgency analyzer. Analyze the complaint and return ONLY a JSON object. No markdown, no explanation, no extra text.

Complaint: "${description}"

Return exactly this:
{
  "urgencyScore": <number 0-100>,
  "label": "<low|moderate|high|critical>",
  "reasoning": "<max 10 words>"
}

Score guide:
0-25: Routine, no urgency words
26-50: Mild concern, general waste
51-75: Urgency words like smell, overflowing, blocking
76-100: Dangerous, children, flooding, medical, urgent`;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.1-8b-instant',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2,
      max_tokens: 150,
    });

    const raw = completion.choices[0]?.message?.content?.trim() || '';
    const cleaned = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const result = JSON.parse(cleaned);

    return {
      score: Math.min(100, Math.max(0, Number(result.urgencyScore) || 30)),
      label: result.label || 'moderate',
      reasoning: result.reasoning || ''
    };
  } catch (error) {
    console.error('[SentimentService] Failed:', error.message);
    return { score: 30, label: 'moderate', reasoning: 'Analysis unavailable' };
  }
};

module.exports = { getSentimentScore };