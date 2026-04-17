const Groq = require('groq-sdk');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ── System prompt with full platform knowledge ────────────────────────────────
const SYSTEM_PROMPT = `You are EcoBot, the friendly and intelligent AI assistant for ZeroX Waste — a Smart Waste Management Platform that helps citizens report, track, and resolve waste complaints in their cities.

## YOUR PERSONALITY
- Warm, helpful, and conversational — like a knowledgeable friend
- Use simple language, occasional relevant emojis (♻️ 🌿 📍 🔔 🏆)
- Be concise but complete — aim for 80-120 words per response
- If unsure, be honest rather than making things up
- For follow-up questions, reference what was discussed earlier in the conversation

## PLATFORM FEATURES YOU KNOW ABOUT

### How to Report Waste (step by step)
1. Click "Report Waste" in the navbar
2. Upload one or more clear photos of the waste
3. Allow GPS location or drag the map pin to the exact spot
4. Choose waste category and write a description
5. Watch the progress bar reach 100%, then click Submit
6. AI analysis runs automatically in background (5-15 seconds)

### Waste Categories
Plastic, Organic/Food, Electronic/E-waste, Paper & Cardboard, Metal, Glass, Batteries, Light Bulbs, Chemical, Medical/Pharmaceutical, Textiles & Clothing, Furniture/Bulky Waste, Garden Waste, Cooking/Motor Oil, Construction Debris, Other

### Priority Score System (0-100 scale)
Your report gets an AI-calculated priority score from 4 factors:
- Resource Score (35% weight): AI analyzes the photo — E-waste scores 85+, Metal 70+, Plastic 55+, Organic 30+
- Location Score (25% weight): Proximity to hospitals/schools gives +60pts, markets/stations +40pts
- Weather Score (20% weight): Rain/thunderstorm adds 50-55pts, temperature above 38°C adds 30pts  
- Sentiment Score (20% weight): Urgent words like "dangerous", "children nearby", "blocking road" raise the score

Priority levels:
- HIGH (70-100): Immediate action required
- MEDIUM (40-69): Scheduled within 24-72 hours
- LOW (0-39): Added to routine cleanup queue

Formula: Score = (0.35 × Resource) + (0.25 × Location) + (0.20 × Weather) + (0.20 × Sentiment)

### Report Status Flow
pending → in-progress → resolved (or rejected)
You get a real-time notification (bell icon in navbar) whenever your report status changes.

### Points & Gamification
- Submit any report: +10 points
- Report gets resolved: +25 bonus points
- High priority report found: +15 bonus points
- First ever report: +20 welcome bonus
- 5 reports milestone: +30 bonus points

Badges you can earn: First Reporter 🌱 (1 report), Eco Warrior ⚔️ (5 reports), Green Champion 🏆 (10 reports), Point Collector 💎 (100 points), Super Reporter 🦸 (250 points)

### Leaderboard
Shows top reporters ranked by points. If your points show as zero after reporting, go to Leaderboard and click "Sync My Points" — this fixes points for reports submitted before the feature was enabled.

### My Reports Page
Shows all your submitted complaints. Click any card to open full AI analysis including:
- Priority score breakdown with individual sub-scores
- AI waste classification (type, hazard level, recyclability)
- Disposal instructions and nearby recycling centers
- Smart recommendations for authorities to contact

If a report shows "N/A" for priority, click "Analyze Now" on that card.

### Map Page
Two view modes:
- Markers: colored pins by waste category (blue=plastic, green=organic, purple=electronic, orange=other). Red ring around pin = High priority.
- Heatmap: circles sized by priority score, red=High, yellow=Medium, green=Low

Use the left sidebar to filter by status, priority, or search by location.

### Notifications (Bell Icon)
Real-time alerts when your report status changes. Keep the page open for instant notifications — they use Server-Sent Events technology. Bell icon shows unread count.

### Admin Features (for admins only)
- Dashboard with charts: trend over time, priority distribution, category breakdown, resolution rate, average priority score
- Table with all reports sortable by priority score or date
- Click any report row to manage it: change status, re-run AI analysis, assign workers
- Changing status to "Resolved" automatically awards the reporter +25 points
- "Show Priority Formula" button in dashboard header explains the scoring
- Worker assignment dropdown shows available workers with their area

### Common Problems & Solutions
- Priority score N/A → Click "Analyze Now" on the report card
- Points showing zero → Go to Leaderboard, click "Sync My Points"
- Location not detecting → Allow browser location permission, or drag the map pin manually
- Report not submitting → Check progress bar — all 4 steps must reach 100%
- Notifications not appearing → Keep the browser tab open; real-time notifications need active connection

## RESPONSE RULES
1. Keep responses under 150 words unless user asks for detailed explanation
2. For step-by-step tasks, use numbered lists
3. For feature descriptions, use brief bullet points
4. Always end with a follow-up offer if appropriate ("Anything else I can help with?")
5. If asked something outside your knowledge, say: "I'm not sure about that specific detail. You can check the platform's documentation or contact support."
6. Never invent features or statistics that aren't listed above`;

// ── Retry helper ─────────────────────────────────────────────────────────────
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const callGroqWithRetry = async (messages, retries = 2) => {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const completion = await groq.chat.completions.create({
        model: 'llama-3.1-8b-instant',
        messages,
        temperature: 0.7,
        max_tokens:  400,
        top_p:       0.9,
      });

      const reply = completion.choices[0]?.message?.content?.trim();
      if (!reply) throw new Error('Empty response from model');
      return reply;

    } catch (error) {
      const isLast = attempt === retries;
      if (isLast) throw error;

      // Wait before retry: 1s, then 2s
      await sleep((attempt + 1) * 1000);
      console.warn(`[Chatbot] Retry ${attempt + 1} after error: ${error.message}`);
    }
  }
};

// ── POST /api/chatbot/message ─────────────────────────────────────────────────
const sendMessage = async (req, res) => {
  try {
    const { messages, userRole = 'user' } = req.body;

    // ── Input validation ────────────────────────────────────────────────────
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({
        status:  'error',
        message: 'messages must be an array',
      });
    }

    if (messages.length === 0) {
      return res.status(400).json({
        status:  'error',
        message: 'messages array cannot be empty',
      });
    }

    // ── Sanitize messages — CRITICAL FIX ───────────────────────────────────
    // Strip any extra fields (time, id, etc.) and enforce role + content only
    const sanitized = messages
      .filter(m => m && typeof m === 'object' && m.content && typeof m.content === 'string' && m.content.trim().length > 0)
      .map(m => ({
        role:    m.role === 'assistant' ? 'assistant' : 'user',
        content: m.content.trim().slice(0, 1500), // hard cap per message
      }))
      .slice(-12); // keep last 12 messages (6 turns) for context window

    if (sanitized.length === 0) {
      return res.status(400).json({
        status:  'error',
        message: 'No valid messages after sanitization',
      });
    }

    // ── Last message must be from user ────────────────────────────────────
    const lastMessage = sanitized[sanitized.length - 1];
    if (lastMessage.role !== 'user') {
      return res.status(400).json({
        status:  'error',
        message: 'Last message must be from user',
      });
    }

    // ── Add role context for admin users ──────────────────────────────────
    if (userRole === 'admin') {
      sanitized[sanitized.length - 1] = {
        role:    'user',
        content: sanitized[sanitized.length - 1].content +
                 '\n\n[Context: I am an admin of this platform]',
      };
    }

    // ── Call Groq with retry logic ────────────────────────────────────────
    const finalMessages = [
      { role: 'system', content: SYSTEM_PROMPT },
      ...sanitized,
    ];

    const reply = await callGroqWithRetry(finalMessages);

    return res.status(200).json({
      status: 'success',
      data:   { reply },
    });

  } catch (error) {
    console.error('[Chatbot] Final error after retries:', error.message);

    // ── Graceful fallback responses based on error type ───────────────────
    let fallback = "I'm experiencing a brief hiccup. Please send your question again and I'll help you right away! 🔄";

    if (error.message?.includes('rate limit') || error.status === 429) {
      fallback = "I'm getting a lot of questions right now! Please wait a few seconds and try again. ⏳";
    } else if (error.message?.includes('authentication') || error.status === 401) {
      fallback = "There's a configuration issue on my end. Please contact the platform admin. 🔧";
    } else if (error.message?.includes('network') || error.code === 'ENOTFOUND') {
      fallback = "Network connectivity issue detected. Please check your connection and try again. 🌐";
    }

    // Return 200 with fallback so frontend shows graceful message instead of error
    return res.status(200).json({
      status: 'success',
      data:   { reply: fallback },
    });
  }
};

// ── GET /api/chatbot/suggestions ─────────────────────────────────────────────
const getSuggestions = (req, res) => {
  const { page = 'home', role = 'user' } = req.query;

  const allSuggestions = {
    home: [
      'How do I report waste?',
      'What is the priority score?',
      'How do I earn points and badges?',
      'What happens after I submit a report?',
    ],
    report: [
      'What waste categories are available?',
      'My GPS is not detecting location',
      'How many photos can I upload?',
      'Why is my submit button disabled?',
    ],
    myreports: [
      'Why does my report show N/A priority?',
      'How do I view AI classification?',
      'What do the status colors mean?',
      'How do I earn more points?',
    ],
    leaderboard: [
      'How are points calculated?',
      'What badges can I earn?',
      'Why are my points showing zero?',
      'How is my rank determined?',
    ],
    map: [
      'What do the pin colors mean?',
      'How does heatmap mode work?',
      'How to filter complaints on the map?',
      'What is the cluster detection feature?',
    ],
    admin: [
      'How do I change a report status?',
      'How does the priority formula work?',
      'How to assign workers to a complaint?',
      'How to re-run AI analysis on a report?',
    ],
    wastelist: [
      'How are reports sorted by default?',
      'What is the AI classification shown?',
      'Can I filter by priority level?',
      'What does escalated mean?',
    ],
  };

  const adminSpecific = [
    'How to assign workers?',
    'What triggers auto-escalation?',
  ];

  let result = allSuggestions[page] || allSuggestions.home;
  if (role === 'admin') {
    result = [...allSuggestions[page]?.slice(0, 2) || [], ...adminSpecific];
  }

  return res.status(200).json({ status: 'success', data: result });
};

module.exports = { sendMessage, getSuggestions };