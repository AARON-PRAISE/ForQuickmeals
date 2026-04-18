const express = require('express');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

if (!OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing');

// ---------------- PROMPT ----------------
function buildMessages(ingredients, mealTime, prepTime) {
  const hasIngredients = Array.isArray(ingredients) && ingredients.length > 0;
  return [
    {
      role: 'system',
      content: `
You are a professional Nigerian chef. Suggest exactly 3 Nigerian meals suitable for ${mealTime} (which can be breakfast, brunch, lunch, dinner, or snack) and should take no longer than ${prepTime} to prepare.
${hasIngredients ? `Try to use these available ingredients where possible: ${JSON.stringify(ingredients)}` : 'No specific ingredients were provided, so suggest any 3 popular Nigerian meals suitable for this meal time.'}

For each meal return:
- name: string
- description: string (2–3 sentences about the meal)
- cost: integer in Naira (estimated total cost to make this meal)
- time: string (realistic prep + cook time e.g. "45 minutes")
- image_prompt: string (a detailed photorealistic image prompt of the finished dish, append "low quality" at the end)

Return ONLY valid JSON. No markdown, no code fences, no extra text.

Required JSON structure:
{
  "suggestions": [
    {
      "name": "",
      "description": "",
      "cost": 0,
      "time": "",
      "image_prompt": ""
    }
  ]
}
      `.trim(),
    },
    {
      role: 'user',
      content: JSON.stringify({ ingredients, mealTime, prepTime }),
    },
  ];
}

// ---------------- ROUTE ----------------
app.post('/suggest-meals', async (req, res) => {
  const { ingredients, mealTime, prepTime } = req.body;

  if (!mealTime || !['breakfast', 'brunch', 'lunch', 'dinner', 'snack'].includes(mealTime.toLowerCase())) {
    return res.status(400).json({ error: 'mealTime must be breakfast, brunch, lunch, dinner, or snack' });
  }

  if (!prepTime) {
    return res.status(400).json({ error: 'prepTime is required e.g. "1 hour" or "30 minutes"' });
  }

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        max_tokens: 1000,
        messages: buildMessages(ingredients, mealTime, prepTime),
      }),
    });

    const raw = await response.text();
    if (!response.ok) throw new Error(`OpenAI error: ${raw}`);

    const openAIResult = JSON.parse(raw);
    const content = openAIResult.choices[0].message.content;

    // Strip accidental markdown fences and parse
    const jsonStr = content.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(jsonStr);

    if (!parsed.suggestions || parsed.suggestions.length !== 3) {
      throw new Error('OpenAI did not return exactly 3 suggestions');
    }

    return res.json({ success: true, mealTime, prepTime, suggestions: parsed.suggestions });
  } catch (err) {
    console.error('❌ Suggest meals failed:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

app.get('/health', (_, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.listen(PORT, '0.0.0.0', () =>
  console.log(`🍽️  Meal suggester running on port ${PORT}`)
);
