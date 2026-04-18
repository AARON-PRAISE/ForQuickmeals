const express = require('express');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ---------------- ENV ----------------
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const WAVESPEED_API_KEY = process.env.WAVESPEED_API_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID?.replace(/\\n/g, '').replace(/[\r\n]/g, '').trim();
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL?.replace(/\\n/g, '').replace(/[\r\n]/g, '').trim();
const FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY;

if (!OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing');
if (!WAVESPEED_API_KEY) throw new Error('WAVESPEED_API_KEY missing');
if (!FIREBASE_PROJECT_ID) throw new Error('FIREBASE_PROJECT_ID missing');
if (!FIREBASE_CLIENT_EMAIL) throw new Error('FIREBASE_CLIENT_EMAIL missing');
if (!FIREBASE_PRIVATE_KEY) throw new Error('FIREBASE_PRIVATE_KEY missing');

// ---------------- JWT / FIREBASE AUTH ----------------
function str2ab(pem) {
  const clean = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\\n/g, '')
    .replace(/[\r\n\s]/g, '');
  const binary = atob(clean);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}

async function getAccessToken() {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;

  function base64url(obj) {
    return btoa(JSON.stringify(obj))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  const headerB64 = base64url({ alg: 'RS256', typ: 'JWT' });
  const payloadB64 = base64url({
    iss: FIREBASE_CLIENT_EMAIL,
    sub: FIREBASE_CLIENT_EMAIL,
    aud: 'https://oauth2.googleapis.com/token',
    iat,
    exp,
    scope: 'https://www.googleapis.com/auth/datastore',
  });

  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    'pkcs8',
    str2ab(FIREBASE_PRIVATE_KEY),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(signingInput)
  );

  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const jwt = `${signingInput}.${sigB64}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });

  const data = await res.json();
  if (!data.access_token) throw new Error('Failed to get Firebase access token');
  return data.access_token;
}

// ---------------- FIRESTORE HELPERS ----------------
function toFirestoreValue(val) {
  if (val && typeof val === 'object' && val.__type === 'reference') {
    return {
      referenceValue: `projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/${val.path}`,
    };
  }
  if (typeof val === 'number') return { doubleValue: val };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (Array.isArray(val))
    return { arrayValue: { values: val.map((v) => toFirestoreValue(v)) } };
  if (val !== null && typeof val === 'object')
    return {
      mapValue: {
        fields: Object.fromEntries(
          Object.entries(val).map(([k, v]) => [k, toFirestoreValue(v)])
        ),
      },
    };
  return { stringValue: String(val ?? '') };
}

function toFirestoreFields(obj) {
  const fields = {};
  for (const key in obj) fields[key] = toFirestoreValue(obj[key]);
  return fields;
}

async function firestoreCreate(collection, data, token) {
  const url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/${collection}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ fields: toFirestoreFields(data) }),
  });
  const result = await res.json();
  if (!res.ok) throw new Error(`Firestore create failed: ${JSON.stringify(result)}`);
  return result.name.split('/').pop();
}

async function firestoreUpdate(docPath, data, token) {
  const fieldPaths = Object.keys(data).join('&updateMask.fieldPaths=');
  const url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/${docPath}?updateMask.fieldPaths=${fieldPaths}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ fields: toFirestoreFields(data) }),
  });
  if (!res.ok) throw new Error(`Firestore update failed: ${await res.text()}`);
}

// ---------------- QUERY QuickMeals BY USER ----------------
async function queryQuickMealsByUser(userId, token) {
  const url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents:runQuery`;

  const body = {
    structuredQuery: {
      from: [{ collectionId: 'QuickMeals' }],
      where: {
        fieldFilter: {
          field: { fieldPath: 'UserRef' },
          op: 'EQUAL',
          value: {
            referenceValue: `projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/users/${userId}`,
          },
        },
      },
      select: {
        fields: [{ fieldPath: '__name__' }],
      },
    },
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  const results = await res.json();
  if (!res.ok) throw new Error(`Firestore query failed: ${JSON.stringify(results)}`);

  return results
    .filter((r) => r.document?.name)
    .map((r) => r.document.name.split('/').pop());
}

// ---------------- WAVESPEED ----------------
async function generateWaveSpeedImage(prompt) {
  async function submitTask() {
    const res = await fetch(
      'https://api.wavespeed.ai/api/v3/openai/gpt-image-1.5/text-to-image',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${WAVESPEED_API_KEY}`,
        },
        body: JSON.stringify({
          enable_base64_output: false,
          enable_sync_mode: false,
          output_format: 'jpeg',
          prompt,
          quality: 'low',
          size: '1024*1024',
        }),
      }
    );

    const json = JSON.parse(await res.text());
    if (!res.ok || !json.data?.id || !json.data?.urls?.get) {
      throw new Error('WaveSpeed submit failed');
    }
    return json.data;
  }

  async function pollResult(pollUrl, maxAttempts = 25) {
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise((r) => setTimeout(r, 3000));

      const res = await fetch(pollUrl, {
        headers: { Authorization: `Bearer ${WAVESPEED_API_KEY}` },
      });

      const json = JSON.parse(await res.text());
      const status = json.data?.status || json.status;

      if (status === 'completed') return json.data?.outputs?.[0] || null;
      if (status === 'failed') return null;
    }
    return null;
  }

  // Try up to 2 attempts
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const data = await submitTask();
      const imageUrl = await pollResult(data.urls.get);
      if (imageUrl) return imageUrl;
    } catch (err) {
      console.error(`❌ WaveSpeed attempt ${attempt} failed:`, err.message);
    }
  }

  return null;
}

// ---------------- OPENAI PROMPT ----------------
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

// ---------------- BUILD QuickmealDataType MAP ----------------
// Uses exact field names from QuickmealDataType regardless of actual meal type
function buildMealMap(suggestion, imageUrl) {
  return {
    LunchName: suggestion.name ?? '',
    LunchDescription: suggestion.description ?? '',
    LunchIngredients: [],              // not returned by this prompt — empty list
    MissingIngredientsLunch: [],       // not returned by this prompt — empty list
    LunchImage: imageUrl ?? '',
    LunchInstructions: [],             // not returned by this prompt — empty list
    LunchBudget: Number(suggestion.cost) || 0,
    LunchEquipment: [],                // not returned by this prompt — empty list
    LunchInstructionImages: [],        // no step images for quick meals
    lunchcost: Number(suggestion.cost) || 0,
  };
}

// ---------------- ROUTE ----------------
app.post('/suggest-meals', async (req, res) => {
  const { ingredients, mealTime, prepTime, userId } = req.body;

  if (!mealTime || !['breakfast', 'brunch', 'lunch', 'dinner', 'snack'].includes(mealTime.toLowerCase())) {
    return res.status(400).json({ error: 'mealTime must be breakfast, brunch, lunch, dinner, or snack' });
  }
  if (!prepTime) {
    return res.status(400).json({ error: 'prepTime is required e.g. "1 hour" or "30 minutes"' });
  }
  if (!userId) {
    return res.status(400).json({ error: 'userId is required' });
  }

  // Respond immediately so the client is not kept waiting
  res.json({ success: true, status: 'processing' });

  // Run everything in background
  (async () => {
    try {
      const token = await getAccessToken();

      // 1️⃣ Query all existing QuickMeals for this user and set Ready: false on all
      console.log('🔍 Querying existing QuickMeals for user:', userId);
      const existingDocIds = await queryQuickMealsByUser(userId, token);
      console.log(`📋 Found ${existingDocIds.length} existing QuickMeals — setting Ready: false`);
      await Promise.all(
        existingDocIds.map((docId) =>
          firestoreUpdate(`QuickMeals/${docId}`, { Ready: false }, token)
        )
      );
      console.log('✅ All previous QuickMeals marked as Ready: false');

      // 2️⃣ Create a new QuickMeals doc with Ready: false to start
      const quickMealId = await firestoreCreate(
        'QuickMeals',
        {
          UserRef: { __type: 'reference', path: `users/${userId}` },
          Ready: false,
        },
        token
      );
      console.log('📄 QuickMeals doc created with ID:', quickMealId);

      // 3️⃣ Call OpenAI for 3 meal suggestions
      console.log('🤖 Calling OpenAI for meal suggestions...');
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
      console.log('✅ OpenAI returned a response');

      const openAIResult = JSON.parse(raw);
      const content = openAIResult.choices[0].message.content;

      let jsonStr = content.replace(/```json|```/g, '').trim();
      const firstBrace = jsonStr.indexOf('{');
      const lastBrace = jsonStr.lastIndexOf('}');
      jsonStr = jsonStr.slice(firstBrace, lastBrace + 1);
      const parsed = JSON.parse(jsonStr);

      if (!parsed.suggestions || parsed.suggestions.length !== 3) {
        throw new Error('OpenAI did not return exactly 3 suggestions');
      }

      const [meal1, meal2, meal3] = parsed.suggestions;

      // 4️⃣ Call WaveSpeed for each meal's image prompt (sequentially to avoid rate limits)
      console.log('🖼️ Generating images via WaveSpeed...');

      console.log('  → Generating image for meal 1:', meal1.name);
      const image1 = await generateWaveSpeedImage(meal1.image_prompt);
      console.log('  ✅ Meal 1 image:', image1 ?? 'failed');

      console.log('  → Generating image for meal 2:', meal2.name);
      const image2 = await generateWaveSpeedImage(meal2.image_prompt);
      console.log('  ✅ Meal 2 image:', image2 ?? 'failed');

      console.log('  → Generating image for meal 3:', meal3.name);
      const image3 = await generateWaveSpeedImage(meal3.image_prompt);
      console.log('  ✅ Meal 3 image:', image3 ?? 'failed');

      // 5️⃣ Update QuickMeals doc with all 3 meals and set Ready: true
      console.log('💾 Saving meals to Firestore QuickMeals doc:', quickMealId);
      await firestoreUpdate(
        `QuickMeals/${quickMealId}`,
        {
          FirstMeal: buildMealMap(meal1, image1),
          Secondmeal: buildMealMap(meal2, image2),
          ThirdMeal: buildMealMap(meal3, image3),
          Ready: true,
        },
        token
      );

      console.log('✅ QuickMeals doc fully saved and marked Ready: true');
      console.log('🚀 suggest-meals background job complete');
    } catch (err) {
      console.error('❌ suggest-meals failed:', err.message);
    }
  })();
});

app.get('/health', (_, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ---------------- START ----------------
app.listen(PORT, '0.0.0.0', () =>
  console.log(`🍽️ Meal suggester running on port ${PORT}`)
);
