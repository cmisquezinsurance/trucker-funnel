// api/submit-lead.js
// Vercel serverless function — receives lead from funnel, writes to Google Sheets

export default async function handler(req, res) {
  // Allow CORS so your HTML page can call this
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const lead = req.body;

    // ── Google Sheets Auth ──────────────────────────────────────────────────
    // These come from your environment variables in Vercel dashboard
    const SHEET_ID       = process.env.GOOGLE_SHEET_ID;
    const CLIENT_EMAIL   = process.env.GOOGLE_CLIENT_EMAIL;
    const PRIVATE_KEY    = process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');

    // Build JWT to authenticate with Google
    const token = await getGoogleToken(CLIENT_EMAIL, PRIVATE_KEY);

    // ── Build the row ───────────────────────────────────────────────────────
    const now = new Date().toLocaleString('en-US', { timeZone: 'America/New_York' });

    const row = [
      now,                                    // Timestamp (ET)
      lead.firstName  || '',                  // First Name
      lead.lastName   || '',                  // Last Name
      lead.phone      || '',                  // Phone
      lead.email      || '',                  // Email
      lead.state      || '',                  // State
      lead.zip        || '',                  // ZIP
      lead.age        || '',                  // Age
      lead.dob        || '',                  // Date of Birth
      lead.driver     || '',                  // Driver Type
      lead.beneficiary || '',                 // Beneficiary
      lead.uq1        || '',                  // Unlock Q1
      lead.uq2        || '',                  // Unlock Q2
      lead.uq3        || '',                  // Unlock Q3
      lead.scheduledDate  || '',              // Scheduled Date (if booked)
      lead.scheduledTime  || '',              // Scheduled Time (if booked)
      lead.type       || 'form_submit',       // Lead Type
    ];

    // ── Append to sheet ─────────────────────────────────────────────────────
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/Sheet1!A1:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ values: [row] }),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Sheets API error: ${err}`);
    }

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error('submit-lead error:', err);
    return res.status(500).json({ error: err.message });
  }
}

// ── Minimal Google JWT helper (no external packages needed) ─────────────────
async function getGoogleToken(clientEmail, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: clientEmail,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const message = `${enc(header)}.${enc(payload)}`;

  // Import the private key
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToBuffer(privateKey),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(message)
  );

  const jwt = `${message}.${Buffer.from(signature).toString('base64url')}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });

  const data = await tokenRes.json();
  if (!data.access_token) throw new Error('Failed to get Google token: ' + JSON.stringify(data));
  return data.access_token;
}

function pemToBuffer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const binary = atob(b64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
  return buffer.buffer;
}
