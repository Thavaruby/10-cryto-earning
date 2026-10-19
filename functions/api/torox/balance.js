
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function getUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.split(";").map(v => v.trim())
    .find(v => v.startsWith("session="))
    ?.slice("session=".length);

  if (!token || token.length > 512) return null;

  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(decodeURIComponent(token))
  );

  const tokenHash = Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  const session = await env.DB.prepare(`
    SELECT user_id, expires_at
    FROM sessions
    WHERE token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session || !Number.isFinite(Date.parse(session.expires_at)) ||
      Date.parse(session.expires_at) <= Date.now()) return null;

  return Number(session.user_id);
}

async function getBtcPrice() {
  const response = await fetch(
    "https://myfaucetcrypto.com/api/converter/crypto-rates",
    {
      headers: { "Accept": "application/json" },
      cf: { cacheTtl: 0 }
    }
  );

  if (!response.ok) {
    throw new Error("BTC price unavailable");
  }

  const data = await response.json();
  const price = Number(data?.rates?.BTC);

  if (!Number.isFinite(price) || price <= 0) {
    throw new Error("Invalid BTC price");
  }

  return price;
}


async function getToroxSettings(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS torox_settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await db.batch([
    db.prepare(`
      INSERT OR IGNORE INTO torox_settings
        (setting_key, setting_value)
      VALUES ('points_per_usd', '100')
    `),
    db.prepare(`
      INSERT OR IGNORE INTO torox_settings
        (setting_key, setting_value)
      VALUES ('conversion_fee_percent', '5')
    `)
  ]);

  const result = await db.prepare(`
    SELECT setting_key, setting_value
    FROM torox_settings
    WHERE setting_key IN (
      'points_per_usd',
      'conversion_fee_percent'
    )
  `).all();

  const settings = {};

  for (const row of result.results || []) {
    settings[row.setting_key] = Number(row.setting_value);
  }

  const pointsPerUsd = settings.points_per_usd;
  const feePercent = settings.conversion_fee_percent;

  if (
    !Number.isFinite(pointsPerUsd) ||
    pointsPerUsd < 1 ||
    !Number.isFinite(feePercent) ||
    feePercent < 0 ||
    feePercent > 50
  ) {
    throw new Error("Invalid Torox conversion settings");
  }

  return { pointsPerUsd, feePercent };
}

      
export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) return json({ error: "Database unavailable." }, 503);

    const userId = await getUser(request, env);
    if (!userId) return json({ error: "Please log in again." }, 401);

    const account = await env.DB.prepare(`
      SELECT balance_milli
      FROM torox_points_accounts
      WHERE user_id = ?
      LIMIT 1
    `).bind(userId).first();

    const pointsMilli = Math.max(0, Number(account?.balance_milli || 0));
    const btcPrice = await getBtcPrice();
    const settings = await getToroxSettings(env.DB);
const points = pointsMilli / 1000;

const grossUsd = points / settings.pointsPerUsd;
const feeUsd = grossUsd * settings.feePercent / 100;
const netUsd = grossUsd - feeUsd;

const btcSats = Math.floor(
  (netUsd / btcPrice) * 100000000
);
    return json({
      success: true,
      points,
      pointsMilli,
      btcPriceUSDT: btcPrice,
      estimatedBTC: btcSats / 100000000,
      estimatedSats: btcSats,
      exchangeRate: `${settings.pointsPerUsd} Points = 1 USD`,
grossUsd,
feeUsd,
netUsd,
conversionFeePercent: settings.feePercent
    });
  } catch (error) {
    console.error("Torox balance error:", error);
    return json({ error: "Could not load Points or BTC price." }, 503);
  }
}
