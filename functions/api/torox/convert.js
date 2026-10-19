
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

  let decodedToken;
  try {
    decodedToken = decodeURIComponent(token);
  } catch {
    return null;
  }

  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(decodedToken)
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


export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) return json({ error: "Database unavailable." }, 503);

    // Reject cross-origin requests.
    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) {
      return json({ error: "Invalid request origin." }, 403);
    }

    const userId = await getUser(request, env);
    if (!userId) return json({ error: "Please log in again." }, 401);

    const account = await env.DB.prepare(`
      SELECT balance_milli
      FROM torox_points_accounts
      WHERE user_id = ?
      LIMIT 1
    `).bind(userId).first();

    const pointsMilli = Number(account?.balance_milli || 0);

    if (!Number.isSafeInteger(pointsMilli) || pointsMilli <= 0) {
      return json({ error: "You do not have Points to convert." }, 400);
    }

    const btcPrice = await getBtcPrice();

    
const settings = await getToroxSettings(env.DB);
const points = pointsMilli / 1000;

const grossUsd = points / settings.pointsPerUsd;
const feeUsd = grossUsd * settings.feePercent / 100;
const netUsd = grossUsd - feeUsd;

const btcSats = Math.floor(
  (netUsd / btcPrice) * 100000000
);

    if (!Number.isSafeInteger(btcSats) || btcSats < 1) {
      return json({
        error: "Your Points balance is too small to convert into one satoshi."
      }, 400);
    }

    const redemptionId = crypto.randomUUID();
    const now = new Date().toISOString();
    const btcAmount = btcSats / 100000000;

    // D1 batch runs these statements together.
    // The first update succeeds only if the Points balance has not
    // changed since it was read. The following statements depend on
    // SQLite changes(), preventing BTC credit if deduction fails.
    const results = await env.DB.batch([
      env.DB.prepare(`
        UPDATE torox_points_accounts
        SET balance_milli = balance_milli - ?1,
            updated_at = ?2
        WHERE user_id = ?3
          AND balance_milli = ?4
          AND balance_milli >= ?1
      `).bind(pointsMilli, now, userId, pointsMilli),

      env.DB.prepare(`
        INSERT INTO torox_points_redemptions
          (id, user_id, points_milli, btc_sats, btc_price_usdt, created_at)
        SELECT ?1, ?2, ?3, ?4, ?5, ?6
        WHERE changes() = 1
      `).bind(
        redemptionId, userId, pointsMilli, btcSats, btcPrice, now
      ),

      env.DB.prepare(`
        UPDATE users
        SET balance = COALESCE(balance, 0) + ?1
        WHERE id = ?2
          AND changes() = 1
      `).bind(btcAmount, userId)
    ]);

    const deducted = Number(results?.[0]?.meta?.changes || 0);

    if (deducted !== 1) {
      return json({
        error: "Your Points balance changed. Refresh the page and try again."
      }, 409);
    }

    const updatedUser = await env.DB.prepare(`
      SELECT balance FROM users WHERE id = ? LIMIT 1
    `).bind(userId).first();

    const remaining = await env.DB.prepare(`
      SELECT balance_milli
      FROM torox_points_accounts
      WHERE user_id = ?
      LIMIT 1
    `).bind(userId).first();

    return json({
      success: true,
      grossUsd,
feeUsd,
netUsd,
pointsPerUsd: settings.pointsPerUsd,
conversionFeePercent: settings.feePercent,
      message: "Points converted to BTC successfully.",
      convertedPoints: pointsMilli / 1000,
      creditedBTC: btcAmount,
      creditedSats: btcSats,
      btcPriceUSDT: btcPrice,
      remainingPoints: Number(remaining?.balance_milli || 0) / 1000,
      btcBalance: Number(updatedUser?.balance || 0),
      redemptionId
    });
  } catch (error) {
    console.error("Torox conversion error:", error);
    return json({ error: "Conversion failed. Please try again." }, 500);
  }
}
