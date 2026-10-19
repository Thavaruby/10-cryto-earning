
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=");
  }

  return null;
}

async function hashToken(token) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  return Array.from(new Uint8Array(hash))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function checkAdmin(request, db) {
  const token = getCookie(request, "session");

  if (!token || token.length > 512) return false;

  const tokenHash = await hashToken(token);

  const session = await db.prepare(`
    SELECT user_id
    FROM sessions
    WHERE token_hash = ?
      AND expires_at > CURRENT_TIMESTAMP
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session) return false;

  const admin = await db.prepare(`
    SELECT user_id
    FROM admins
    WHERE user_id = ?
    LIMIT 1
  `).bind(session.user_id).first();

  return Boolean(admin);
}

export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) {
      return json({ error: "Database unavailable." }, 503);
    }

    const db = env.DB.withSession("first-primary");

    if (!(await checkAdmin(request, db))) {
      return json({ error: "Unauthorized." }, 401);
    }

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS torox_payout_tracking (
        conversion_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        offer_id TEXT NOT NULL,
        payout_usd REAL,
        created_at TEXT NOT NULL
      )
    `).run();

    const result = await db.prepare(`
      SELECT
        COUNT(*) AS totalConversions,
        COUNT(payout_usd) AS knownPayouts,
        SUM(CASE WHEN payout_usd IS NULL THEN 1 ELSE 0 END)
          AS missingPayouts,
        COALESCE(SUM(payout_usd), 0) AS revenueUsd
      FROM torox_payout_tracking
    `).first();

    const redemption = await db.prepare(`
      SELECT
        COUNT(*) AS totalRedemptions,
        COALESCE(SUM(btc_sats), 0) AS totalSats
      FROM torox_points_redemptions
    `).first();

    const revenue = Number(result?.revenueUsd || 0);
    const known = Number(result?.knownPayouts || 0);
    const missing = Number(result?.missingPayouts || 0);
    const total = Number(result?.totalConversions || 0);
    const sats = Number(redemption?.totalSats || 0);

    // BTC value is intentionally not estimated here:
    // historical redemptions need their recorded BTC price
    // to calculate a reliable USD cost.
    return json({
      success: true,
      revenueUsd: revenue,
      knownPayouts: known,
      missingPayouts: missing,
      totalTrackedConversions: total,
      totalRedemptions: Number(redemption?.totalRedemptions || 0),
      totalConvertedSats: sats,
      profitUsd: null,
      profitNote:
        "Profit requires the USD value of BTC at each redemption. " +
        "Missing payout records are unknown, not zero revenue."
    });
  } catch (error) {
    console.error("Torox profit report error:", error);
    return json({ error: "Could not load Torox profit report." }, 500);
  }
}
