
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

    // Include every conversion, even if its payout
    // has not yet been recorded.
    const revenueResult = await db.prepare(`
      SELECT
        COUNT(c.conversion_id) AS totalConversions,

        COUNT(p.conversion_id) AS trackedConversions,

        COUNT(p.payout_usd) AS knownPayouts,

        SUM(
          CASE
            WHEN p.payout_usd IS NULL THEN 1
            ELSE 0
          END
        ) AS missingPayouts,

        COALESCE(SUM(p.payout_usd), 0) AS revenueUsd

      FROM torox_conversions c

      LEFT JOIN torox_payout_tracking p
        ON p.conversion_id = c.conversion_id
    `).first();

    // Calculate the recorded BTC cost using the
    // BTC price stored at each redemption.
    const costResult = await db.prepare(`
      SELECT
        COUNT(*) AS totalRedemptions,

        COALESCE(SUM(btc_sats), 0) AS totalSats,

        COALESCE(
          SUM(
            (btc_sats / 100000000.0) * btc_price_usdt
          ),
          0
        ) AS convertedBtcCostUsd

      FROM torox_points_redemptions
    `).first();

    const totalConversions =
      Number(revenueResult?.totalConversions || 0);

    const trackedConversions =
      Number(revenueResult?.trackedConversions || 0);

    const knownPayouts =
      Number(revenueResult?.knownPayouts || 0);

    const missingPayouts =
      Number(revenueResult?.missingPayouts || 0);

    const revenueUsd =
      Number(revenueResult?.revenueUsd || 0);

    const totalRedemptions =
      Number(costResult?.totalRedemptions || 0);

    const totalConvertedSats =
      Number(costResult?.totalSats || 0);

    const convertedBtcCostUsd =
      Number(costResult?.convertedBtcCostUsd || 0);

    // Do not claim an accurate profit while any
    // conversion has an unknown payout.
    const profitUsd = missingPayouts === 0
      ? revenueUsd - convertedBtcCostUsd
      : null;

    return json({
      success: true,

      totalConversions,
      trackedConversions,
      knownPayouts,
      missingPayouts,

      revenueUsd,

      totalRedemptions,
      totalConvertedSats,
      convertedBtcCostUsd,

      profitUsd,

      profitNote: profitUsd === null
        ? "Profit is not reliable yet. Some conversion payouts are missing or unknown."
        : "Profit is calculated from recorded payouts minus recorded BTC conversion cost."
    });

  } catch (error) {
    console.error("Torox profit report error:", error);

    return json({
      error: "Could not load Torox profit report."
    }, 500);
  }
}
