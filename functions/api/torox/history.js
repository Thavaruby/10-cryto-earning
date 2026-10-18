
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
  const token = cookie.split(";")
    .map(v => v.trim())
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
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const session = await env.DB.prepare(`
    SELECT user_id, expires_at
    FROM sessions
    WHERE token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (
    !session ||
    !Number.isFinite(Date.parse(session.expires_at)) ||
    Date.parse(session.expires_at) <= Date.now()
  ) {
    return null;
  }

  return Number(session.user_id);
}

export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) {
      return json({ error: "Database unavailable." }, 503);
    }

    const userId = await getUser(request, env);

    if (!userId) {
      return json({ error: "Please log in again." }, 401);
    }

    const result = await env.DB.prepare(`
      SELECT
        id,
        points_milli,
        btc_sats,
        btc_price_usdt,
        created_at
      FROM torox_points_redemptions
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `).bind(userId).all();

    const history = (result.results || []).map(row => ({
      id: row.id,
      points: Number(row.points_milli) / 1000,
      btc: Number(row.btc_sats) / 100000000,
      sats: Number(row.btc_sats),
      btcPriceUSDT: Number(row.btc_price_usdt),
      createdAt: row.created_at
    }));

    return json({
      success: true,
      history
    });
  } catch (error) {
    console.error("Torox history error:", error);
    return json({
      error: "Could not load conversion history."
    }, 500);
  }
}
