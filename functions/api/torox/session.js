
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(hash))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");

    if (separator === -1) continue;

    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (key === name) return value;
  }

  return null;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      return jsonResponse({ error: "Database unavailable." }, 500);
    }

    if (!env.TOROX_APP_KEY) {
      return jsonResponse({ error: "Torox is not configured." }, 503);
    }

    const sessionToken = getCookie(request, "session");

    if (!sessionToken || sessionToken.length > 512) {
      return jsonResponse({ error: "Please log in first." }, 401);
    }

    const tokenHash = await sha256Hex(sessionToken);

    const session = await env.DB.prepare(`
      SELECT user_id, expires_at
      FROM sessions
      WHERE token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    if (!session) {
      return jsonResponse({ error: "Invalid session. Please log in again." }, 401);
    }

    const expiry = Date.parse(session.expires_at);

    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      return jsonResponse({ error: "Session expired. Please log in again." }, 401);
    }

    const endpoint =
      "https://api.wall.torox.io/partner/session?placement_id=16999&token=" +
      encodeURIComponent(env.TOROX_APP_KEY);

    const toroxResponse = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        player: {
          uid: String(session.user_id)
        }
      })
    });

    if (!toroxResponse.ok) {
      console.error("Torox session API returned HTTP", toroxResponse.status);
      return jsonResponse({ error: "Torox is temporarily unavailable." }, 502);
    }

    const result = await toroxResponse.json();

    if (
      result.ok !== true ||
      typeof result.wall_url !== "string"
    ) {
      console.error("Torox session response was not accepted.");
      return jsonResponse({ error: "Could not create the Torox session." }, 502);
    }

    let wallUrl;

    try {
      wallUrl = new URL(result.wall_url);
    } catch {
      return jsonResponse({ error: "Invalid Torox response." }, 502);
    }

    if (
      wallUrl.protocol !== "https:" ||
      wallUrl.hostname !== "wall.torox.io"
    ) {
      return jsonResponse({ error: "Invalid Torox offerwall URL." }, 502);
    }

    return jsonResponse({
      ok: true,
      wallUrl: wallUrl.href
    });
  } catch (error) {
    console.error("Torox session error:", error);
    return jsonResponse({ error: "Unable to connect to Torox." }, 500);
  }
}
