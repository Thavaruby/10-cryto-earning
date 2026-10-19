
function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const item of header.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

async function hashToken(token) {
  const bytes = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function isAdmin(request, db) {
  const token = getCookie(request, "session");
  if (!token) return false;

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
    SELECT user_id FROM admins
    WHERE user_id = ? LIMIT 1
  `).bind(session.user_id).first();

  return !!admin;
}

async function ensureSettings(db) {
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
}

async function readSettings(db) {
  await ensureSettings(db);

  const rows = await db.prepare(`
    SELECT setting_key, setting_value
    FROM torox_settings
  `).all();

  const values = Object.fromEntries(
    (rows.results || []).map(r => [
      r.setting_key,
      Number(r.setting_value)
    ])
  );

  return {
    pointsPerUsd: values.points_per_usd ?? 100,
    conversionFeePercent:
      values.conversion_fee_percent ?? 5
  };
}

export async function onRequestGet({ request, env }) {
  try {
    const db = env.DB.withSession("first-primary");

    if (!await isAdmin(request, db)) {
      return json({ success: false, error: "Unauthorized" }, 401);
    }

    const settings = await readSettings(db);
    return json({ success: true, settings });
  } catch (error) {
    console.error("Torox admin settings GET error:", error);
    return json({ success: false, error: "Unable to load settings" }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const db = env.DB.withSession("first-primary");

    if (!await isAdmin(request, db)) {
      return json({ success: false, error: "Unauthorized" }, 401);
    }

    const body = await request.json();
    const pointsPerUsd = Number(body.pointsPerUsd);
    const fee = Number(body.conversionFeePercent);

    if (
      !Number.isFinite(pointsPerUsd) ||
      pointsPerUsd < 1 ||
      pointsPerUsd > 1000000 ||
      !Number.isFinite(fee) ||
      fee < 0 ||
      fee > 50
    ) {
      return json({
        success: false,
        error: "Rate must be 1–1000000; fee must be 0–50%."
      }, 400);
    }

    await ensureSettings(db);

    await db.batch([
      db.prepare(`
        UPDATE torox_settings
        SET setting_value = ?, updated_at = CURRENT_TIMESTAMP
        WHERE setting_key = 'points_per_usd'
      `).bind(String(pointsPerUsd)),
      db.prepare(`
        UPDATE torox_settings
        SET setting_value = ?, updated_at = CURRENT_TIMESTAMP
        WHERE setting_key = 'conversion_fee_percent'
      `).bind(String(fee))
    ]);

    return json({
      success: true,
      settings: { pointsPerUsd, conversionFeePercent: fee }
    });
  } catch (error) {
    console.error("Torox admin settings POST error:", error);
    return json({ success: false, error: "Unable to save settings" }, 500);
  }
}
