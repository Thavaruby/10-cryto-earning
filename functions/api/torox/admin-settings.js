
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
  const result = await db.prepare(`
    SELECT setting_key, setting_value
    FROM torox_settings
    WHERE setting_key IN (
      'points_per_usd',
      'conversion_fee_percent'
    )
  `).all();

  const values = {};

  for (const row of result.results || []) {
    values[row.setting_key] = Number(row.setting_value);
  }

  return {
    pointsPerUsd: values.points_per_usd ?? 100,
    conversionFeePercent: values.conversion_fee_percent ?? 5
  };
}

export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB) return json({ error: "Database unavailable." }, 503);

    const db = env.DB.withSession("first-primary");

    if (!(await checkAdmin(request, db))) {
      return json({ error: "Unauthorized." }, 401);
    }

    await ensureSettings(db);

    return json({
      success: true,
      settings: await readSettings(db)
    });
  } catch (error) {
    console.error("Torox admin settings GET error:", error);
    return json({ error: "Could not load settings." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) return json({ error: "Database unavailable." }, 503);

    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) {
      return json({ error: "Invalid request origin." }, 403);
    }

    const db = env.DB.withSession("first-primary");

    if (!(await checkAdmin(request, db))) {
      return json({ error: "Unauthorized." }, 401);
    }

    const body = await request.json();
    const pointsPerUsd = Number(body.pointsPerUsd);
    const fee = Number(body.conversionFeePercent);

    if (
      !Number.isFinite(pointsPerUsd) ||
      pointsPerUsd < 1 ||
      pointsPerUsd > 1000000
    ) {
      return json({ error: "Points per USD must be between 1 and 1,000,000." }, 400);
    }

    if (
      !Number.isFinite(fee) ||
      fee < 0 ||
      fee > 50
    ) {
      return json({ error: "Fee must be between 0% and 50%." }, 400);
    }

    await ensureSettings(db);

    const now = new Date().toISOString();

    await db.batch([
      db.prepare(`
        INSERT INTO torox_settings
          (setting_key, setting_value, updated_at)
        VALUES ('points_per_usd', ?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET
          setting_value = excluded.setting_value,
          updated_at = excluded.updated_at
      `).bind(String(pointsPerUsd), now),

      db.prepare(`
        INSERT INTO torox_settings
          (setting_key, setting_value, updated_at)
        VALUES ('conversion_fee_percent', ?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET
          setting_value = excluded.setting_value,
          updated_at = excluded.updated_at
      `).bind(String(fee), now)
    ]);

    return json({
      success: true,
      settings: await readSettings(db)
    });
  } catch (error) {
    console.error("Torox admin settings POST error:", error);
    return json({ error: "Could not save settings." }, 500);
  }
}
