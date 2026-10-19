
const EXPECTED_CURRENCY = "Points";
const TOROX_SOURCE_IP = "44.212.211.226";
const MAX_AMOUNT_POINTS = 1_000_000_000;

async function logToroxReject(env, reason, details = {}) {
  console.warn("[Torox postback rejected]", {
    reason,
    conversion_id: details.conversionId ?? null,
    offer_id: details.offerId ?? null,
    user_id: details.userId ?? null
  });

  try {
    if (!env?.DB) return;

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS torox_postback_rejections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversion_id TEXT,
        offer_id TEXT,
        user_id INTEGER,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();

    await env.DB.prepare(`
      INSERT INTO torox_postback_rejections
        (conversion_id, offer_id, user_id, reason)
      VALUES (?, ?, ?, ?)
    `).bind(
      details.conversionId == null ? null : String(details.conversionId),
      details.offerId == null ? null : String(details.offerId),
      details.userId == null ||
      !Number.isSafeInteger(Number(details.userId))
        ? null
        : Number(details.userId),
      String(reason).slice(0, 200)
    ).run();
  } catch (error) {
    console.error("[Torox rejection log insert failed]", {
      reason: String(error?.message || "D1 insert failed")
    });
  }
}

function reply(value, status = 200) {
  return new Response(value, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function md5(input) {
  const bytes = new TextEncoder().encode(input);
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  const bitLength = bytes.length * 8;

  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(
    paddedLength - 4,
    Math.floor(bitLength / 0x100000000),
    true
  );

  const shifts = [
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
  ];

  const constants = Array.from(
    { length: 64 },
    (_, i) =>
      Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0
  );

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  function rotateLeft(value, amount) {
    return (value << amount) | (value >>> (32 - amount));
  }

  for (let offset = 0; offset < paddedLength; offset += 64) {
    const words = new Uint32Array(16);

    for (let j = 0; j < 16; j++) {
      words[j] = view.getUint32(offset + j * 4, true);
    }

    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let i = 0; i < 64; i++) {
      let f;
      let g;

      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }

      const previousD = d;
      d = c;
      c = b;

      const sum = (a + f + constants[i] + words[g]) >>> 0;
      b = (b + rotateLeft(sum, shifts[i])) >>> 0;
      a = previousD;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  function wordToHex(word) {
    let result = "";
    for (let i = 0; i < 4; i++) {
      result += ((word >>> (i * 8)) & 0xff)
        .toString(16)
        .padStart(2, "0");
    }
    return result;
  }

  return wordToHex(a0) + wordToHex(b0) +
    wordToHex(c0) + wordToHex(d0);
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;

  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

function parsePoints(value) {
  if (
    typeof value !== "string" ||
    !/^-?\d+(?:\.\d+)?$/.test(value)
  ) {
    return null;
  }

  const negative = value.startsWith("-");
  const unsigned = negative ? value.slice(1) : value;
  const [wholeRaw, fractionRaw = ""] = unsigned.split(".");

  if (
    fractionRaw.length > 3 &&
    /[^0]/.test(fractionRaw.slice(3))
  ) {
    return null;
  }

  const whole = Number(wholeRaw);
  const fraction = Number(
    fractionRaw.slice(0, 3).padEnd(3, "0")
  );

  if (!Number.isSafeInteger(whole)) return null;

  const milli = whole * 1000 + fraction;

  if (!Number.isSafeInteger(milli)) return null;
  if (milli === 0) return null;
  if (Math.abs(milli) > MAX_AMOUNT_POINTS * 1000) return null;

  return negative ? -milli : milli;
}

function validText(value, maxLength = 200) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength;
}

function parseToroxPayout(value) {
  if (value === null || value === "") {
    return { valid: true, value: null };
  }

  if (!/^-?\d+(?:\.\d{1,4})?$/.test(value)) {
    return { valid: false, value: null };
  }

  const payout = Number(value);

  if (!Number.isFinite(payout) || Math.abs(payout) > 1000000) {
    return { valid: false, value: null };
  }

  return {
    valid: true,
    value: Math.round(payout * 10000) / 10000
  };
}

async function saveToroxPayout(
  db, conversionId, userId, offerId, payoutUsd
) {
  await db.prepare(`
    INSERT INTO torox_payout_tracking
      (conversion_id, user_id, offer_id, payout_usd, created_at)
    VALUES (?1, ?2, ?3, ?4, ?5)
    ON CONFLICT(conversion_id) DO UPDATE SET
      payout_usd = COALESCE(
        excluded.payout_usd,
        torox_payout_tracking.payout_usd
      )
  `).bind(
    conversionId,
    userId,
    offerId,
    payoutUsd,
    new Date().toISOString()
  ).run();
}

async function findConversion(db, conversionId) {
  return db.prepare(`
    SELECT conversion_id, user_id, offer_id,
           amount_milli, currency_name
    FROM torox_conversions
    WHERE conversion_id = ?1
  `).bind(conversionId).first();
}

function matchesConversion(
  existing, userId, offerId, amountMilli, currencyName
) {
  return existing &&
    Number(existing.user_id) === userId &&
    String(existing.offer_id) === offerId &&
    Number(existing.amount_milli) === amountMilli &&
    existing.currency_name === currencyName;
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const params = url.searchParams;

  let conversionId = params.get("id");
  let offerId = params.get("oid");
  let userIdRaw = params.get("user_id");

  try {
    if (!env.DB || !env.TOROX_APP_KEY) {
      console.error("[Torox postback] Missing configuration", {
        dbConfigured: Boolean(env.DB),
        appKeyConfigured: Boolean(env.TOROX_APP_KEY)
      });
      return reply("0", 500);
    }

    const amountRaw = params.get("amount");
    const currencyName = params.get("currency_name");
    const suppliedSignature = (params.get("sig") || "").toLowerCase();

    if (
      !validText(conversionId, 200) ||
      !validText(offerId, 100) ||
      !validText(userIdRaw, 30) ||
      !validText(amountRaw, 30) ||
      !validText(currencyName, 50) ||
      !/^[a-f0-9]{32}$/.test(suppliedSignature)
    ) {
      await logToroxReject(env, "missing_or_invalid_parameters", {
        conversionId, offerId,
        userId: userIdRaw && /^[1-9]\d*$/.test(userIdRaw)
          ? Number(userIdRaw)
          : null
      });
      return reply("0");
    }

    if (!/^[1-9]\d*$/.test(userIdRaw)) {
      await logToroxReject(env, "invalid_user_id_format", {
        conversionId, offerId
      });
      return reply("0");
    }

    const userId = Number(userIdRaw);

    if (!Number.isSafeInteger(userId)) {
      await logToroxReject(env, "unsafe_user_id", {
        conversionId, offerId
      });
      return reply("0");
    }

    const expectedCurrency =
      env.TOROX_CURRENCY_NAME || EXPECTED_CURRENCY;

    if (currencyName !== expectedCurrency) {
      await logToroxReject(env, "currency_mismatch", {
        conversionId, offerId, userId
      });
      return reply("0");
    }

    const amountMilli = parsePoints(amountRaw);

    if (amountMilli === null) {
      await logToroxReject(env, "invalid_amount", {
        conversionId, offerId, userId
      });
      return reply("0");
    }

    // Keep source IP verification enabled.
    const sourceIp = request.headers.get("CF-Connecting-IP");

    if (sourceIp !== TOROX_SOURCE_IP) {
      await logToroxReject(env, "source_ip_mismatch", {
        conversionId, offerId, userId
      });
      return reply("0", 403);
    }

    const expectedSignature = md5(
      `${offerId}-${userIdRaw}-${env.TOROX_APP_KEY}`
    );

    if (!constantTimeEqual(suppliedSignature, expectedSignature)) {
      await logToroxReject(env, "signature_mismatch", {
        conversionId, offerId, userId
      });
      return reply("0");
    }

    // Torox test: acknowledge without crediting a real user.
    if (
      params.get("event") === "Test" &&
      params.get("o_name") === "Postback Tester"
    ) {
      console.log("[Torox postback] Test request acknowledged", {
        conversionId, offerId, userId
      });
      return reply("1");
    }

    const payoutInfo = parseToroxPayout(params.get("payout"));

    if (!payoutInfo.valid) {
      await logToroxReject(env, "invalid_payout", {
        conversionId, offerId, userId
      });
      return reply("0");
    }

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS torox_payout_tracking (
        conversion_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        offer_id TEXT NOT NULL,
        payout_usd REAL,
        created_at TEXT NOT NULL
      )
    `).run();

    const existing = await findConversion(env.DB, conversionId);

    if (existing) {
      const matches = matchesConversion(
        existing, userId, offerId, amountMilli, currencyName
      );

      if (!matches) {
        await logToroxReject(env, "duplicate_conversion_mismatch", {
          conversionId, offerId, userId
        });
      }

      if (matches) {
        await saveToroxPayout(
          env.DB, conversionId, userId, offerId, payoutInfo.value
        );
      }

      return reply(matches ? "1" : "0");
    }

    const user = await env.DB.prepare(
      "SELECT id FROM users WHERE id = ?1 LIMIT 1"
    ).bind(userId).first();

    if (!user) {
      await logToroxReject(env, "user_not_found", {
        conversionId, offerId, userId
      });
      return reply("0");
    }

    const now = new Date().toISOString();

    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO torox_conversions
          (conversion_id, user_id, offer_id, amount_milli,
           currency_name, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
      `).bind(
        conversionId, userId, offerId, amountMilli, currencyName, now
      ),

      env.DB.prepare(`
        INSERT INTO torox_points_accounts
          (user_id, balance_milli, updated_at)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(user_id) DO UPDATE SET
          balance_milli =
            torox_points_accounts.balance_milli + excluded.balance_milli,
          updated_at = excluded.updated_at
      `).bind(userId, amountMilli, now),

      env.DB.prepare(`
        INSERT INTO torox_points_ledger
          (conversion_id, user_id, delta_milli, event_type, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
      `).bind(
        conversionId,
        userId,
        amountMilli,
        amountMilli < 0 ? "reversal" : "credit",
        now
      ),

      env.DB.prepare(`
        INSERT INTO torox_payout_tracking
          (conversion_id, user_id, offer_id, payout_usd, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(conversion_id) DO UPDATE SET
          payout_usd = COALESCE(
            excluded.payout_usd,
            torox_payout_tracking.payout_usd
          )
      `).bind(
        conversionId, userId, offerId, payoutInfo.value, now
      )
    ]);

    console.log("[Torox postback] Credit recorded", {
      conversionId, offerId, userId, amountMilli, currencyName
    });

    return reply("1");
  } catch (error) {
    console.error("[Torox postback] Processing exception", {
      errorName: error instanceof Error ? error.name : "UnknownError",
      errorMessage: error instanceof Error
        ? error.message
        : "Unknown error"
    });

    // Persist the failure reason; logger failure must not mask the error.
    await logToroxReject(env, "processing_exception", {
      conversionId, offerId,
      userId: userIdRaw && /^[1-9]\d*$/.test(userIdRaw)
        ? Number(userIdRaw)
        : null
    });

    // Acknowledge only if this exact conversion was already recorded.
    try {
      const amountRaw = params.get("amount");
      const currencyName = params.get("currency_name");

      if (
        env.DB &&
        validText(conversionId, 200) &&
        /^[1-9]\d*$/.test(userIdRaw || "")
      ) {
        const userId = Number(userIdRaw);
        const amountMilli = parsePoints(amountRaw);

        if (Number.isSafeInteger(userId) && amountMilli !== null) {
          const existing = await findConversion(env.DB, conversionId);

          if (
            matchesConversion(
              existing, userId, offerId, amountMilli, currencyName
            )
          ) {
            return reply("1");
          }
        }
      }
    } catch {
      // Do not expose internal database errors to the caller.
    }

    return reply("0", 500);
  }
}
