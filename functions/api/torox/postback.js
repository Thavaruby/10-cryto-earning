const EXPECTED_CURRENCY = "Points";
const TOROX_SOURCE_IP = "44.212.211.226";
const MAX_AMOUNT_POINTS = 1_000_000_000;

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
    (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0
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
    !/^-?\d+(?:\.\d{1,3})?$/.test(value)
  ) {
    return null;
  }

  const negative = value.startsWith("-");
  const unsigned = negative ? value.slice(1) : value;
  const parts = unsigned.split(".");
  const whole = Number(parts[0]);
  const fraction = Number((parts[1] || "").padEnd(3, "0"));

  if (!Number.isSafeInteger(whole)) return null;

  const milli = whole * 1000 + fraction;
  if (!Number.isSafeInteger(milli)) return null;
  if (milli === 0) return null;
  if (milli > MAX_AMOUNT_POINTS * 1000) return null;

  return negative ? -milli : milli;
}

function validText(value, maxLength = 200) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength;
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
  existing,
  userId,
  offerId,
  amountMilli,
  currencyName
) {
  return existing &&
    Number(existing.user_id) === userId &&
    String(existing.offer_id) === offerId &&
    Number(existing.amount_milli) === amountMilli &&
    existing.currency_name === currencyName;
}

export async function onRequestGet({ request, env }) {
  try {
    if (!env.DB || !env.TOROX_APP_KEY) {
      return reply("0", 500);
    }

    const url = new URL(request.url);
    const params = url.searchParams;

    const conversionId = params.get("id");
    const offerId = params.get("oid");
    const userIdRaw = params.get("user_id");
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
      return reply("0");
    }

    // The user_id must be the numeric users.id from your database.
    if (!/^[1-9]\d*$/.test(userIdRaw)) {
      return reply("0");
    }

    const userId = Number(userIdRaw);
    if (!Number.isSafeInteger(userId)) {
      return reply("0");
    }

    const expectedCurrency = env.TOROX_CURRENCY_NAME || EXPECTED_CURRENCY;
    if (currencyName !== expectedCurrency) {
      return reply("0");
    }

    const amountMilli = parsePoints(amountRaw);
    if (amountMilli === null) {
      return reply("0");
    }

    // Cloudflare must be in front of this Pages endpoint.
    // Verify Torox's actual source IP before production use.
    const sourceIp = request.headers.get("CF-Connecting-IP");
    if (sourceIp !== TOROX_SOURCE_IP) {
      return reply("0", 403);
    }

    const expectedSignature = md5(
      `${offerId}-${userIdRaw}-${env.TOROX_APP_KEY}`
    );

    if (!constantTimeEqual(suppliedSignature, expectedSignature)) {
      return reply("0");
    }

    const existing = await findConversion(env.DB, conversionId);

    if (existing) {
      return reply(
        matchesConversion(
          existing,
          userId,
          offerId,
          amountMilli,
          currencyName
        ) ? "1" : "0"
      );
    }

    const user = await env.DB.prepare(
      "SELECT id FROM users WHERE id = ?1 LIMIT 1"
    ).bind(userId).first();

    if (!user) {
      return reply("0");
    }

    const now = new Date().toISOString();

    // All three database changes are submitted together.
    // The unique conversion ID prevents a repeated credit.
    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO torox_conversions
          (conversion_id, user_id, offer_id, amount_milli,
           currency_name, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
      `).bind(
        conversionId,
        userId,
        offerId,
        amountMilli,
        currencyName,
        now
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
      )
    ]);

    return reply("1");
  } catch (error) {
    // If a concurrent retry inserted this conversion first,
    // acknowledge only when every stored field matches.
    try {
      const url = new URL(request.url);
      const conversionId = url.searchParams.get("id");
      const offerId = url.searchParams.get("oid");
      const userIdRaw = url.searchParams.get("user_id");
      const amountRaw = url.searchParams.get("amount");
      const currencyName = url.searchParams.get("currency_name");

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
              existing,
              userId,
              offerId,
              amountMilli,
              currencyName
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
