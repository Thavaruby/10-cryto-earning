const DEVICE_COOKIE = "mcf_device";
const CHALLENGE_COOKIE = "mcf_login_challenge";

function response(data, status = 200, headers = {}) {
    return Response.json(data, {
        status,
        headers: {
            "Cache-Control": "no-store",
            ...headers
        }
    });
}

function cookie(request, name) {
    const prefix = name + "=";
    const item = (request.headers.get("Cookie") || "")
        .split(";")
        .map(v => v.trim())
        .find(v => v.startsWith(prefix));

    if (!item) return null;

    try {
        return decodeURIComponent(item.slice(prefix.length));
    } catch {
        return null;
    }
}

async function sha256(value) {
    const bytes = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", bytes);

    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function secureToken() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));

    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

export async function onRequestPost(context) {
    const db = context.env.DB.withSession("first-primary");
    const now = Date.now();

    try {
        const data = await context.request.json();
        const code = String(data?.code || "").trim();
        const challenge = cookie(context.request, CHALLENGE_COOKIE);

        if (!challenge || !/^\d{6}$/.test(code)) {
            return response({
                success: false,
                error: "Invalid verification code."
            }, 400);
        }

        const challengeHash = await sha256(challenge);

        const record = await db.prepare(`
            SELECT
                id,
                user_id,
                code_hash,
                device_id_hash,
                expires_at,
                attempts
            FROM device_login_verifications
            WHERE challenge_hash = ?
            LIMIT 1
        `).bind(challengeHash).first();

        if (!record || Number(record.expires_at) <= now) {
            if (record) {
                await db.prepare(`
                    DELETE FROM device_login_verifications
                    WHERE id = ?
                `).bind(record.id).run();
            }

            return response({
                success: false,
                error: "Code expired. Please log in again."
            }, 401, {
                "Set-Cookie":
                    `${CHALLENGE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
            });
        }

        if (Number(record.attempts) >= 5) {
            await db.prepare(`
                DELETE FROM device_login_verifications
                WHERE id = ?
            `).bind(record.id).run();

            return response({
                success: false,
                error: "Too many attempts. Please log in again."
            }, 429);
        }

        const submittedHash = await sha256(code);

        if (submittedHash !== record.code_hash) {
            await db.prepare(`
                UPDATE device_login_verifications
                SET attempts = attempts + 1
                WHERE id = ?
            `).bind(record.id).run();

            return response({
                success: false,
                error: "Incorrect verification code."
            }, 401);
        }

        /*
         * Rotate the account's registered device only
         * after successful email verification.
         */
        const newSession = secureToken();
        const sessionHash = await sha256(newSession);
        const expiresAt = new Date(
            now + 7 * 24 * 60 * 60 * 1000
        ).toISOString();

        /*
         * Recheck the device has not been assigned to
         * a different account since the code was sent.
         */
        const conflictingDevice = await db.prepare(`
            SELECT user_id
            FROM user_devices
            WHERE device_id_hash = ?
            LIMIT 1
        `).bind(record.device_id_hash).first();

        if (
            conflictingDevice &&
            Number(conflictingDevice.user_id) !== Number(record.user_id)
        ) {
            return response({
                success: false,
                error: "This device is registered to another account."
            }, 403);
        }

        /*
         * Perform binding, session creation and challenge
         * deletion together.
         */
        await db.batch([
            db.prepare(`
                UPDATE user_devices
                SET device_id_hash = ?
                WHERE user_id = ?
            `).bind(record.device_id_hash, record.user_id),

            db.prepare(`
                INSERT INTO sessions (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
            `).bind(record.user_id, sessionHash, expiresAt),

            db.prepare(`
                DELETE FROM device_login_verifications
                WHERE user_id = ?
            `).bind(record.user_id)
        ]);

        return response({
            success: true,
            message: "Verification successful."
        }, 200, {
            "Set-Cookie": [
                `session=${newSession}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
                `${CHALLENGE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
            ].join(", ")
        });

    } catch (error) {
        console.error(
            "Device login verification error:",
            error instanceof Error ? error.message : "Unknown error"
        );

        return response({
            success: false,
            error: "Unable to verify login. Please try again."
        }, 500);
    }
}
