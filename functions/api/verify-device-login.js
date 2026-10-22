
const ITERATIONS = 100000;
const DEVICE_COOKIE = "mcf_device";
const CHALLENGE_COOKIE = "mcf_login_challenge";

function jsonResponse(data, status = 200, cookies = []) {
    const headers = new Headers({
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    });

    for (const value of cookies) {
        headers.append("Set-Cookie", value);
    }

    return new Response(JSON.stringify(data), {
        status,
        headers
    });
}

function getCookie(request, name) {
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

function fromBase64(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

async function sha256Hex(value) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(value)
    );

    return Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

async function hashDeviceToken(token) {
    const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(token)
    );

    const bytes = new Uint8Array(digest);
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

async function hashCode(code, salt) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(code),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const result = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        key,
        256
    );

    return new Uint8Array(result);
}

function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a[i] ^ b[i];
    }

    return difference === 0;
}

function clearChallengeCookie() {
    return `${CHALLENGE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

function secureSessionToken() {
    return Array.from(
        crypto.getRandomValues(new Uint8Array(32))
    ).map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function onRequestPost(context) {
    try {
        const data = await context.request.json().catch(() => null);
        const code = String(data?.code || "").trim();

        if (!/^\d{6}$/.test(code)) {
            return jsonResponse({
                success: false,
                error: "Enter the six-digit verification code."
            }, 400);
        }

        const challengeToken = getCookie(
            context.request,
            CHALLENGE_COOKIE
        );

        const deviceToken = getCookie(
            context.request,
            DEVICE_COOKIE
        );

        if (
            !challengeToken ||
            !/^[A-Za-z0-9_-]{43}$/.test(challengeToken) ||
            !deviceToken ||
            !/^[A-Za-z0-9_-]{43}$/.test(deviceToken)
        ) {
            return jsonResponse({
                success: false,
                error: "Verification expired. Please log in again."
            }, 401, [clearChallengeCookie()]);
        }

        const db = context.env.DB.withSession("first-primary");
        const now = Date.now();

        const challengeHash = await sha256Hex(challengeToken);
        const deviceIdHash = await hashDeviceToken(deviceToken);

        const record = await db.prepare(`
            SELECT user_id, code_hash, device_id_hash,
                   expires_at, attempts
            FROM device_login_verifications
            WHERE challenge_hash = ?
            LIMIT 1
        `).bind(challengeHash).first();

        if (!record || Number(record.expires_at) <= now) {
            if (record) {
                await db.prepare(`
                    DELETE FROM device_login_verifications
                    WHERE challenge_hash = ?
                `).bind(challengeHash).run();
            }

            return jsonResponse({
                success: false,
                error: "Verification expired. Please log in again."
            }, 401, [clearChallengeCookie()]);
        }

        if (Number(record.attempts) >= 5) {
            await db.prepare(`
                DELETE FROM device_login_verifications
                WHERE challenge_hash = ?
            `).bind(challengeHash).run();

            return jsonResponse({
                success: false,
                error: "Too many attempts. Please log in again."
            }, 429, [clearChallengeCookie()]);
        }

        if (record.device_id_hash !== deviceIdHash) {
            return jsonResponse({
                success: false,
                error: "Device verification failed. Please log in again."
            }, 403, [clearChallengeCookie()]);
        }

        const parts = String(record.code_hash || "").split("$");

        if (parts.length !== 2) {
            await db.prepare(`
                DELETE FROM device_login_verifications
                WHERE challenge_hash = ?
            `).bind(challengeHash).run();

            return jsonResponse({
                success: false,
                error: "Verification failed. Please request a new code."
            }, 401, [clearChallengeCookie()]);
        }

        let salt;
        let storedHash;

        try {
            salt = fromBase64(parts[0]);
            storedHash = fromBase64(parts[1]);
        } catch {
            return jsonResponse({
                success: false,
                error: "Verification failed. Please request a new code."
            }, 401, [clearChallengeCookie()]);
        }

        if (salt.length !== 16 || storedHash.length !== 32) {
            return jsonResponse({
                success: false,
                error: "Verification failed. Please request a new code."
            }, 401, [clearChallengeCookie()]);
        }

        const calculatedHash = await hashCode(code, salt);

        if (!constantTimeEqual(calculatedHash, storedHash)) {
            const nextAttempts = Number(record.attempts) + 1;

            if (nextAttempts >= 5) {
                await db.prepare(`
                    DELETE FROM device_login_verifications
                    WHERE challenge_hash = ?
                `).bind(challengeHash).run();
            } else {
                await db.prepare(`
                    UPDATE device_login_verifications
                    SET attempts = ?
                    WHERE challenge_hash = ?
                `).bind(nextAttempts, challengeHash).run();
            }

            return jsonResponse({
                success: false,
                error: nextAttempts >= 5
                    ? "Too many attempts. Please log in again."
                    : `Incorrect code. ${5 - nextAttempts} attempt(s) remaining.`
            }, 401, nextAttempts >= 5 ? [clearChallengeCookie()] : []);
        }

        const conflictingDevice = await db.prepare(`
            SELECT user_id
            FROM user_devices
            WHERE device_id_hash = ?
            LIMIT 1
        `).bind(deviceIdHash).first();

        if (
            conflictingDevice &&
            Number(conflictingDevice.user_id) !== Number(record.user_id)
        ) {
            return jsonResponse({
                success: false,
                error: "This device is registered to another account."
            }, 403, [clearChallengeCookie()]);
        }

        const sessionToken = secureSessionToken();
        const sessionHash = await sha256Hex(sessionToken);
        const sessionExpiry = new Date(
            now + 7 * 24 * 60 * 60 * 1000
        ).toISOString();

        
await db.batch([
    db.prepare(`
        UPDATE user_devices
        SET device_id_hash = ?
        WHERE user_id = ?
    `).bind(deviceIdHash, record.user_id),

    // Revoke all previous sessions for this account.
    db.prepare(`
        DELETE FROM sessions
        WHERE user_id = ?
    `).bind(record.user_id),

    // Create a fresh session for the verified device.
    db.prepare(`
        INSERT INTO sessions (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
    `).bind(record.user_id, sessionHash, sessionExpiry),

    // Remove pending verification challenges for this account.
    db.prepare(`
        DELETE FROM device_login_verifications
        WHERE user_id = ?
    `).bind(record.user_id)
]);


        return jsonResponse({
            success: true,
            message: "Device verified. Login successful."
        }, 200, [
            `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
            clearChallengeCookie()
        ]);

    } catch (error) {
        console.error(
            "DEVICE LOGIN VERIFICATION ERROR:",
            error instanceof Error ? error.message : "Unknown error"
        );

        return jsonResponse({
            success: false,
            error: "Unable to verify this device right now."
        }, 500);
    }
}
