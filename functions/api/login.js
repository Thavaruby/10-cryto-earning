const ITERATIONS = 100000;

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const LOCKOUT_MS = LOCKOUT_MINUTES * 60 * 1000;

const DEVICE_COOKIE_NAME = "mcf_device";
const DEVICE_TOKEN_BYTES = 32;
const DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 2;


function fromBase64(base64) {
    const binary = atob(base64);

    return Uint8Array.from(
        binary,
        char => char.charCodeAt(0)
    );
}


function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}


function toBase64Url(bytes) {
    return toBase64(bytes)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}


async function hashPassword(password, salt) {
    const encoder = new TextEncoder();

    const keyMaterial =
        await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );

    const derivedBits =
        await crypto.subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: ITERATIONS,
                hash: "SHA-256"
            },
            keyMaterial,
            256
        );

    return new Uint8Array(derivedBits);
}


function constantTimeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    let result = 0;

    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }

    return result === 0;
}


async function hashSessionToken(token) {
    const data =
        new TextEncoder().encode(token);

    const hash =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    return Array.from(
        new Uint8Array(hash)
    )
        .map(byte =>
            byte.toString(16).padStart(2, "0")
        )
        .join("");
}


async function hashDeviceToken(token) {
    const data =
        new TextEncoder().encode(token);

    const hash =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    return toBase64Url(
        new Uint8Array(hash)
    );
}


function createDeviceToken() {
    return toBase64Url(
        crypto.getRandomValues(
            new Uint8Array(DEVICE_TOKEN_BYTES)
        )
    );
}


function getCookie(request, name) {
    const cookieHeader =
        request.headers.get("Cookie") || "";

    const cookies =
        cookieHeader.split(";");

    for (const cookie of cookies) {

        const index =
            cookie.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            cookie.slice(0, index).trim();

        if (key !== name) {
            continue;
        }

        try {

            return decodeURIComponent(
                cookie.slice(index + 1).trim()
            );

        } catch {

            return null;
        }
    }

    return null;
}


function jsonResponse(
    data,
    status = 200,
    extraHeaders = {}
) {
    const headers = new Headers({
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    });

    for (const [key, value] of Object.entries(extraHeaders)) {
        headers.set(key, value);
    }

    return new Response(
        JSON.stringify(data),
        {
            status,
            headers
        }
    );
}


export async function onRequestPost(context) {

    try {

        let data;

        try {

            data =
                await context.request.json();

        } catch {

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid request"
                },
                400
            );
        }


        const email =
            String(data?.email || "")
                .trim()
                .toLowerCase();


        const password =
            String(data?.password || "");


        if (!email || !password) {

            return jsonResponse(
                {
                    success: false,
                    error: "Email and password are required"
                },
                400
            );
        }


        if (
            email.length > 254 ||
            password.length > 1024
        ) {

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }


        const db =
            context.env.DB.withSession("first-primary");


        const now =
            Date.now();


        // ---------------------------------------------------------
        // LOGIN LOCKOUT CHECK
        // ---------------------------------------------------------

        const attemptRecord =
            await db
                .prepare(
                    `SELECT
                        email,
                        failed_attempts,
                        locked_until
                     FROM login_attempts
                     WHERE email = ?`
                )
                .bind(email)
                .first();


        if (
            attemptRecord &&
            Number(attemptRecord.locked_until || 0) > now
        ) {

            return jsonResponse(
                {
                    success: false,
                    error: "Too many failed login attempts. Please try again later."
                },
                429,
                {
                    "Retry-After":
                        String(
                            Math.ceil(
                                (
                                    Number(
                                        attemptRecord.locked_until
                                    ) - now
                                ) / 1000
                            )
                        )
                }
            );
        }


        // ---------------------------------------------------------
        // FIND USER
        // ---------------------------------------------------------

        const user =
            await db
                .prepare(
                    `SELECT
                        id,
                        email,
                        password_hash,
                        balance
                     FROM users
                     WHERE email = ?`
                )
                .bind(email)
                .first();


        // ---------------------------------------------------------
        // INVALID USER
        // ---------------------------------------------------------

        if (
            !user ||
            !user.password_hash
        ) {

            await recordFailedLogin(
                db,
                email,
                now
            );

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }


        // ---------------------------------------------------------
        // PASSWORD HASH PARSING
        // ---------------------------------------------------------

        let parts;
        let salt;
        let storedHash;


        try {

            parts =
                String(user.password_hash)
                    .split("$");


            if (parts.length !== 4) {

                throw new Error(
                    "Invalid password hash format"
                );
            }


            salt =
                fromBase64(parts[2]);


            storedHash =
                fromBase64(parts[3]);


            if (
                salt.length === 0 ||
                storedHash.length === 0
            ) {

                throw new Error(
                    "Invalid password hash data"
                );
            }

        } catch {

            await recordFailedLogin(
                db,
                email,
                now
            );

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }


        // ---------------------------------------------------------
        // PASSWORD VERIFICATION
        // ---------------------------------------------------------

        let calculatedHash;


        try {

            calculatedHash =
                await hashPassword(
                    password,
                    salt
                );

        } catch {

            await recordFailedLogin(
                db,
                email,
                now
            );

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }


        if (
            !constantTimeEqual(
                calculatedHash,
                storedHash
            )
        ) {

            await recordFailedLogin(
                db,
                email,
                now
            );

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }


        // ---------------------------------------------------------
        // SUCCESSFUL LOGIN
        // ---------------------------------------------------------

        await db
            .prepare(
                `DELETE FROM login_attempts
                 WHERE email = ?`
            )
            .bind(email)
            .run();


        // ---------------------------------------------------------
        // DEVICE BINDING
        // ---------------------------------------------------------

        let deviceToken =
            getCookie(
                context.request,
                DEVICE_COOKIE_NAME
            );


        let newDeviceCookie = false;


        if (
            !deviceToken ||
            deviceToken.length < 40 ||
            deviceToken.length > 200
        ) {

            deviceToken =
                createDeviceToken();

            newDeviceCookie = true;
        }


        const deviceIdHash =
            await hashDeviceToken(
                deviceToken
            );


        /*
         * If this browser/device has no device record yet,
         * bind it to the account that successfully logged in.
         *
         * We do NOT block another existing account here.
         *
         * Step 1 registration protection is handled by
         * register-secure.js.
         *
         * Step 2 will later add device-level claim protection.
         */
        const existingDevice =
            await db
                .prepare(
                    `SELECT
                        id,
                        user_id
                     FROM user_devices
                     WHERE device_id_hash = ?
                     LIMIT 1`
                )
                .bind(deviceIdHash)
                .first();


        if (!existingDevice) {

            try {

                await db
                    .prepare(
                        `INSERT INTO user_devices
                        (
                            user_id,
                            device_id_hash
                        )
                        VALUES (?, ?)`
                    )
                    .bind(
                        user.id,
                        deviceIdHash
                    )
                    .run();

            } catch (deviceError) {

                const deviceErrorMessage =
                    deviceError instanceof Error
                        ? deviceError.message
                        : "Unknown device binding error";

                /*
                 * A concurrent request may have inserted
                 * the same device between SELECT and INSERT.
                 *
                 * Login itself remains successful.
                 */
                if (
                    !deviceErrorMessage
                        .toLowerCase()
                        .includes("unique")
                ) {

                    console.error(
                        "Device binding error:",
                        deviceErrorMessage
                    );
                }
            }
        }


        // ---------------------------------------------------------
        // GENERATE SECURE SESSION TOKEN
        // ---------------------------------------------------------

        const randomBytes =
            crypto.getRandomValues(
                new Uint8Array(32)
            );


        const sessionToken =
            Array.from(randomBytes)
                .map(byte =>
                    byte.toString(16).padStart(2, "0")
                )
                .join("");


        const tokenHash =
            await hashSessionToken(
                sessionToken
            );


        const expiresAt =
            new Date(
                Date.now() +
                7 * 24 * 60 * 60 * 1000
            ).toISOString();


        await db
            .prepare(
                `INSERT INTO sessions
                (
                    user_id,
                    token_hash,
                    expires_at
                )
                VALUES (?, ?, ?)`
            )
            .bind(
                user.id,
                tokenHash,
                expiresAt
            )
            .run();


        // ---------------------------------------------------------
        // RESPONSE
        // ---------------------------------------------------------

        const headers =
            new Headers();

        headers.set(
            "Content-Type",
            "application/json"
        );

        headers.set(
            "Cache-Control",
            "no-store"
        );


        /*
         * Session cookie.
         */
        headers.append(
            "Set-Cookie",
            `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
        );


        /*
         * Device cookie.
         *
         * Only send a new device cookie when the browser
         * did not already have one.
         */
        if (newDeviceCookie) {

            headers.append(
                "Set-Cookie",
                `${DEVICE_COOKIE_NAME}=${encodeURIComponent(deviceToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${DEVICE_COOKIE_MAX_AGE}`
            );
        }


        return new Response(
            JSON.stringify(
                {
                    success: true,
                    message: "Login successful!"
                }
            ),
            {
                status: 200,
                headers
            }
        );


    } catch (error) {

        console.error(
            "LOGIN ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return jsonResponse(
            {
                success: false,
                error: "Internal server error"
            },
            500
        );
    }
}


// =============================================================
// FAILED LOGIN TRACKING
// =============================================================

async function recordFailedLogin(
    db,
    email,
    now
) {

    const existing =
        await db
            .prepare(
                `SELECT
                    failed_attempts,
                    locked_until
                 FROM login_attempts
                 WHERE email = ?`
            )
            .bind(email)
            .first();


    let failedAttempts =
        Number(
            existing?.failed_attempts || 0
        );


    let lockedUntil =
        Number(
            existing?.locked_until || 0
        );


    if (
        lockedUntil > 0 &&
        lockedUntil <= now
    ) {

        failedAttempts = 0;
        lockedUntil = 0;
    }


    failedAttempts++;


    if (
        failedAttempts >=
        MAX_FAILED_ATTEMPTS
    ) {

        lockedUntil =
            now + LOCKOUT_MS;
    }


    await db
        .prepare(
            `INSERT INTO login_attempts
                (
                    email,
                    failed_attempts,
                    locked_until,
                    updated_at
                )
             VALUES (?, ?, ?, ?)
             ON CONFLICT(email)
             DO UPDATE SET
                failed_attempts = excluded.failed_attempts,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at`
        )
        .bind(
            email,
            failedAttempts,
            lockedUntil,
            now
        )
        .run();
}
