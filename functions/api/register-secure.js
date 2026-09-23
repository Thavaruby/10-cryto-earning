const ITERATIONS = 100000;

const DEVICE_COOKIE_NAME = "mcf_device";
const DEVICE_TOKEN_BYTES = 32;
const DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 2; // 2 years

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

async function sha256Base64Url(value) {
    const encoder = new TextEncoder();

    const digest =
        await crypto.subtle.digest(
            "SHA-256",
            encoder.encode(value)
        );

    return toBase64Url(
        new Uint8Array(digest)
    );
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

function isValidEmail(email) {
    if (email.length > 254) {
        return false;
    }

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getCookie(request, name) {
    const cookieHeader =
        request.headers.get("Cookie") || "";

    const cookies =
        cookieHeader.split(";");

    for (const cookie of cookies) {
        const index = cookie.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            cookie.slice(0, index).trim();

        if (key !== name) {
            continue;
        }

        return decodeURIComponent(
            cookie.slice(index + 1).trim()
        );
    }

    return null;
}

function createDeviceToken() {
    return toBase64Url(
        crypto.getRandomValues(
            new Uint8Array(DEVICE_TOKEN_BYTES)
        )
    );
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
            data = await context.request.json();
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

        if (!isValidEmail(email)) {

            return jsonResponse(
                {
                    success: false,
                    error: "Please enter a valid email address"
                },
                400
            );
        }

        if (password.length < 8) {

            return jsonResponse(
                {
                    success: false,
                    error: "Password must contain at least 8 characters"
                },
                400
            );
        }

        /*
         * Existing device gets its existing token.
         * A new browser/device receives a new token.
         */
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
            deviceToken = createDeviceToken();
            newDeviceCookie = true;
        }

        const deviceIdHash =
            await sha256Base64Url(deviceToken);

        const db =
            context.env.DB.withSession("first-primary");

        /*
         * Existing email check.
         */
        const existingUser =
            await db
                .prepare(
                    "SELECT id FROM users WHERE email = ?"
                )
                .bind(email)
                .first();

        if (existingUser) {

            return jsonResponse(
                {
                    success: false,
                    error: "Email already registered"
                },
                409
            );
        }

        /*
         * Device protection:
         *
         * If this device is already linked to an account,
         * a second account cannot be created.
         */
        const existingDevice =
            await db
                .prepare(
                    `SELECT user_id
                     FROM user_devices
                     WHERE device_id_hash = ?
                     LIMIT 1`
                )
                .bind(deviceIdHash)
                .first();

        if (existingDevice) {

            return jsonResponse(
                {
                    success: false,
                    error: "This device already has an account."
                },
                409
            );
        }

        const salt =
            crypto.getRandomValues(
                new Uint8Array(16)
            );

        const passwordHash =
            await hashPassword(
                password,
                salt
            );

        const storedHash =
            `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(passwordHash)}`;

        let userId;

        try {

            /*
             * Create the user first.
             */
            const userResult =
                await db
                    .prepare(
                        `INSERT INTO users
                        (email, password_hash, balance)
                        VALUES (?, ?, 0)
                        RETURNING id`
                    )
                    .bind(
                        email,
                        storedHash
                    )
                    .first();

            if (!userResult?.id) {
                throw new Error(
                    "User creation did not return an ID"
                );
            }

            userId = Number(userResult.id);

            /*
             * Bind this device to the newly created account.
             */
            try {

                await db
                    .prepare(
                        `INSERT INTO user_devices
                        (user_id, device_id_hash)
                        VALUES (?, ?)`
                    )
                    .bind(
                        userId,
                        deviceIdHash
                    )
                    .run();

            } catch (deviceError) {

                /*
                 * Another request may have registered
                 * this same device at almost the same time.
                 *
                 * Remove the just-created account so we
                 * don't leave an unprotected account behind.
                 */
                try {

                    await db
                        .prepare(
                            "DELETE FROM users WHERE id = ?"
                        )
                        .bind(userId)
                        .run();

                } catch (cleanupError) {

                    console.error(
                        "Registration cleanup error:",
                        cleanupError instanceof Error
                            ? cleanupError.message
                            : "Unknown cleanup error"
                    );
                }

                const deviceErrorMessage =
                    deviceError instanceof Error
                        ? deviceError.message
                        : "";

                if (
                    deviceErrorMessage
                        .toLowerCase()
                        .includes("unique")
                ) {

                    return jsonResponse(
                        {
                            success: false,
                            error: "This device already has an account."
                        },
                        409
                    );
                }

                throw deviceError;
            }

        } catch (error) {

            const errorMessage =
                error instanceof Error
                    ? error.message
                    : "";

            /*
             * If the database has a UNIQUE constraint
             * on email, another simultaneous registration
             * can reach the INSERT after the earlier check.
             */
            if (
                errorMessage
                    .toLowerCase()
                    .includes("unique")
            ) {

                return jsonResponse(
                    {
                        success: false,
                        error: "Email already registered"
                    },
                    409
                );
            }

            throw error;
        }

        const headers = {};

        if (newDeviceCookie) {
            headers["Set-Cookie"] =
                `${DEVICE_COOKIE_NAME}=${encodeURIComponent(deviceToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${DEVICE_COOKIE_MAX_AGE}`;
        }

        return jsonResponse(
            {
                success: true,
                message: "Account created successfully!"
            },
            201,
            headers
        );

    } catch (error) {

        console.error(
            "Secure registration error:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return jsonResponse(
            {
                success: false,
                error: "Unable to create account."
            },
            500
        );
    }
}
