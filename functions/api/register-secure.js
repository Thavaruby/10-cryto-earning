const ITERATIONS = 100000;

const DEVICE_COOKIE_NAME = "mcf_device";
const DEVICE_TOKEN_BYTES = 32;
const DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 2; // 2 years


/* =====================================================
   BASE64
===================================================== */

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


/* =====================================================
   SHA-256
===================================================== */

async function sha256Base64Url(value) {

    const encoder =
        new TextEncoder();

    const digest =
        await crypto.subtle.digest(
            "SHA-256",
            encoder.encode(value)
        );

    return toBase64Url(
        new Uint8Array(digest)
    );
}


/* =====================================================
   PASSWORD HASH
===================================================== */

async function hashPassword(
    password,
    salt
) {

    const encoder =
        new TextEncoder();

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

    return new Uint8Array(
        derivedBits
    );
}


/* =====================================================
   EMAIL VALIDATION
===================================================== */

function isValidEmail(email) {

    if (email.length > 254) {
        return false;
    }

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);
}


/* =====================================================
   COOKIE
===================================================== */

function getCookie(
    request,
    name
) {

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
            cookie.slice(
                0,
                index
            ).trim();

        if (key !== name) {
            continue;
        }

        try {

            return decodeURIComponent(
                cookie
                    .slice(index + 1)
                    .trim()
            );

        } catch {

            return null;
        }
    }

    return null;
}


/* =====================================================
   DEVICE TOKEN
===================================================== */

function createDeviceToken() {

    return toBase64Url(
        crypto.getRandomValues(
            new Uint8Array(
                DEVICE_TOKEN_BYTES
            )
        )
    );
}


/* =====================================================
   JSON RESPONSE
===================================================== */

function jsonResponse(
    data,
    status = 200,
    extraHeaders = {}
) {

    const headers =
        new Headers({
            "Content-Type":
                "application/json",

            "Cache-Control":
                "no-store"
        });

    for (
        const [key, value]
        of Object.entries(extraHeaders)
    ) {

        headers.set(
            key,
            value
        );
    }

    return new Response(
        JSON.stringify(data),
        {
            status,
            headers
        }
    );
}


/* =====================================================
   REGISTER
===================================================== */

export async function onRequestPost(
    context
) {

    try {

        /* =================================================
           REQUEST JSON
        ================================================= */

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


        /* =================================================
           INPUT
        ================================================= */

        const email =
            String(
                data?.email || ""
            )
                .trim()
                .toLowerCase();

        const password =
            String(
                data?.password || ""
            );


        /* =================================================
           REQUIRED FIELDS
        ================================================= */

        if (
            !email ||
            !password
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Email and password are required"
                },
                400
            );
        }


        /* =================================================
           EMAIL VALIDATION
        ================================================= */

        if (!isValidEmail(email)) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Please enter a valid email address"
                },
                400
            );
        }


        /* =================================================
           PASSWORD VALIDATION
        ================================================= */

        if (
            password.length < 8 ||
            password.length > 1024
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Password must contain between 8 and 1024 characters"
                },
                400
            );
        }


        /* =================================================
           DEVICE TOKEN
        ================================================= */

        /*
         * Existing device keeps its existing token.
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

            deviceToken =
                createDeviceToken();

            newDeviceCookie = true;
        }


        const deviceIdHash =
            await sha256Base64Url(
                deviceToken
            );


        /* =================================================
           DATABASE
        ================================================= */

        const db =
            context.env.DB.withSession(
                "first-primary"
            );


        /* =================================================
           EXISTING EMAIL CHECK
        ================================================= */

        const existingUser =
            await db
                .prepare(
                    `SELECT
                        id
                     FROM users
                     WHERE email = ?`
                )
                .bind(
                    email
                )
                .first();


        if (existingUser) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Email already registered"
                },
                409
            );
        }


        /* =================================================
           EXISTING DEVICE CHECK
        ================================================= */

        const existingDevice =
            await db
                .prepare(
                    `SELECT
                        user_id
                     FROM user_devices
                     WHERE device_id_hash = ?
                     LIMIT 1`
                )
                .bind(
                    deviceIdHash
                )
                .first();


        if (existingDevice) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "This device already has an account."
                },
                409
            );
        }


        /* =================================================
           PASSWORD HASH
        ================================================= */

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


        /* =================================================
           ATOMIC USER + DEVICE CREATION
        ================================================= */

        /*
         * Both operations are executed in one D1 batch.
         *
         * If either INSERT fails, the batch is rolled back.
         *
         * The second statement obtains the newly-created
         * user's ID through the unique email address.
         */

        try {

            await db.batch([

                db.prepare(
                    `INSERT INTO users
                    (
                        email,
                        password_hash,
                        balance
                    )
                    VALUES (?, ?, 0)`
                ).bind(
                    email,
                    storedHash
                ),

                db.prepare(
                    `INSERT INTO user_devices
                    (
                        user_id,
                        device_id_hash
                    )
                    SELECT
                        id,
                        ?
                    FROM users
                    WHERE email = ?`
                ).bind(
                    deviceIdHash,
                    email
                )

            ]);

        } catch (error) {

            const errorMessage =
                error instanceof Error
                    ? error.message
                    : "";

            /*
             * A UNIQUE constraint can be triggered
             * by another registration request arriving
             * concurrently.
             */

            if (
                errorMessage
                    .toLowerCase()
                    .includes("unique")
            ) {

                /*
                 * Determine whether the conflict is
                 * the email or the device.
                 */

                const conflictingUser =
                    await db
                        .prepare(
                            `SELECT
                                id
                             FROM users
                             WHERE email = ?
                             LIMIT 1`
                        )
                        .bind(
                            email
                        )
                        .first();


                if (conflictingUser) {

                    return jsonResponse(
                        {
                            success: false,
                            error:
                                "Email already registered"
                        },
                        409
                    );
                }


                const conflictingDevice =
                    await db
                        .prepare(
                            `SELECT
                                user_id
                             FROM user_devices
                             WHERE device_id_hash = ?
                             LIMIT 1`
                        )
                        .bind(
                            deviceIdHash
                        )
                        .first();


                if (conflictingDevice) {

                    return jsonResponse(
                        {
                            success: false,
                            error:
                                "This device already has an account."
                        },
                        409
                    );
                }
            }


            console.error(
                "Registration database error:",
                errorMessage ||
                    "Unknown registration error"
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to create account."
                },
                500
            );
        }


        /* =================================================
           RESPONSE COOKIE
        ================================================= */

        const headers = {};


        if (newDeviceCookie) {

            headers["Set-Cookie"] =
                `${DEVICE_COOKIE_NAME}=${encodeURIComponent(deviceToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${DEVICE_COOKIE_MAX_AGE}`;
        }


        /* =================================================
           SUCCESS
        ================================================= */

        return jsonResponse(
            {
                success: true,
                message:
                    "Account created successfully!"
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
                error:
                    "Unable to create account."
            },
            500
        );
    }
}
