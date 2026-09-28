const ITERATIONS = 100000;


/* =========================================================
   Uint8Array → Base64
========================================================= */

function toBase64(bytes) {

    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}


/* =========================================================
   Base64 → Uint8Array
========================================================= */

function fromBase64(base64) {

    const binary =
        atob(base64);

    return Uint8Array.from(
        binary,
        char => char.charCodeAt(0)
    );
}


/* =========================================================
   PBKDF2 HASH
========================================================= */

async function hashValue(value, salt) {

    const encoder =
        new TextEncoder();

    const keyMaterial =
        await crypto.subtle.importKey(
            "raw",
            encoder.encode(value),
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


/* =========================================================
   BASE64URL
========================================================= */

function base64Url(bytes) {

    return toBase64(bytes)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}


/* =========================================================
   VERIFY PBKDF2 HASH
========================================================= */

async function verifyHash(
    value,
    storedHash
) {

    try {

        if (
            typeof storedHash !== "string" ||
            !storedHash
        ) {
            return false;
        }


        const parts =
            storedHash.split("$");


        if (parts.length !== 4) {
            return false;
        }


        const algorithm =
            parts[0];

        const iterations =
            Number(parts[1]);


        if (
            algorithm !== "pbkdf2" ||
            iterations !== ITERATIONS
        ) {
            return false;
        }


        const salt =
            fromBase64(parts[2]);

        const expectedHash =
            fromBase64(parts[3]);


        if (
            salt.length !== 16 ||
            expectedHash.length !== 32
        ) {
            return false;
        }


        const actualHash =
            await hashValue(
                value,
                salt
            );


        if (
            actualHash.length !==
            expectedHash.length
        ) {
            return false;
        }


        /*
         * Constant-time comparison.
         */

        let difference = 0;


        for (
            let i = 0;
            i < actualHash.length;
            i++
        ) {

            difference |=
                actualHash[i] ^
                expectedHash[i];
        }


        return difference === 0;

    } catch {

        return false;
    }
}


/* =========================================================
   MAIN
========================================================= */

export async function onRequestPost(
    context
) {

    try {

        /* -------------------------------------------------
           Parse request
        ------------------------------------------------- */

        const data =
            await context.request.json();


        /* -------------------------------------------------
           Normalize email
        ------------------------------------------------- */

        const email =
            String(
                data.email || ""
            )
                .trim()
                .toLowerCase();


        /* -------------------------------------------------
           Verification code
        ------------------------------------------------- */

        const code =
            String(
                data.code || ""
            )
                .trim();


        /* -------------------------------------------------
           Basic validation
        ------------------------------------------------- */

        if (
            !email ||
            !code
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Email and verification code are required."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Email length protection
        ------------------------------------------------- */

        if (
            email.length > 254
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid verification request."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Strict 6-digit code validation
        ------------------------------------------------- */

        if (
            !/^\d{6}$/.test(code)
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid verification code."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           D1 primary session
        ------------------------------------------------- */

        const db =
            context.env.DB.withSession(
                "first-primary"
            );


        /* -------------------------------------------------
           Find user
        ------------------------------------------------- */

        const user =
            await db
                .prepare(
                    `
                    SELECT id
                    FROM users
                    WHERE email = ?
                    LIMIT 1
                    `
                )
                .bind(email)
                .first();


        /*
         * Generic response prevents
         * account enumeration.
         */

        if (!user) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired verification code."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Find latest reset record
        ------------------------------------------------- */

        const reset =
            await db
                .prepare(
                    `
                    SELECT
                        id,
                        code_hash,
                        expires_at,
                        attempts,
                        used
                    FROM password_resets
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    `
                )
                .bind(user.id)
                .first();


        if (
            !reset ||
            !reset.code_hash
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired verification code."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Code can only be used once
           
           used = 0
           → verification pending

           used = 1
           → verification completed
        ------------------------------------------------- */

        if (
            Number(reset.used) === 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This verification code has already been used."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Maximum 5 incorrect attempts
        ------------------------------------------------- */

        if (
            Number(reset.attempts) >= 5
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Too many incorrect attempts. Please request a new code."
                },
                {
                    status: 429,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Current Unix time
        ------------------------------------------------- */

        const now =
            Math.floor(
                Date.now() / 1000
            );


        /* -------------------------------------------------
           Code expires after 10 minutes
        ------------------------------------------------- */

        if (
            now >= Number(reset.expires_at)
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This verification code has expired. Please request a new code."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Verify submitted code
        ------------------------------------------------- */

        const valid =
            await verifyHash(
                code,
                reset.code_hash
            );


        /* -------------------------------------------------
           Invalid code
        ------------------------------------------------- */

        if (!valid) {

            await db
                .prepare(
                    `
                    UPDATE password_resets
                    SET attempts = attempts + 1
                    WHERE id = ?
                      AND used = 0
                      AND attempts < 5
                    `
                )
                .bind(reset.id)
                .run();


            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid verification code."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Create secure one-time reset token
        ------------------------------------------------- */

        const tokenBytes =
            crypto.getRandomValues(
                new Uint8Array(32)
            );


        const resetToken =
            base64Url(tokenBytes);


        /* -------------------------------------------------
           Hash reset token before storing
        ------------------------------------------------- */

        const tokenSalt =
            crypto.getRandomValues(
                new Uint8Array(16)
            );


        const tokenHash =
            await hashValue(
                resetToken,
                tokenSalt
            );


        const storedTokenHash =
            `pbkdf2$${ITERATIONS}$${toBase64(tokenSalt)}$${toBase64(tokenHash)}`;


        /* -------------------------------------------------
           Atomically consume verification code
           
           used:
             0 → 1

           verified_at:
             current timestamp

           reset_token_hash:
             hashed one-time reset token
        ------------------------------------------------- */

        const consumeResult =
            await db
                .prepare(
                    `
                    UPDATE password_resets
                    SET
                        used = 1,
                        verified_at = ?,
                        reset_token_hash = ?
                    WHERE id = ?
                      AND used = 0
                      AND attempts < 5
                      AND expires_at > ?
                    `
                )
                .bind(
                    now,
                    storedTokenHash,
                    reset.id,
                    now
                )
                .run();


        /* -------------------------------------------------
           Concurrent request protection
        ------------------------------------------------- */

        if (
            !consumeResult.meta ||
            Number(
                consumeResult.meta.changes
            ) !== 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This verification code is no longer valid. Please request a new code."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Success
        ------------------------------------------------- */

        return Response.json(
            {
                success: true,
                message:
                    "Verification successful.",
                reset_token:
                    resetToken
            },
            {
                headers: {
                    "Cache-Control":
                        "no-store"
                }
            }
        );


    } catch (error) {

        console.error(
            "Verify reset code error:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to verify the code."
            },
            {
                status: 500,
                headers: {
                    "Cache-Control":
                        "no-store"
                }
            }
        );
    }
}
