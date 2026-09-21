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
   VERIFY PBKDF2 HASH
========================================================= */

async function verifyHash(
    value,
    storedHash
) {

    try {

        const parts =
            storedHash.split("$");


        if (parts.length !== 4) {
            return false;
        }


        const algorithm =
            parts[0];

        const iterations =
            Number(parts[1]);


        /*
         * Strictly require our expected
         * password-hash format.
         */

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


        /*
         * Expected PBKDF2-SHA256 output:
         * 256 bits = 32 bytes.
         */

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
           Reset token
        ------------------------------------------------- */

        const token =
            String(
                data.token || ""
            )
                .trim();


        /* -------------------------------------------------
           New password
        ------------------------------------------------- */

        const password =
            String(
                data.password || ""
            );


        /* -------------------------------------------------
           Basic validation
        ------------------------------------------------- */

        if (
            !email ||
            !token ||
            !password
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid password reset request."
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

        if (email.length > 254) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid password reset request."
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
           Password validation
        ------------------------------------------------- */

        if (
            password.length < 8
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Password must contain at least 8 characters."
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
         * Generic response.
         *
         * Do not reveal whether an email
         * belongs to an account.
         */

        if (!user) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired reset session."
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
                        reset_token_hash,
                        verified_at,
                        used
                    FROM password_resets
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    `
                )
                .bind(user.id)
                .first();


        /* -------------------------------------------------
           Reset record validation
        ------------------------------------------------- */

        if (
            !reset ||
            !reset.reset_token_hash
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired reset session."
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
           Verification must be completed first
        ------------------------------------------------- */

        if (!reset.verified_at) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Please verify your email code first."
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
           Reset token must not already be consumed
           
           used = 1
           → verification completed

           used = 2
           → password reset transaction has consumed it
        ------------------------------------------------- */

        if (
            Number(reset.used) !== 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Your password reset session is no longer valid."
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
           Current Unix time
        ------------------------------------------------- */

        const now =
            Math.floor(
                Date.now() / 1000
            );


        /* -------------------------------------------------
           Reset token expires 10 minutes
           after successful code verification.
        ------------------------------------------------- */

        const verifiedAt =
            Number(
                reset.verified_at
            );


        if (
            !verifiedAt ||
            now >=
                verifiedAt +
                (10 * 60)
        ) {

            await db
                .prepare(
                    `
                    DELETE FROM password_resets
                    WHERE id = ?
                      AND used = 1
                    `
                )
                .bind(reset.id)
                .run();


            return Response.json(
                {
                    success: false,
                    error:
                        "Your password reset session has expired. Please request a new code."
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
           Verify reset token
        ------------------------------------------------- */

        const validToken =
            await verifyHash(
                token,
                reset.reset_token_hash
            );


        if (!validToken) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired reset session."
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
           Create new password salt
        ------------------------------------------------- */

        const salt =
            crypto.getRandomValues(
                new Uint8Array(16)
            );


        /* -------------------------------------------------
           Hash new password
        ------------------------------------------------- */

        const passwordHash =
            await hashValue(
                password,
                salt
            );


        /* -------------------------------------------------
           Store password hash
        ------------------------------------------------- */

        const storedHash =
            `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(passwordHash)}`;


        /*
         * =================================================
         * ATOMIC PASSWORD RESET
         * =================================================
         *
         * Step 1:
         *
         * Change reset record:
         *
         *     used 1 → used 2
         *
         * only if it is still valid.
         *
         * Step 2:
         *
         * Update password.
         *
         * Step 3:
         *
         * Delete reset record.
         *
         * These statements are executed using D1 batch,
         * which provides transactional behavior.
         *
         * A second simultaneous request cannot also change
         * used = 1 → used = 2.
         *
         * Therefore only one request can consume
         * the reset session.
         */


        const resetConsume =
            await db
                .prepare(
                    `
                    UPDATE password_resets
                    SET used = 2
                    WHERE id = ?
                      AND user_id = ?
                      AND used = 1
                      AND verified_at IS NOT NULL
                      AND verified_at > ?
                      AND reset_token_hash = ?
                    `
                )
                .bind(
                    reset.id,
                    user.id,
                    now - (10 * 60),
                    reset.reset_token_hash
                );


        const updatePassword =
            await db
                .prepare(
                    `
                    UPDATE users
                    SET password_hash = ?
                    WHERE id = ?
                      AND EXISTS (
                          SELECT 1
                          FROM password_resets
                          WHERE id = ?
                            AND user_id = ?
                            AND used = 2
                            AND verified_at IS NOT NULL
                            AND verified_at > ?
                            AND reset_token_hash = ?
                      )
                    `
                )
                .bind(
                    storedHash,
                    user.id,
                    reset.id,
                    user.id,
                    now - (10 * 60),
                    reset.reset_token_hash
                );


        const deleteReset =
            await db
                .prepare(
                    `
                    DELETE FROM password_resets
                    WHERE id = ?
                      AND user_id = ?
                      AND used = 2
                    `
                )
                .bind(
                    reset.id,
                    user.id
                );


        /*
         * Execute all three operations as one D1 batch.
         */

        const results =
            await db.batch(
                [
                    resetConsume,
                    updatePassword,
                    deleteReset
                ]
            );


        /* -------------------------------------------------
           Validate transaction results
        ------------------------------------------------- */

        const consumeChanges =
            results[0] &&
            results[0].meta
                ? Number(
                    results[0].meta.changes
                )
                : 0;


        const passwordChanges =
            results[1] &&
            results[1].meta
                ? Number(
                    results[1].meta.changes
                )
                : 0;


        const deleteChanges =
            results[2] &&
            results[2].meta
                ? Number(
                    results[2].meta.changes
                )
                : 0;


        /*
         * All three operations must succeed.
         */

        if (
            consumeChanges !== 1 ||
            passwordChanges !== 1 ||
            deleteChanges !== 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Your password reset session is no longer valid."
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
                    "Password reset successfully."
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
            "Reset password error:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to reset password."
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
