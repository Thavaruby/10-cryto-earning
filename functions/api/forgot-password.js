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
   PBKDF2 HASH
========================================================= */

async function hashValue(value, salt) {

    const encoder = new TextEncoder();

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

    return new Uint8Array(derivedBits);
}


/* =========================================================
   SECURE RANDOM 6-DIGIT CODE

   Uses rejection sampling instead of:
   random % 1000000

   This avoids modulo bias.
========================================================= */

function generateCode() {

    const MAX =
        0x100000000; // 2^32

    const LIMIT =
        MAX - (MAX % 1000000);

    while (true) {

        const random =
            new Uint32Array(1);

        crypto.getRandomValues(random);

        const value =
            random[0];

        if (value < LIMIT) {

            return String(
                value % 1000000
            ).padStart(6, "0");
        }
    }
}


/* =========================================================
   MAIN
========================================================= */

export async function onRequestPost(context) {

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
            String(data.email || "")
                .trim()
                .toLowerCase();


        /*
         * Basic email length protection.
         */
        if (
            !email ||
            email.length > 254
        ) {

            return Response.json(
                {
                    success: false,
                    error: "Email is required"
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
                    SELECT id, email
                    FROM users
                    WHERE email = ?
                    LIMIT 1
                    `
                )
                .bind(email)
                .first();


        /*
         * IMPORTANT:
         *
         * Do not reveal whether the email exists.
         *
         * This prevents account/email enumeration.
         */

        if (!user) {

            return Response.json(
                {
                    success: true,
                    cooldown: false,
                    message:
                        "If this email is registered, a verification code has been sent."
                },
                {
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
           Check previous reset request
        ------------------------------------------------- */

        const recentReset =
            await db
                .prepare(
                    `
                    SELECT created_at
                    FROM password_resets
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                    `
                )
                .bind(user.id)
                .first();


        /* -------------------------------------------------
           10-minute request cooldown
        ------------------------------------------------- */

        if (
            recentReset &&
            now -
                Number(
                    recentReset.created_at
                ) < 600
        ) {

            return Response.json(
                {
                    success: true,
                    cooldown: true,
                    message:
                        "Please wait before requesting another verification code."
                },
                {
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* -------------------------------------------------
           Remove previous reset sessions
        ------------------------------------------------- */

        await db
            .prepare(
                `
                DELETE FROM password_resets
                WHERE user_id = ?
                `
            )
            .bind(user.id)
            .run();


        /* -------------------------------------------------
           Generate secure 6-digit verification code
        ------------------------------------------------- */

        const code =
            generateCode();


        /* -------------------------------------------------
           Create random salt for OTP hash
        ------------------------------------------------- */

        const salt =
            crypto.getRandomValues(
                new Uint8Array(16)
            );


        /* -------------------------------------------------
           Hash verification code
        ------------------------------------------------- */

        const codeHash =
            await hashValue(
                code,
                salt
            );


        const storedCodeHash =
            `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(codeHash)}`;


        /* -------------------------------------------------
           10-minute OTP expiry
        ------------------------------------------------- */

        const expiresAt =
            now + (10 * 60);

        const createdAt =
            now;


        /* -------------------------------------------------
           Store hashed verification code
        ------------------------------------------------- */

        const insertResult =
            await db
                .prepare(
                    `
                    INSERT INTO password_resets
                    (
                        user_id,
                        code_hash,
                        expires_at,
                        attempts,
                        used,
                        created_at
                    )
                    VALUES (?, ?, ?, 0, 0, ?)
                    `
                )
                .bind(
                    user.id,
                    storedCodeHash,
                    expiresAt,
                    createdAt
                )
                .run();


        /*
         * Get the exact reset record we just created.
         *
         * This allows us to remove it if email sending fails.
         */

        let resetId = null;


        if (
            insertResult &&
            insertResult.meta &&
            Number(insertResult.meta.last_row_id)
        ) {

            resetId =
                Number(
                    insertResult.meta.last_row_id
                );
        }


        /*
         * Fallback: find the newest reset record.
         *
         * This is only used if D1 does not return
         * last_row_id in the expected form.
         */

        if (!resetId) {

            const insertedReset =
                await db
                    .prepare(
                        `
                        SELECT id
                        FROM password_resets
                        WHERE user_id = ?
                        ORDER BY id DESC
                        LIMIT 1
                        `
                    )
                    .bind(user.id)
                    .first();

            if (insertedReset) {

                resetId =
                    Number(
                        insertedReset.id
                    );
            }
        }


        /* -------------------------------------------------
           Resend configuration
        ------------------------------------------------- */

        const resendApiKey =
            context.env.RESEND_API_KEY;


        if (!resendApiKey) {

            console.error(
                "RESEND_API_KEY is not configured."
            );


            /*
             * Remove the reset record because
             * no email can be delivered.
             */

            if (resetId) {

                await db
                    .prepare(
                        `
                        DELETE FROM password_resets
                        WHERE id = ?
                        `
                    )
                    .bind(resetId)
                    .run();
            }


            return Response.json(
                {
                    success: false,
                    error:
                        "Email service is not configured."
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


        /* -------------------------------------------------
           Send verification email
        ------------------------------------------------- */

        const emailResponse =
            await fetch(
                "https://api.resend.com/emails",
                {
                    method: "POST",

                    headers: {
                        "Authorization":
                            `Bearer ${resendApiKey}`,

                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({

                            from:
                                "My Crypto Faucet <noreply@myfaucetcrypto.com>",

                            to: [email],

                            subject:
                                "My Crypto Faucet - Password Reset Code",

                            html: `
                                <div style="
                                    font-family: Arial, sans-serif;
                                    max-width: 600px;
                                    margin: auto;
                                    padding: 30px;
                                    background: #f5f7fb;
                                ">

                                    <div style="
                                        background: white;
                                        padding: 30px;
                                        border-radius: 12px;
                                        text-align: center;
                                    ">

                                        <h2 style="
                                            color: #222;
                                            margin-bottom: 20px;
                                        ">
                                            My Crypto Faucet
                                        </h2>

                                        <p>
                                            You requested to reset your password.
                                        </p>

                                        <p>
                                            Your verification code is:
                                        </p>

                                        <div style="
                                            font-size: 32px;
                                            font-weight: bold;
                                            letter-spacing: 8px;
                                            margin: 25px 0;
                                            color: #d89b00;
                                        ">
                                            ${code}
                                        </div>

                                        <p>
                                            This code will expire in
                                            <strong>10 minutes</strong>.
                                        </p>

                                        <p style="
                                            color: #777;
                                            font-size: 13px;
                                            line-height: 1.5;
                                        ">
                                            If you did not request a password
                                            reset, you can safely ignore this email.
                                        </p>

                                    </div>

                                </div>
                            `
                        })
                }
            );


        /* -------------------------------------------------
           Handle Resend failure
        ------------------------------------------------- */

        if (!emailResponse.ok) {

            const errorText =
                await emailResponse.text();


            console.error(
                "Resend email error:",
                errorText
            );


            /*
             * IMPORTANT:
             *
             * The reset code was already stored.
             * Since the email was not sent, remove it.
             *
             * This prevents the user from being trapped
             * by the 10-minute cooldown after a mail failure.
             */

            if (resetId) {

                await db
                    .prepare(
                        `
                        DELETE FROM password_resets
                        WHERE id = ?
                        `
                    )
                    .bind(resetId)
                    .run();
            }


            return Response.json(
                {
                    success: false,
                    error:
                        "Unable to send verification email."
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


        /* -------------------------------------------------
           Success
        ------------------------------------------------- */

        return Response.json(
            {
                success: true,
                cooldown: false,
                message:
                    "If this email is registered, a verification code has been sent."
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
            "Forgot password error:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to process password reset request."
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
