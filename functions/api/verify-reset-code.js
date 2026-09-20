const ITERATIONS = 100000;

function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function fromBase64(base64) {
    const binary = atob(base64);

    return Uint8Array.from(
        binary,
        char => char.charCodeAt(0)
    );
}

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

function base64Url(bytes) {

    return toBase64(bytes)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

async function verifyHash(value, storedHash) {

    try {

        const parts = storedHash.split("$");

        if (parts.length !== 4) {
            return false;
        }

        const algorithm = parts[0];
        const iterations = Number(parts[1]);
        const salt = fromBase64(parts[2]);
        const expectedHash = fromBase64(parts[3]);

        if (
            algorithm !== "pbkdf2" ||
            iterations !== ITERATIONS
        ) {
            return false;
        }

        const actualHash =
            await hashValue(value, salt);

        if (
            actualHash.length !== expectedHash.length
        ) {
            return false;
        }

        let difference = 0;

        for (
            let i = 0;
            i < actualHash.length;
            i++
        ) {
            difference |=
                actualHash[i] ^ expectedHash[i];
        }

        return difference === 0;

    } catch {

        return false;
    }
}

export async function onRequestPost(context) {

    try {

        const data =
            await context.request.json();

        const email =
            String(data.email || "")
                .trim()
                .toLowerCase();

        const code =
            String(data.code || "")
                .trim();

        if (!email || !code) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Email and verification code are required."
                },
                { status: 400 }
            );
        }

        if (!/^\d{6}$/.test(code)) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid verification code."
                },
                { status: 400 }
            );
        }

        // Use the primary session for consistent reads/writes.
        const db =
            context.env.DB.withSession("first-primary");

        const user =
            await db
                .prepare(
                    "SELECT id FROM users WHERE email = ?"
                )
                .bind(email)
                .first();

        /*
         * Generic response prevents account enumeration.
         */
        if (!user) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired verification code."
                },
                { status: 400 }
            );
        }

        const reset =
            await db
                .prepare(
                    `SELECT id,
                            code_hash,
                            expires_at,
                            attempts,
                            used
                     FROM password_resets
                     WHERE user_id = ?
                     ORDER BY id DESC
                     LIMIT 1`
                )
                .bind(user.id)
                .first();

        if (!reset) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired verification code."
                },
                { status: 400 }
            );
        }

        /*
         * Code can only be used once.
         */
        if (Number(reset.used) === 1) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This verification code has already been used."
                },
                { status: 400 }
            );
        }

        /*
         * Maximum 5 incorrect attempts.
         */
        if (Number(reset.attempts) >= 5) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Too many incorrect attempts. Please request a new code."
                },
                { status: 429 }
            );
        }

        const now =
            Math.floor(Date.now() / 1000);

        /*
         * Code expires after 10 minutes.
         */
        if (now >= Number(reset.expires_at)) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This verification code has expired. Please request a new code."
                },
                { status: 400 }
            );
        }

        /*
         * Verify the submitted code.
         */
        const valid =
            await verifyHash(
                code,
                reset.code_hash
            );

        if (!valid) {

            await db
                .prepare(
                    `UPDATE password_resets
                     SET attempts = attempts + 1
                     WHERE id = ?
                       AND used = 0
                       AND attempts < 5`
                )
                .bind(reset.id)
                .run();

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid verification code."
                },
                { status: 400 }
            );
        }

        /*
         * Create a secure one-time reset token.
         */
        const tokenBytes =
            crypto.getRandomValues(
                new Uint8Array(32)
            );

        const resetToken =
            base64Url(tokenBytes);

        /*
         * Hash the reset token before storing it.
         */
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

        /*
         * Atomically consume the verification code.
         *
         * This prevents two simultaneous correct requests
         * from both successfully using the same code.
         */
        const consumeResult =
            await db
                .prepare(
                    `UPDATE password_resets
                     SET used = 1,
                         verified_at = ?,
                         reset_token_hash = ?
                     WHERE id = ?
                       AND used = 0
                       AND attempts < 5
                       AND expires_at > ?`
                )
                .bind(
                    now,
                    storedTokenHash,
                    reset.id,
                    now
                )
                .run();

        /*
         * If another request already consumed the code,
         * this request must not receive a reset token.
         */
        if (
            !consumeResult.meta ||
            Number(consumeResult.meta.changes) !== 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This verification code is no longer valid. Please request a new code."
                },
                { status: 400 }
            );
        }

        return Response.json({

            success: true,

            message:
                "Verification successful.",

            reset_token:
                resetToken

        });

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
            { status: 500 }
        );
    }
}

What changed

Only the security-critical parts:

- ✅ "DB.withSession("first-primary")"
- ✅ Expiry check changed to ">="
- ✅ Failed-attempt increment is protected by "attempts < 5"
- ✅ Atomic one-time code consumption
- ✅ A second simultaneous request cannot receive another reset token
- ✅ No D1 schema change
- ✅ Your PBKDF2/100,000-iteration system remains unchanged

Next step: deploy this "verify-code.js", then test the normal flow: Forgot password → email code → enter correct code → verification successful → reset-password page.
