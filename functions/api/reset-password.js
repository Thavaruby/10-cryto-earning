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

async function verifyHash(value, storedHash) {

    try {

        const parts =
            storedHash.split("$");

        if (parts.length !== 4) {
            return false;
        }

        const algorithm = parts[0];
        const iterations = Number(parts[1]);

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

        const actualHash =
            await hashValue(value, salt);

        if (
            actualHash.length !==
            expectedHash.length
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

        const token =
            String(data.token || "").trim();

        const password =
            String(data.password || "");

        if (!email || !token || !password) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid password reset request."
                },
                { status: 400 }
            );
        }

        if (password.length < 8) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Password must contain at least 8 characters."
                },
                { status: 400 }
            );
        }

        const db = context.env.DB;

        const user =
            await db
                .prepare(
                    "SELECT id FROM users WHERE email = ?"
                )
                .bind(email)
                .first();

        if (!user) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired reset session."
                },
                { status: 400 }
            );
        }

        const reset =
            await db
                .prepare(
                    `SELECT id,
                            reset_token_hash,
                            verified_at
                     FROM password_resets
                     WHERE user_id = ?
                     ORDER BY id DESC
                     LIMIT 1`
                )
                .bind(user.id)
                .first();

        if (!reset || !reset.reset_token_hash) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired reset session."
                },
                { status: 400 }
            );
        }

        /*
         * Reset token is valid only after
         * successful verification.
         */
        if (!reset.verified_at) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Please verify your email code first."
                },
                { status: 400 }
            );
        }

        /*
         * Reset token is valid for 10 minutes
         * after successful code verification.
         */
        const now =
            Math.floor(Date.now() / 1000);

        const verifiedAt =
            Number(reset.verified_at);

        if (
            !verifiedAt ||
            now > verifiedAt + (10 * 60)
        ) {

            await db
                .prepare(
                    "DELETE FROM password_resets WHERE id = ?"
                )
                .bind(reset.id)
                .run();

            return Response.json(
                {
                    success: false,
                    error:
                        "Your password reset session has expired. Please request a new code."
                },
                { status: 400 }
            );
        }

        /*
         * Verify the one-time reset token.
         */
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
                { status: 400 }
            );
        }

        /*
         * Create a new random salt.
         * This uses the SAME PBKDF2 format
         * as register-secure.js.
         */
        const salt =
            crypto.getRandomValues(
                new Uint8Array(16)
            );

        const passwordHash =
            await hashValue(
                password,
                salt
            );

        const storedHash =
            `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(passwordHash)}`;

        /*
         * Update the user's password.
         */
        await db
            .prepare(
                "UPDATE users SET password_hash = ? WHERE id = ?"
            )
            .bind(
                storedHash,
                user.id
            )
            .run();

        /*
         * Delete the reset record.
         * This makes the reset process one-time use.
         */
        await db
            .prepare(
                "DELETE FROM password_resets WHERE id = ?"
            )
            .bind(reset.id)
            .run();

        return Response.json({

            success: true,

            message:
                "Password reset successfully."

        });

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
            { status: 500 }
        );
    }
}
