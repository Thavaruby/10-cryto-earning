const ITERATIONS = 100000;

function fromBase64(base64) {
    const binary = atob(base64);

    return Uint8Array.from(
        binary,
        char => char.charCodeAt(0)
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

function jsonResponse(data, status = 200, extraHeaders = {}) {
    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                ...extraHeaders
            }
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

        const db =
            context.env.DB.withSession("first-primary");

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

        if (!user || !user.password_hash) {
            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }

        let parts;
        let salt;
        let storedHash;

        try {

            parts =
                String(user.password_hash).split("$");

            if (parts.length !== 4) {
                throw new Error("Invalid password hash format");
            }

            salt =
                fromBase64(parts[2]);

            storedHash =
                fromBase64(parts[3]);

            if (
                salt.length === 0 ||
                storedHash.length === 0
            ) {
                throw new Error("Invalid password hash data");
            }

        } catch {

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }

        let calculatedHash;

        try {

            calculatedHash =
                await hashPassword(
                    password,
                    salt
                );

        } catch {

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
            return jsonResponse(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                401
            );
        }

        // Generate a cryptographically secure
        // 32-byte session token.
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

        // Only the SHA-256 hash is stored in DB.
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
                (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)`
            )
            .bind(
                user.id,
                tokenHash,
                expiresAt
            )
            .run();

        return jsonResponse(
            {
                success: true,
                message: "Login successful!"
            },
            200,
            {
                "Set-Cookie":
                    `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
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
