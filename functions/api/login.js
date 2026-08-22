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

export async function onRequestPost(context) {

    try {

        const data =
            await context.request.json();

        const email =
            String(data.email || "")
                .trim()
                .toLowerCase();

        const password =
            String(data.password || "");

        if (!email || !password) {

            return Response.json(
                {
                    success: false,
                    error: "Email and password are required"
                },
                { status: 400 }
            );
        }

        const user =
            await context.env.DB
                .prepare(
                    "SELECT id, email, password_hash, balance FROM users WHERE email = ?"
                )
                .bind(email)
                .first();

        if (!user || !user.password_hash) {

            return Response.json(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                { status: 401 }
            );
        }

        const parts =
            user.password_hash.split("$");

        if (parts.length !== 4) {

            return Response.json(
                {
                    success: false,
                    error: "Invalid password configuration"
                },
                { status: 500 }
            );
        }

        const salt =
            fromBase64(parts[2]);

        const storedHash =
            fromBase64(parts[3]);

        const calculatedHash =
            await hashPassword(
                password,
                salt
            );

        if (
            !constantTimeEqual(
                calculatedHash,
                storedHash
            )
        ) {

            return Response.json(
                {
                    success: false,
                    error: "Invalid email or password"
                },
                { status: 401 }
            );
        }

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

        await context.env.DB
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

        return new Response(
            JSON.stringify({
                success: true,
                message: "Login successful!"
            }),
            {
                headers: {
                    "Content-Type":
                        "application/json",

                    "Set-Cookie":
                        `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
                }
            }
        );

    } catch (error) {

        return Response.json(
            {
                success: false,
                error: error.message
            },
            { status: 500 }
        );
    }
}
