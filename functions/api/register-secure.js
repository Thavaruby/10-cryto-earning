const ITERATIONS = 100000;

function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
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

function jsonResponse(data, status = 200) {
    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
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

        const db =
            context.env.DB.withSession("first-primary");

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

        try {

            await db
                .prepare(
                    `INSERT INTO users
                    (email, password_hash, balance)
                    VALUES (?, ?, 0)`
                )
                .bind(
                    email,
                    storedHash
                )
                .run();

        } catch (error) {

            const errorMessage =
                error instanceof Error
                    ? error.message
                    : "";

            /*
             * If the database has a UNIQUE constraint
             * on email, another simultaneous registration
             * can reach the INSERT after the earlier check.
             *
             * Do not expose the raw database error.
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

        return jsonResponse(
            {
                success: true,
                message: "Account created successfully!"
            },
            201
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
