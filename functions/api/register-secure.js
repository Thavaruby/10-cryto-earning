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
    return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function hashPassword(password, salt) {
    const encoder = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
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

export async function onRequestPost(context) {

    try {

        const data = await context.request.json();

        const email = String(data.email || "")
            .trim()
            .toLowerCase();

        const password = String(data.password || "");

        if (!email || !password) {
            return Response.json(
                {
                    success: false,
                    error: "Email and password are required"
                },
                { status: 400 }
            );
        }

        if (password.length < 8) {
            return Response.json(
                {
                    success: false,
                    error: "Password must contain at least 8 characters"
                },
                { status: 400 }
            );
        }

        const existingUser = await context.env.DB
            .prepare("SELECT id FROM users WHERE email = ?")
            .bind(email)
            .first();

        if (existingUser) {
            return Response.json(
                {
                    success: false,
                    error: "Email already registered"
                },
                { status: 409 }
            );
        }

        const salt = crypto.getRandomValues(
            new Uint8Array(16)
        );

        const passwordHash = await hashPassword(
            password,
            salt
        );

        const storedHash =
            `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(passwordHash)}`;

        const result = await context.env.DB
            .prepare(
                "INSERT INTO users (email, password_hash, balance) VALUES (?, ?, 0)"
            )
            .bind(email, storedHash)
            .run();

        return Response.json({
            success: true,
            message: "Account created successfully!",
            user_id: result.meta.last_row_id
        });

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
