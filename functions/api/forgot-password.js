const ITERATIONS = 100000;

// Convert Uint8Array → Base64
function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

// PBKDF2 hash function
async function hashValue(value, salt) {
    const encoder = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(value),
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

// Create secure random 6-digit code
function generateCode() {
    const random = new Uint32Array(1);

    crypto.getRandomValues(random);

    return String(random[0] % 1000000).padStart(6, "0");
}

export async function onRequestPost(context) {

    try {

        const data = await context.request.json();

        const email = String(data.email || "")
            .trim()
            .toLowerCase();

        if (!email) {
            return Response.json(
                {
                    success: false,
                    error: "Email is required"
                },
                { status: 400 }
            );
        }

        const db = context.env.DB.withSession("first-primary");

        // Find user
        const user = await db
            .prepare(
                "SELECT id, email FROM users WHERE email = ?"
            )
            .bind(email)
            .first();

        /*
         * Do not reveal whether the email exists.
         * This prevents email-account enumeration.
         */
        if (!user) {
            return Response.json({
                success: true,
                message:
                    "If this email is registered, a verification code has been sent."
            });
        }

        
const now = Math.floor(Date.now() / 1000);

const recentReset = await db
    .prepare(`
        SELECT created_at
        FROM password_resets
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    `)
    .bind(user.id)
    .first();

if (
    recentReset &&
    now - Number(recentReset.created_at) < 60
) {
    return Response.json(
        {
            success: true,
            message:
                "If this email is registered, a verification code has been sent."
        }
    );
}
    
        // Remove previous unused reset codes
        await db
            .prepare(
                "DELETE FROM password_resets WHERE user_id = ?"
            )
            .bind(user.id)
            .run();

        // Generate 6-digit verification code
        const code = generateCode();

        // Create random salt for code hash
        const salt = crypto.getRandomValues(
            new Uint8Array(16)
        );

        const codeHash = await hashValue(code, salt);

        const storedCodeHash =
            `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${toBase64(codeHash)}`;

        // 10-minute expiry
        const expiresAt =
            Math.floor(Date.now() / 1000) + (10 * 60);

        const createdAt =
            Math.floor(Date.now() / 1000);

        // Store hashed code
        await db
            .prepare(
                `INSERT INTO password_resets
                (user_id, code_hash, expires_at, attempts, used, created_at)
                VALUES (?, ?, ?, 0, 0, ?)`
            )
            .bind(
                user.id,
                storedCodeHash,
                expiresAt,
                createdAt
            )
            .run();

        /*
         * Send verification email using Resend
         */

        const resendApiKey =
            context.env.RESEND_API_KEY;

        if (!resendApiKey) {

            console.error(
                "RESEND_API_KEY is not configured."
            );

            return Response.json(
                {
                    success: false,
                    error: "Email service is not configured."
                },
                { status: 500 }
            );
        }

        const emailResponse = await fetch(
            "https://api.resend.com/emails",
            {
                method: "POST",

                headers: {
                    "Authorization":
                        `Bearer ${resendApiKey}`,
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

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

        if (!emailResponse.ok) {

            const errorText =
                await emailResponse.text();

            console.error(
                "Resend email error:",
                errorText
            );

            return Response.json(
                {
                    success: false,
                    error:
                        "Unable to send verification email."
                },
                { status: 500 }
            );
        }

        return Response.json({

            success: true,

            message:
                "If this email is registered, a verification code has been sent."

        });

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
            { status: 500 }
        );
    }
}
