const REWARD = 0.00000001;
const COOLDOWN_SECONDS = 60 * 60;

function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) return null;

    for (const cookie of cookieHeader.split(";")) {
        const [key, ...value] = cookie.trim().split("=");

        if (key === name) {
            return value.join("=");
        }
    }

    return null;
}

async function hashSessionToken(token) {
    const data = new TextEncoder().encode(token);

    const hash = await crypto.subtle.digest(
        "SHA-256",
        data
    );

    return Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

export async function onRequestPost(context) {

    try {

        // Get Turnstile token
        const data =
            await context.request.json();

        const turnstileToken =
            String(data.turnstileToken || "");

        if (!turnstileToken) {

            return Response.json(
                {
                    success: false,
                    error: "Please complete verification"
                },
                { status: 400 }
            );
        }

        // Verify Turnstile with Cloudflare
        const verifyResponse =
            await fetch(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/x-www-form-urlencoded"
                    },

                    body:
                        new URLSearchParams({
                            secret:
                                context.env.TURNSTILE_SECRET,

                            response:
                                turnstileToken
                        })
                }
            );

        const verifyResult =
            await verifyResponse.json();

        if (!verifyResult.success) {

            return Response.json(
                {
                    success: false,
                    error: "Verification failed"
                },
                { status: 400 }
            );
        }

        // Get session
        const sessionToken =
            getCookie(
                context.request,
                "session"
            );

        if (!sessionToken) {

            return Response.json(
                {
                    success: false,
                    error: "Please login first"
                },
                { status: 401 }
            );
        }

        const tokenHash =
            await hashSessionToken(
                sessionToken
            );

        const user =
            await context.env.DB
                .prepare(
                    `SELECT
                        sessions.user_id,
                        sessions.expires_at
                     FROM sessions
                     WHERE sessions.token_hash = ?
                     LIMIT 1`
                )
                .bind(tokenHash)
                .first();

        if (!user) {

            return Response.json(
                {
                    success: false,
                    error: "Invalid session"
                },
                { status: 401 }
            );
        }

        if (
            new Date(user.expires_at) <=
            new Date()
        ) {

            return Response.json(
                {
                    success: false,
                    error: "Session expired"
                },
                { status: 401 }
            );
        }

        // Check cooldown
        const lastClaim =
            await context.env.DB
                .prepare(
                    `SELECT claimed_at
                     FROM claims
                     WHERE user_id = ?
                     ORDER BY claimed_at DESC
                     LIMIT 1`
                )
                .bind(user.user_id)
                .first();

        if (lastClaim) {

            const lastTime =
                new Date(
                    lastClaim.claimed_at
                ).getTime();

            const elapsedSeconds =
                Math.floor(
                    (Date.now() - lastTime) / 1000
                );

            if (
                elapsedSeconds <
                COOLDOWN_SECONDS
            ) {

                const remaining =
                    COOLDOWN_SECONDS -
                    elapsedSeconds;

                const hours =
                    Math.floor(
                        remaining / 3600
                    );

                const minutes =
                    Math.floor(
                        (remaining % 3600) / 60
                    );

                const seconds =
                    remaining % 60;

                return Response.json(
                    {
                        success: false,
                        error:
                            `Please wait ${hours}h ${minutes}m ${seconds}s before claiming again.`
                    },
                    { status: 429 }
                );
            }
        }

        // Record claim
        await context.env.DB
            .prepare(
                `INSERT INTO claims
                (user_id, reward)
                VALUES (?, ?)`
            )
            .bind(
                user.user_id,
                REWARD
            )
            .run();

        // Add reward to balance
        await context.env.DB
            .prepare(
                `UPDATE users
                 SET balance = balance + ?
                 WHERE id = ?`
            )
            .bind(
                REWARD,
                user.user_id
            )
            .run();

        // Get updated balance
        const updatedUser =
            await context.env.DB
                .prepare(
                    `SELECT balance
                     FROM users
                     WHERE id = ?`
                )
                .bind(user.user_id)
                .first();

        return Response.json({
            success: true,
            message: "Reward claimed successfully!",
            reward: REWARD,
            balance: updatedUser.balance
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
