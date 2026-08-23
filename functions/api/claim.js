const REWARD = 0.000001;
const COOLDOWN_SECONDS = 10 * 60;

function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) return null;

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
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
                new Date(lastClaim.claimed_at)
                    .getTime();

            const now =
                Date.now();

            const elapsedSeconds =
                Math.floor(
                    (now - lastTime) / 1000
                );

            if (
                elapsedSeconds <
                COOLDOWN_SECONDS
            ) {

                const remaining =
                    COOLDOWN_SECONDS -
                    elapsedSeconds;

                return Response.json(
                    {
                        success: false,
                        error:
                            `Please wait ${remaining} seconds before claiming again.`
                    },
                    { status: 429 }
                );
            }
        }

        await context.env.DB
            .prepare(
                "INSERT INTO claims (user_id, reward) VALUES (?, ?)"
            )
            .bind(
                user.user_id,
                REWARD
            )
            .run();

        await context.env.DB
            .prepare(
                "UPDATE users SET balance = balance + ? WHERE id = ?"
            )
            .bind(
                REWARD,
                user.user_id
            )
            .run();

        const updatedUser =
            await context.env.DB
                .prepare(
                    "SELECT balance FROM users WHERE id = ?"
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
