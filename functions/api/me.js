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

function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) return null;

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
        const [key, ...value] = cookie.trim().split("=");

        if (key === name) {
            return decodeURIComponent(value.join("="));
        }
    }

    return null;
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

export async function onRequestGet(context) {

    try {

        const db =
            context.env.DB.withSession("first-primary");

        const sessionToken =
            getCookie(
                context.request,
                "session"
            );

        if (!sessionToken) {

            return jsonResponse(
                {
                    success: false,
                    error: "Not logged in"
                },
                401
            );
        }

        const tokenHash =
            await hashSessionToken(
                sessionToken
            );

        const session =
            await db
                .prepare(
                    `SELECT
                        sessions.user_id,
                        sessions.expires_at,
                        users.email,
                        users.balance
                     FROM sessions
                     JOIN users
                     ON users.id = sessions.user_id
                     WHERE sessions.token_hash = ?
                     LIMIT 1`
                )
                .bind(tokenHash)
                .first();

        if (!session) {

            return jsonResponse(
                {
                    success: false,
                    error: "Invalid session"
                },
                401
            );
        }

        if (
            new Date(session.expires_at) <=
            new Date()
        ) {

            await db
                .prepare(
                    `DELETE FROM sessions
                     WHERE token_hash = ?`
                )
                .bind(tokenHash)
                .run();

            return jsonResponse(
                {
                    success: false,
                    error: "Session expired"
                },
                401
            );
        }

        return jsonResponse({
            success: true,
            user: {
                id: session.user_id,
                email: session.email,
                balance: session.balance
            }
        });

    } catch (error) {

        console.error(
            "ME ENDPOINT ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return jsonResponse(
            {
                success: false,
                error: "Unable to load account."
            },
            500
        );
    }
}
