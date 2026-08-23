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

export async function onRequestGet(context) {

    try {

        const sessionToken =
            getCookie(context.request, "session");

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
            await hashSessionToken(sessionToken);

        const session =
            await context.env.DB
                .prepare(
                    `SELECT user_id, expires_at
                     FROM sessions
                     WHERE token_hash = ?
                     LIMIT 1`
                )
                .bind(tokenHash)
                .first();

        if (!session) {
            return Response.json(
                {
                    success: false,
                    error: "Invalid session"
                },
                { status: 401 }
            );
        }

        if (new Date(session.expires_at) <= new Date()) {
            return Response.json(
                {
                    success: false,
                    error: "Session expired"
                },
                { status: 401 }
            );
        }

        const claims =
            await context.env.DB
                .prepare(
                    `SELECT
                        id,
                        reward,
                        claimed_at
                     FROM claims
                     WHERE user_id = ?
                     ORDER BY id DESC
                     LIMIT 20`
                )
                .bind(session.user_id)
                .all();

        return Response.json({
            success: true,
            claims: claims.results
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
