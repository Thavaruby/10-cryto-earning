function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) return null;

    for (const cookie of cookieHeader.split(";")) {
        const [key, ...value] = cookie.trim().split("=");

        if (key === name) {
            return decodeURIComponent(value.join("="));
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
            context.env.DB.withSession(
                "first-primary"
            );

        const sessionToken =
            getCookie(
                context.request,
                "session"
            );

        if (!sessionToken) {

            return jsonResponse(
                {
                    success: false,
                    error: "Please login first"
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
                        user_id,
                        expires_at
                     FROM sessions
                     WHERE token_hash = ?
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

        const withdrawals =
            await db
                .prepare(
                    `SELECT
                        id,
                        amount,
                        wallet_address,
                        currency,
                        status,
                        created_at,
                        processed_at,
                        payout_id,
                        txid
                     FROM withdrawals
                     WHERE user_id = ?
                     ORDER BY id DESC
                     LIMIT 100`
                )
                .bind(session.user_id)
                .all();

        return jsonResponse({
            success: true,
            withdrawals:
                withdrawals.results || []
        });

    } catch (error) {

        console.error(
            "WITHDRAWALS HISTORY ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to load withdrawal history."
            },
            500
        );
    }
}
