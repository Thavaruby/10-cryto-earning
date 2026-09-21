// functions/api/admin/faucetpay-transactions.js

async function sha256Hex(text) {
    const data = new TextEncoder().encode(text);

    const hash =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    return [...new Uint8Array(hash)]
        .map(
            b =>
                b.toString(16).padStart(2, "0")
        )
        .join("");
}

function getCookie(request, name) {

    const cookieHeader =
        request.headers.get("Cookie") || "";

    for (const cookie of cookieHeader.split(";")) {

        const [key, ...valueParts] =
            cookie.trim().split("=");

        if (key === name) {
            return decodeURIComponent(
                valueParts.join("=")
            );
        }
    }

    return null;
}

function jsonResponse(
    data,
    status = 200
) {
    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: {
                "Content-Type":
                    "application/json",

                "Cache-Control":
                    "no-store"
            }
        }
    );
}

export async function onRequestGet(context) {

    try {

        const { request, env } = context;

        // --------------------------------------------------
        // 1. Database session
        // --------------------------------------------------

        const db =
            env.DB.withSession(
                "first-primary"
            );

        // --------------------------------------------------
        // 2. Check login session
        // --------------------------------------------------

        const sessionToken =
            getCookie(
                request,
                "session"
            );

        if (!sessionToken) {

            return jsonResponse(
                {
                    success: false,
                    error: "Unauthorized."
                },
                401
            );
        }

        const tokenHash =
            await sha256Hex(
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
                    error: "Unauthorized."
                },
                401
            );
        }

        // --------------------------------------------------
        // 3. Check session expiry
        // --------------------------------------------------

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
                    error: "Unauthorized."
                },
                401
            );
        }

        // --------------------------------------------------
        // 4. Check admin
        // --------------------------------------------------

        const admin =
            await db
                .prepare(
                    `SELECT user_id
                     FROM admins
                     WHERE user_id = ?
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();

        if (!admin) {

            return jsonResponse(
                {
                    success: false,
                    error: "Forbidden."
                },
                403
            );
        }

        // --------------------------------------------------
        // 5. Check FaucetPay API key
        // --------------------------------------------------

        const apiKey =
            env.FAUCETPAY_API_KEY;

        if (!apiKey) {

            console.error(
                "FaucetPay transactions: API key is missing."
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "FaucetPay service is not configured."
                },
                500
            );
        }

        // --------------------------------------------------
        // 6. Request FaucetPay transactions
        // --------------------------------------------------

        const response =
            await fetch(
                "https://faucetpay.io/api/v2/transactions",
                {
                    method: "POST",

                    headers: {
                        "Authorization":
                            `Bearer ${apiKey}`,

                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        coin: "BTC",
                        page: 1
                    })
                }
            );

        let result;

        try {
            result =
                await response.json();
        } catch {
            result = null;
        }

        console.log(
            "FaucetPay transactions HTTP status:",
            response.status
        );

        // --------------------------------------------------
        // 7. Handle FaucetPay failure
        // --------------------------------------------------

        if (
            !response.ok ||
            !result ||
            result.success !== true
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to load FaucetPay transactions.",
                    http_status:
                        response.status
                },
                502
            );
        }

        // --------------------------------------------------
        // 8. Success
        // --------------------------------------------------

        return jsonResponse(
            {
                success: true,
                http_status:
                    response.status,
                faucetpay:
                    result
            },
            200
        );

    } catch (error) {

        console.error(
            "FAUCETPAY TRANSACTIONS ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to load FaucetPay transactions."
            },
            500
        );
    }
}
