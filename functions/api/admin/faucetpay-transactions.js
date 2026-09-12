// functions/api/admin/faucetpay-transactions.js

async function sha256Hex(text) {
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", data);

    return [...new Uint8Array(hash)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie") || "";

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
        const [key, ...valueParts] = cookie.trim().split("=");

        if (key === name) {
            return decodeURIComponent(valueParts.join("="));
        }
    }

    return null;
}

export async function onRequestGet(context) {
    try {
        const { request, env } = context;

        // --------------------------------------------------
        // 1. Database session
        // --------------------------------------------------

        const db = env.DB.withSession("first-primary");

        // --------------------------------------------------
        // 2. Check login session
        // --------------------------------------------------

        const sessionToken = getCookie(request, "session");

        if (!sessionToken) {
            return Response.json(
                {
                    success: false,
                    error: "Unauthorized."
                },
                {
                    status: 401,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }

        const tokenHash = await sha256Hex(sessionToken);

        const session = await db
            .prepare(`
                SELECT user_id
                FROM sessions
                WHERE token_hash = ?
                  AND expires_at > CURRENT_TIMESTAMP
                LIMIT 1
            `)
            .bind(tokenHash)
            .first();

        if (!session) {
            return Response.json(
                {
                    success: false,
                    error: "Unauthorized."
                },
                {
                    status: 401,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }

        // --------------------------------------------------
        // 3. Check admin
        // --------------------------------------------------

        const admin = await db
            .prepare(`
                SELECT user_id
                FROM admins
                WHERE user_id = ?
                LIMIT 1
            `)
            .bind(session.user_id)
            .first();

        if (!admin) {
            return Response.json(
                {
                    success: false,
                    error: "Forbidden."
                },
                {
                    status: 403,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }

        // --------------------------------------------------
        // 4. Check FaucetPay API key
        // --------------------------------------------------

        const apiKey = env.FAUCETPAY_API_KEY;

        if (!apiKey) {
            console.error(
                "FaucetPay transactions: API key is missing."
            );

            return Response.json(
                {
                    success: false,
                    error: "FaucetPay service is not configured."
                },
                {
                    status: 500,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }

        // --------------------------------------------------
        // 5. Request FaucetPay transactions
        // --------------------------------------------------

        const response = await fetch(
            "https://faucetpay.io/api/v2/transactions",
            {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${apiKey}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    coin: "BTC",
                    page: 1
                })
            }
        );

        let result;

        try {
            result = await response.json();
        } catch {
            result = null;
        }

        // Do NOT log the full FaucetPay response.
        console.log(
            "FaucetPay transactions HTTP status:",
            response.status
        );

        // --------------------------------------------------
        // 6. Handle FaucetPay failure
        // --------------------------------------------------

        if (!response.ok || !result || result.success !== true) {
            return Response.json(
                {
                    success: false,
                    error: "Unable to load FaucetPay transactions.",
                    http_status: response.status
                },
                {
                    status: 502,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }

        // --------------------------------------------------
        // 7. Success
        // --------------------------------------------------

        return Response.json(
            {
                success: true,
                http_status: response.status,
                faucetpay: result
            },
            {
                status: 200,
                headers: {
                    "Cache-Control": "no-store"
                }
            }
        );

    } catch (error) {
        console.error(
            "FaucetPay transactions endpoint error."
        );

        return Response.json(
            {
                success: false,
                error: "Unable to load FaucetPay transactions."
            },
            {
                status: 500,
                headers: {
                    "Cache-Control": "no-store"
                }
            }
        );
    }
}
