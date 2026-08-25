const MIN_WITHDRAWAL = 0.00001;

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

        const data =
            await context.request.json();

        const amount =
            Number(data.amount);

        const walletAddress =
            String(data.walletAddress || "").trim();

        const currency =
            String(data.currency || "").trim().toUpperCase();

        if (!Number.isFinite(amount) || amount <= 0) {

            return Response.json(
                {
                    success: false,
                    error: "Invalid withdrawal amount"
                },
                { status: 400 }
            );
        }

        if (amount < MIN_WITHDRAWAL) {

            return Response.json(
                {
                    success: false,
                    error:
                        `Minimum withdrawal is ${MIN_WITHDRAWAL}`
                },
                { status: 400 }
            );
        }

        if (!walletAddress) {

            return Response.json(
                {
                    success: false,
                    error: "Wallet address is required"
                },
                { status: 400 }
            );
        }

        if (currency !== "BTC") {

    return Response.json(
        {
            success: false,
            error: "Only BTC withdrawals are supported"
        },
        { status: 400 }
    );
}

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

        if (
            new Date(session.expires_at) <=
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

        const user =
            await context.env.DB
                .prepare(
                    "SELECT balance FROM users WHERE id = ?"
                )
                .bind(session.user_id)
                .first();

        if (!user) {

            return Response.json(
                {
                    success: false,
                    error: "User not found"
                },
                { status: 404 }
            );
        }

        if (Number(user.balance) < amount) {

            return Response.json(
                {
                    success: false,
                    error: "Insufficient balance"
                },
                { status: 400 }
            );
        }

        await context.env.DB
            .prepare(
                `INSERT INTO withdrawals
                (user_id, amount, wallet_address, currency)
                VALUES (?, ?, ?, ?)`
            )
            .bind(
                session.user_id,
                amount,
                walletAddress,
                currency
            )
            .run();

        return Response.json({
            success: true,
            message: "Withdrawal request submitted",
            status: "pending"
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
