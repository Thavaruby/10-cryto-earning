const MIN_WITHDRAWAL = 0.0000001;

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

        const data = await context.request.json();

        const amount = Number(data.amount);

        const walletAddress =
            String(data.walletAddress || "").trim();

        // BTC ONLY
        const currency = "BTC";

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
                        "Minimum withdrawal is 0.0000001 BTC"
                },
                { status: 400 }
            );
        }

        if (!walletAddress) {
            return Response.json(
                {
                    success: false,
                    error: "Bitcoin wallet address is required"
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

        /*
         * Prevent multiple pending withdrawals
         * for the same user.
         */
        const existingPending =
            await context.env.DB
                .prepare(
                    `SELECT id
                     FROM withdrawals
                     WHERE user_id = ?
                       AND status = 'pending'
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();

        if (existingPending) {
            return Response.json(
                {
                    success: false,
                    error:
                        "You already have a pending withdrawal."
                },
                { status: 409 }
            );
        }

        /*
         * Reserve the balance immediately.
         *
         * The WHERE balance >= amount condition
         * prevents negative balances and protects
         * against concurrent withdrawal requests.
         */
        const reserveBalance =
            await context.env.DB
                .prepare(
                    `UPDATE users
                     SET balance = balance - ?
                     WHERE id = ?
                       AND balance >= ?`
                )
                .bind(
                    amount,
                    session.user_id,
                    amount
                )
                .run();

        if (reserveBalance.meta.changes !== 1) {
            return Response.json(
                {
                    success: false,
                    error: "Insufficient BTC balance"
                },
                { status: 400 }
            );
        }

        /*
         * Create pending withdrawal.
         */
        try {

            await context.env.DB
                .prepare(
                    `INSERT INTO withdrawals
                    (
                        user_id,
                        amount,
                        wallet_address,
                        currency,
                        status
                    )
                    VALUES (?, ?, ?, ?, 'pending')`
                )
                .bind(
                    session.user_id,
                    amount,
                    walletAddress,
                    currency
                )
                .run();

        } catch (insertError) {

            /*
             * If creating the withdrawal fails,
             * restore the reserved balance.
             */
            await context.env.DB
                .prepare(
                    `UPDATE users
                     SET balance = balance + ?
                     WHERE id = ?`
                )
                .bind(
                    amount,
                    session.user_id
                )
                .run();

            throw insertError;
        }

        /*
         * Get updated balance.
         */
        const updatedUser =
            await context.env.DB
                .prepare(
                    `SELECT balance
                     FROM users
                     WHERE id = ?`
                )
                .bind(session.user_id)
                .first();

        return Response.json({
            success: true,
            message:
                "Withdrawal request submitted successfully.",
            status: "pending",
            amount: amount,
            currency: "BTC",
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
