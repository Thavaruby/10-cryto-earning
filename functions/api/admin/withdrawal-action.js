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

        const withdrawalId =
            Number(data.withdrawalId);

        const action =
            String(data.action || "").toLowerCase();

        if (
            !Number.isInteger(withdrawalId) ||
            withdrawalId <= 0
        ) {
            return Response.json(
                {
                    success: false,
                    error: "Invalid withdrawal ID"
                },
                { status: 400 }
            );
        }

        if (
            action !== "approve" &&
            action !== "reject"
        ) {
            return Response.json(
                {
                    success: false,
                    error: "Invalid action"
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

        const admin =
            await context.env.DB
                .prepare(
                    `SELECT user_id
                     FROM admins
                     WHERE user_id = ?
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();

        if (!admin) {
            return Response.json(
                {
                    success: false,
                    error: "Admin access required"
                },
                { status: 403 }
            );
        }

        const withdrawal =
            await context.env.DB
                .prepare(
                    `SELECT
                        id,
                        user_id,
                        amount,
                        status
                     FROM withdrawals
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(withdrawalId)
                .first();

        if (!withdrawal) {
            return Response.json(
                {
                    success: false,
                    error: "Withdrawal not found"
                },
                { status: 404 }
            );
        }

        if (withdrawal.status !== "pending") {
            return Response.json(
                {
                    success: false,
                    error:
                        "This withdrawal has already been processed"
                },
                { status: 409 }
            );
        }

        /*
         * REJECT
         */

        if (action === "reject") {

            const result =
                await context.env.DB
                    .prepare(
                        `UPDATE withdrawals
                         SET status = 'rejected',
                             processed_at = CURRENT_TIMESTAMP
                         WHERE id = ?
                           AND status = 'pending'`
                    )
                    .bind(withdrawalId)
                    .run();

            if (result.meta.changes !== 1) {

                return Response.json(
                    {
                        success: false,
                        error:
                            "Withdrawal was already processed"
                    },
                    { status: 409 }
                );
            }

            return Response.json({
                success: true,
                status: "rejected"
            });
        }

        /*
         * APPROVE
         *
         * First atomically reserve the pending
         * withdrawal by changing its status.
         */

        const reserve =
            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET status = 'processing'
                     WHERE id = ?
                       AND status = 'pending'`
                )
                .bind(withdrawalId)
                .run();

        if (reserve.meta.changes !== 1) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Withdrawal was already processed"
                },
                { status: 409 }
            );
        }

        /*
         * Deduct balance only if enough balance exists.
         */

        const updateBalance =
            await context.env.DB
                .prepare(
                    `UPDATE users
                     SET balance = balance - ?
                     WHERE id = ?
                       AND balance >= ?`
                )
                .bind(
                    withdrawal.amount,
                    withdrawal.user_id,
                    withdrawal.amount
                )
                .run();

        if (updateBalance.meta.changes !== 1) {

            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET status = 'pending'
                     WHERE id = ?
                       AND status = 'processing'`
                )
                .bind(withdrawalId)
                .run();

            return Response.json(
                {
                    success: false,
                    error:
                        "Insufficient user balance"
                },
                { status: 400 }
            );
        }

        /*
         * Mark withdrawal as approved.
         */

        const approve =
            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET status = 'approved',
                         processed_at = CURRENT_TIMESTAMP
                     WHERE id = ?
                       AND status = 'processing'`
                )
                .bind(withdrawalId)
                .run();

        if (approve.meta.changes !== 1) {

            /*
             * Safety rollback if the final update
             * could not be completed.
             */

            await context.env.DB
                .prepare(
                    `UPDATE users
                     SET balance = balance + ?
                     WHERE id = ?`
                )
                .bind(
                    withdrawal.amount,
                    withdrawal.user_id
                )
                .run();

            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET status = 'pending'
                     WHERE id = ?
                       AND status = 'processing'`
                )
                .bind(withdrawalId)
                .run();

            return Response.json(
                {
                    success: false,
                    error:
                        "Unable to complete withdrawal"
                },
                { status: 500 }
            );
        }

        return Response.json({
            success: true,
            status: "approved"
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
