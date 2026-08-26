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

        /* =========================
           VALIDATION
        ========================= */

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

        /* =========================
           SESSION
        ========================= */

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

        /* =========================
           ADMIN CHECK
        ========================= */

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

        /* =========================
           GET WITHDRAWAL
        ========================= */

        const withdrawal =
            await context.env.DB
                .prepare(
                    `SELECT
                        id,
                        user_id,
                        amount,
                        currency,
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

        /* =========================
           BTC ONLY
        ========================= */

        if (withdrawal.currency !== "BTC") {
            return Response.json(
                {
                    success: false,
                    error:
                        "Only BTC withdrawals are supported"
                },
                { status: 400 }
            );
        }

        /* =========================
           ALREADY PROCESSED
        ========================= */

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

        /* =========================
           APPROVE
           
           IMPORTANT:
           Balance was already reserved
           when withdrawal was created.

           DO NOT deduct balance again.
        ========================= */

        if (action === "approve") {

            const result =
                await context.env.DB
                    .prepare(
                        `UPDATE withdrawals
                         SET status = 'approved',
                             processed_at = CURRENT_TIMESTAMP
                         WHERE id = ?
                           AND status = 'pending'`
                    )
                    .bind(withdrawalId)
                    .run();

            if (
                !result ||
                result.meta.changes !== 1
            ) {
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
                status: "approved",
                amount: withdrawal.amount,
                currency: "BTC"
            });
        }

        /* =========================
           REJECT

           Balance was reserved during
           withdrawal request.

           Therefore return the BTC
           exactly once.
        ========================= */

        if (action === "reject") {

            const result =
                await context.env.DB.batch([

                    context.env.DB
                        .prepare(
                            `UPDATE withdrawals
                             SET status = 'rejected',
                                 processed_at = CURRENT_TIMESTAMP
                             WHERE id = ?
                               AND status = 'pending'`
                        )
                        .bind(withdrawalId),

                    context.env.DB
                        .prepare(
                            `UPDATE users
                             SET balance = balance + ?
                             WHERE id = ?`
                        )
                        .bind(
                            withdrawal.amount,
                            withdrawal.user_id
                        )

                ]);

            /*
             * The withdrawal UPDATE must change
             * exactly one row.
             */

            if (
                !result ||
                !result[0] ||
                result[0].meta.changes !== 1
            ) {
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
                status: "rejected",
                refunded: withdrawal.amount,
                currency: "BTC"
            });
        }

    } catch (error) {

        console.error(
            "Withdrawal action error:",
            error
        );

        return Response.json(
            {
                success: false,
                error: error.message
            },
            { status: 500 }
        );
    }
}
