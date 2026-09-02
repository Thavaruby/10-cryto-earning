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

    const data =
        new TextEncoder().encode(token);

    const hash =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    return Array.from(
        new Uint8Array(hash)
    )
        .map(byte =>
            byte.toString(16).padStart(2, "0")
        )
        .join("");
}


export async function onRequestGet(context) {

    try {

        /* =========================
           CHECK LOGIN
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


        /* =========================
           CHECK SESSION
        ========================= */

        const tokenHash =
            await hashSessionToken(
                sessionToken
            );

        const session =
            await context.env.DB
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
           CHECK ADMIN
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
           READ STATUS FILTER
        ========================= */

        const url =
            new URL(context.request.url);

        const requestedStatus =
            String(
                url.searchParams.get("status") ||
                "pending"
            ).toLowerCase();


        /* =========================
           ALLOWED STATUSES ONLY
        ========================= */

        const allowedStatuses = [
            "pending",
            "approved",
            "rejected"
        ];


        if (
            !allowedStatuses.includes(
                requestedStatus
            )
        ) {

            return Response.json(
                {
                    success: false,
                    error: "Invalid withdrawal status"
                },
                { status: 400 }
            );
        }


        /* =========================
           LOAD BTC WITHDRAWALS
           BY STATUS
        ========================= */

        const withdrawals =
            await context.env.DB
                .prepare(
                    `SELECT
                        withdrawals.id,
                        withdrawals.user_id,
                        users.email,
                        withdrawals.amount,
                        withdrawals.wallet_address,
                        withdrawals.currency,
                        withdrawals.status,
                        withdrawals.created_at,
                        withdrawals.processed_at,
                        withdrawals.txid,
                        withdrawals.payout_id

                     FROM withdrawals

                     JOIN users
                       ON users.id =
                          withdrawals.user_id

                     WHERE withdrawals.status = ?
                       AND withdrawals.currency = 'BTC'

                     ORDER BY withdrawals.id DESC`
                )
                .bind(requestedStatus)
                .all();


        /* =========================
           RESPONSE
        ========================= */

        return Response.json({

            success: true,

            status: requestedStatus,

            withdrawals:
                withdrawals.results || []

        });


    } catch (error) {

        console.error(
            "Admin withdrawals error:",
            error
        );

        return Response.json(
            {
                success: false,
                error: "Internal server error"
            },
            { status: 500 }
        );
    }
}
