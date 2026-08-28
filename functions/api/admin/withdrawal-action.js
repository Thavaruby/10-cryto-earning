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
        .map(byte =>
            byte.toString(16).padStart(2, "0")
        )
        .join("");
}


export async function onRequestPost(context) {

    try {

        /* =========================
           READ REQUEST
        ========================= */

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
            !session.expires_at ||
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
                        wallet_address,
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
           PENDING ONLY
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


        /* =====================================================
           REJECT
        ===================================================== */

        if (action === "reject") {

            /*
             * First mark rejected.
             * Only if this succeeds do we refund.
             */

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


            /*
             * Refund reserved balance.
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


            return Response.json({

                success: true,

                status: "rejected",

                refunded:
                    withdrawal.amount,

                currency: "BTC"

            });
        }


        /* =====================================================
           APPROVE
        ===================================================== */

        /*
         * IMPORTANT:
         *
         * The user's balance was already reserved
         * when the withdrawal was created.
         *
         * Therefore we DO NOT deduct it again.
         */


        /* =========================
           CHECK API KEY
        ========================= */

        const apiKey =
            context.env.FAUCETPAY_API_KEY;


        if (!apiKey) {

            return Response.json(
                {
                    success: false,
                    error:
                        "FaucetPay API key is not configured."
                },
                { status: 500 }
            );
        }


        /* =========================
           FAUCETPAY PAYMENT
        ========================= */

        /*
         * FaucetPay expects the amount in
         * the smallest currency unit.
         *
         * BTC:
         * 1 BTC = 100,000,000 satoshis
         */

        const satoshis =
            Math.round(
                Number(withdrawal.amount) *
                100000000
            );


        if (
            !Number.isSafeInteger(satoshis) ||
            satoshis <= 0
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid BTC withdrawal amount."
                },
                { status: 400 }
            );
        }


        /*
         * Send payment through FaucetPay.
         */

        const faucetPayResponse =
            await fetch(
                "https://faucetpay.io/api/v1/send",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",

                        "X-API-KEY":
                            apiKey
                    },

                    body: JSON.stringify({

                        currency: "BTC",

                        amount: satoshis,

                        address:
                            withdrawal.wallet_address

                    })
                }
            );


        let faucetPayResult;

        try {

            faucetPayResult =
                await faucetPayResponse.json();

        } catch {

            faucetPayResult = null;
        }


        /* =========================
           FAUCETPAY ERROR
        ========================= */

        if (
            !faucetPayResponse.ok ||
            !faucetPayResult ||
            faucetPayResult.success !== true
        ) {

            console.error(
                "FaucetPay payment failed:",
                faucetPayResult
            );


            /*
             * DO NOT mark withdrawal approved.
             *
             * User's reserved balance remains safe.
             */

            return Response.json(
                {
                    success: false,
                    error:
                        faucetPayResult?.message ||
                        faucetPayResult?.error ||
                        "FaucetPay payment failed. Withdrawal remains pending."
                },
                { status: 502 }
            );
        }


        /* =========================
           GET TXID
        ========================= */

        const txid =
            faucetPayResult.txid ||
            faucetPayResult.transaction_id ||
            faucetPayResult.tx_id ||
            null;


        /* =========================
           MARK APPROVED
        ========================= */

        const result =
            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET status = 'approved',
                         processed_at = CURRENT_TIMESTAMP,
                         txid = ?
                     WHERE id = ?
                       AND status = 'pending'`
                )
                .bind(
                    txid,
                    withdrawalId
                )
                .run();


        if (
            !result ||
            result.meta.changes !== 1
        ) {

            /*
             * Payment may already have been sent.
             *
             * This is intentionally NOT retried automatically,
             * because retrying could create a duplicate payment.
             */

            console.error(
                "Database update failed after FaucetPay payment.",
                {
                    withdrawalId,
                    txid
                }
            );


            return Response.json(
                {
                    success: false,
                    error:
                        "Payment was sent, but withdrawal status could not be updated. Check FaucetPay before retrying.",
                    txid: txid
                },
                { status: 500 }
            );
        }


        /* =========================
           SUCCESS
        ========================= */

        return Response.json({

            success: true,

            status: "approved",

            amount:
                withdrawal.amount,

            currency:
                "BTC",

            txid:
                txid

        });


    } catch (error) {

        console.error(
            "Withdrawal action error:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to process withdrawal."
            },
            { status: 500 }
        );
    }
}
