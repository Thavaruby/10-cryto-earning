function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) {
        return null;
    }

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
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");
}


export async function onRequestPost(context) {

    try {

        /* =====================================================
           1. READ REQUEST
        ===================================================== */

        let data;

        try {

            data =
                await context.request.json();

        } catch {

            return Response.json(
                {
                    success: false,
                    error: "Invalid request."
                },
                { status: 400 }
            );
        }


        const withdrawalId =
            Number(data.withdrawalId);

        const action =
            String(
                data.action || ""
            ).toLowerCase();


        /* =====================================================
           2. VALIDATION
        ===================================================== */

        if (
            !Number.isInteger(withdrawalId) ||
            withdrawalId <= 0
        ) {

            return Response.json(
                {
                    success: false,
                    error: "Invalid withdrawal ID."
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
                    error: "Invalid action."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           3. CHECK LOGIN
        ===================================================== */

        const sessionToken =
            getCookie(
                context.request,
                "session"
            );


        if (!sessionToken) {

            return Response.json(
                {
                    success: false,
                    error: "Please login first."
                },
                { status: 401 }
            );
        }


        /* =====================================================
           4. VERIFY SESSION
        ===================================================== */

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
                    error: "Invalid session."
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
                    error: "Session expired."
                },
                { status: 401 }
            );
        }


        /* =====================================================
           5. ADMIN CHECK
        ===================================================== */

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
                    error: "Admin access required."
                },
                { status: 403 }
            );
        }


        /* =====================================================
           6. GET WITHDRAWAL
        ===================================================== */

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
                    error: "Withdrawal not found."
                },
                { status: 404 }
            );
        }


        /* =====================================================
           7. BTC ONLY
        ===================================================== */

        if (
            withdrawal.currency !== "BTC"
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Only BTC withdrawals are supported."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           8. PENDING ONLY
        ===================================================== */

        if (
            withdrawal.status !== "pending"
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This withdrawal has already been processed."
                },
                { status: 409 }
            );
        }


        /* =====================================================
           9. REJECT
        ===================================================== */

        if (action === "reject") {

            /*
             * Mark rejected AND refund balance
             * in one D1 batch.
             *
             * This prevents a situation where the
             * withdrawal becomes rejected but the
             * refund fails.
             */

            const result =
                await context.env.DB.batch([

                    context.env.DB
                        .prepare(
                            `UPDATE withdrawals
                             SET
                                status = 'rejected',
                                processed_at = CURRENT_TIMESTAMP
                             WHERE id = ?
                               AND status = 'pending'`
                        )
                        .bind(
                            withdrawalId
                        ),

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


            if (
                !result ||
                !result[0] ||
                result[0].meta.changes !== 1
            ) {

                return Response.json(
                    {
                        success: false,
                        error:
                            "Withdrawal was already processed."
                    },
                    { status: 409 }
                );
            }


            return Response.json({

                success: true,

                status: "rejected",

                refunded:
                    withdrawal.amount,

                currency: "BTC"

            });
        }


        /* =====================================================
           10. APPROVE
        ===================================================== */

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


        /* =====================================================
           11. BTC → SATOSHIS
        ===================================================== */

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


        /* =====================================================
           12. FAUCETPAY V2 SEND
        ===================================================== */

        const faucetPayResponse =
            await fetch(
                "https://faucetpay.io/api/v2/send",
                {
                    method: "POST",

                    headers: {
                        "Authorization":
                            `Bearer ${apiKey}`,

                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({

                            idempotency_key:
                                `withdrawal-${withdrawal.id}`,

                            to:
                                withdrawal.wallet_address,

                            amount:
                                satoshis,

                            currency:
                                "BTC"

                        })
                }
            );


        let faucetPayResult = null;


        try {

            faucetPayResult =
                await faucetPayResponse.json();

        } catch {

            faucetPayResult = null;
        }


        /* =====================================================
           13. FAUCETPAY ERROR
        ===================================================== */

        if (
            !faucetPayResponse.ok ||
            !faucetPayResult ||
            faucetPayResult.success !== true
        ) {

            console.error(
                "FaucetPay payment failed:",
                faucetPayResult
            );


            return Response.json(
                {
                    success: false,

                    error:
                        faucetPayResult?.message ||
                        faucetPayResult?.error ||
                        "FaucetPay payment failed. Withdrawal remains pending."
                },

                {
                    status:
                        faucetPayResponse.status ||
                        502
                }
            );
        }


        /* =====================================================
           14. GET FAUCETPAY PAYOUT ID
        ===================================================== */

        const payoutId =
            faucetPayResult?.data?.payout_id ||
            faucetPayResult?.payout_id ||
            null;


        /*
         * IMPORTANT:
         *
         * payout_id is a FaucetPay reference.
         * It is NOT necessarily a blockchain TXID.
         *
         * We store it in the existing txid column
         * to avoid changing the database schema.
         */


        /* =====================================================
           15. MARK APPROVED
        ===================================================== */

        const updateResult =
            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET
                        status = 'approved',
                        processed_at = CURRENT_TIMESTAMP,
                        txid = ?
                     WHERE id = ?
                       AND status = 'pending'`
                )
                .bind(
                    payoutId
                        ? String(payoutId)
                        : null,

                    withdrawalId
                )
                .run();


        /* =====================================================
           16. DATABASE UPDATE FAILED
        ===================================================== */

        if (
            !updateResult ||
            updateResult.meta.changes !== 1
        ) {

            /*
             * DO NOT automatically retry.
             *
             * FaucetPay may already have paid.
             */

            console.error(
                "Database update failed after FaucetPay payment.",
                {
                    withdrawalId,
                    payoutId
                }
            );


            return Response.json(
                {
                    success: false,

                    error:
                        "Payment was sent, but withdrawal status could not be updated. Check FaucetPay before retrying.",

                    payoutId:
                        payoutId
                },

                { status: 500 }
            );
        }


        /* =====================================================
           17. SUCCESS
        ===================================================== */

        return Response.json({

            success: true,

            status:
                "approved",

            amount:
                withdrawal.amount,

            currency:
                "BTC",

            payoutId:
                payoutId

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
