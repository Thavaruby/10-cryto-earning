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


export async function onRequestPost(context) {

    console.log(
        "WITHDRAWAL ACTION FUNCTION CALLED"
    );

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
            String(data.action || "")
                .toLowerCase();


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
                    error:
                        "Invalid withdrawal ID."
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
                    error:
                        "Invalid action."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           3. SESSION
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
                    error:
                        "Please login first."
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
                    error:
                        "Invalid session."
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
                    error:
                        "Session expired."
                },
                { status: 401 }
            );
        }


        /* =====================================================
           4. ADMIN CHECK
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
                    error:
                        "Admin access required."
                },
                { status: 403 }
            );
        }


        /* =====================================================
           5. GET WITHDRAWAL
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
                        status,
                        payout_id,
                        txid
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
                    error:
                        "Withdrawal not found."
                },
                { status: 404 }
            );
        }


        /* =====================================================
           6. BTC ONLY
        ===================================================== */

        if (
            String(withdrawal.currency)
                .toUpperCase() !== "BTC"
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
   7. REJECT
     
   PENDING → REJECTED
     
   The database trigger automatically refunds
   the reserved withdrawal amount to the user.
     
   Refund happens exactly once because the UPDATE
   only succeeds when status is still 'pending'.
===================================================== */

if (action === "reject") {

    const result =
        await context.env.DB
            .prepare(
                `UPDATE withdrawals
                 SET
                    status = 'rejected',
                    processed_at = CURRENT_TIMESTAMP
                 WHERE id = ?
                   AND status = 'pending'`
            )
            .bind(withdrawalId)
            .run();


    if (
        !result ||
        !result.meta ||
        result.meta.changes !== 1
    ) {

        console.error(
            "Withdrawal rejection failed or already processed:",
            {
                withdrawalId
            }
        );


        return Response.json(
            {
                success: false,
                error:
                    "Withdrawal was already processed or is being processed."
            },
            { status: 409 }
        );
    }


    console.log(
        "WITHDRAWAL REJECTED:",
        JSON.stringify({
            withdrawalId,
            refunded: withdrawal.amount,
            userId: withdrawal.user_id
        })
    );


    return Response.json({

        success: true,

        status:
            "rejected",

        refunded:
            withdrawal.amount,

        currency:
            "BTC"

    });
}
        

        /* =====================================================
           8. APPROVE
           
           IMPORTANT:
           
           Atomically claim the withdrawal first:
           
           PENDING → PROCESSING
           
           This prevents two admins from sending
           the same withdrawal simultaneously.
        ===================================================== */

        const claimResult =
            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET status = 'processing'
                     WHERE id = ?
                       AND status = 'pending'`
                )
                .bind(withdrawalId)
                .run();


        if (
            !claimResult ||
            claimResult.meta.changes !== 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This withdrawal is already being processed or has already been processed."
                },
                { status: 409 }
            );
        }


        /* =====================================================
           9. FAUCETPAY API KEY
        ===================================================== */

        const apiKey =
            context.env.FAUCETPAY_API_KEY;


        if (!apiKey) {

            /* Restore pending because
               payment was not attempted. */

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
                        "FaucetPay API key is not configured."
                },
                { status: 500 }
            );
        }


        /* =====================================================
           10. BTC → SATOSHIS
        ===================================================== */

        const amountBTC =
            Number(withdrawal.amount);


        if (
            !Number.isFinite(amountBTC) ||
            amountBTC <= 0
        ) {

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
                        "Invalid BTC withdrawal amount."
                },
                { status: 400 }
            );
        }


        const satoshis =
            Math.round(
                amountBTC * 100000000
            );


        if (
            !Number.isSafeInteger(satoshis) ||
            satoshis <= 0
        ) {

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
                        "Invalid BTC withdrawal amount."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           11. IDEMPOTENCY KEY
        ===================================================== */

        const idempotencyKey =
            `withdrawal-${withdrawal.id}`;


        /* =====================================================
           12. FAUCETPAY SEND
        ===================================================== */

        console.log(
            "SENDING FAUCETPAY PAYMENT:",
            JSON.stringify({
                withdrawalId:
                    withdrawal.id,

                satoshis,

                currency:
                    "BTC",

                idempotencyKey
            })
        );


        let faucetPayResponse;

        try {

            faucetPayResponse =
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

                        body: JSON.stringify({

                            idempotency_key:
                                idempotencyKey,

                            to:
                                withdrawal.wallet_address,

                            amount:
                                satoshis,

                            currency:
                                "BTC"
                        })
                    }
                );

        } catch (error) {

            console.error(
                "FaucetPay network error:",
                error
            );


            /* Payment was not confirmed.
               Return withdrawal to pending. */

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
                        "FaucetPay could not be reached. Withdrawal remains pending."
                },
                { status: 502 }
            );
        }


        /* =====================================================
           13. READ FAUCETPAY RESPONSE
        ===================================================== */

        let faucetPayResult = null;


        try {

            faucetPayResult =
                await faucetPayResponse.json();

        } catch {

            faucetPayResult = null;
        }


        console.log(
            "FAUCETPAY HTTP STATUS:",
            faucetPayResponse.status
        );


        console.log(
            "FAUCETPAY RESPONSE:",
            JSON.stringify(
                faucetPayResult
            )
        );


        /* =====================================================
           14. FAUCETPAY ERROR
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


            /* Payment was not confirmed.
               Restore pending. */

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
                        faucetPayResult?.message ||
                        faucetPayResult?.error ||
                        "FaucetPay payment failed. Withdrawal remains pending."
                },
                { status: 502 }
            );
        }


        /* =====================================================
           15. GET PAYOUT ID
        ===================================================== */

        const payoutId =
            faucetPayResult?.data?.payout_id ||
            faucetPayResult?.payout_id ||
            null;


        console.log(
            "FAUCETPAY PAYMENT SUCCESS:",
            JSON.stringify({
                withdrawalId:
                    withdrawal.id,

                payoutId
            })
        );


        /* =====================================================
           16. MARK APPROVED
           
           PROCESSING → APPROVED
        ===================================================== */

        const updateResult =
            await context.env.DB
                .prepare(
                    `UPDATE withdrawals
                     SET
                        status = 'approved',
                        processed_at =
                            CURRENT_TIMESTAMP,
                        payout_id = ?
                     WHERE id = ?
                       AND status = 'processing'`
                )
                .bind(
                    payoutId
                        ? String(payoutId)
                        : null,

                    withdrawalId
                )
                .run();


        /* =====================================================
           17. DATABASE UPDATE FAILURE
        ===================================================== */

        if (
            !updateResult ||
            updateResult.meta.changes !== 1
        ) {

            console.error(
                "DATABASE UPDATE FAILED AFTER PAYMENT:",
                JSON.stringify({
                    withdrawalId,
                    payoutId
                })
            );


            /*
             * FaucetPay payment has already succeeded.
             *
             * DO NOT retry automatically.
             *
             * Keep PROCESSING so it is obvious that
             * manual investigation is required.
             */

            return Response.json(
                {
                    success: false,

                    error:
                        "Payment was sent by FaucetPay, but the database update failed. Do not retry automatically.",

                    payout_id:
                        payoutId
                },
                { status: 500 }
            );
        }


        /* =====================================================
           18. SUCCESS
        ===================================================== */

        console.log(
            "WITHDRAWAL APPROVED:",
            JSON.stringify({
                withdrawalId:
                    withdrawal.id,

                payoutId,

                amount:
                    withdrawal.amount,

                currency:
                    "BTC"
            })
        );


        return Response.json({

            success: true,

            status:
                "approved",

            amount:
                withdrawal.amount,

            currency:
                "BTC",

            payout_id:
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
