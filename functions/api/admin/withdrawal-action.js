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
             * Withdrawal was already deducted
             * from user's balance.
             *
             * Mark rejected + refund together.
             */

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

                refunded:
                    withdrawal.amount,

                currency: "BTC"

            });
        }


        /* =====================================================
           APPROVE
        ===================================================== */

        const apiKey =
            context.env.FAUCETPAY_API_KEY;


        if (!apiKey) {

            return Response.json(
                {
                    success: false,
                    error:
                        "FaucetPay API key is not configured"
                },
                { status: 500 }
            );
        }


        /* =========================
           BTC → SATOSHIS
        ========================= */

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
                        "Invalid BTC withdrawal amount"
                },
                { status: 400 }
            );
        }


        /* =========================
           IDEMPOTENCY KEY
        ========================= */

        const idempotencyKey =
            `withdrawal-${withdrawal.id}`;


        /* =========================
           FAUCETPAY V2 SEND
        ========================= */

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


        let faucetPayResult = null;


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
        "FaucetPay error:",
        faucetPayResult
    );

    return Response.json(
        {
            success: false,
            error:
                faucetPayResult?.message ||
                faucetPayResult?.error ||
                "FaucETPAY payment failed. Withdrawal remains pending."
        },
        { status: 502 }
    );
}


/* =========================
   GET PAYOUT ID.
========================= */

const payoutId =
    faucetPayResult?.data?.payout_id ||
    faucetPayResult?.payout_id ||
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
                 payout_id = ?
             WHERE id = ?
               AND status = 'pending'`
        )
        .bind(
            payoutId ? String(payoutId) : null,
            withdrawalId
        )
        .run();


if (
    !result ||
    result.meta.changes !== 1
) {

    console.error(
        "Database update failed after FaucetPay payment",
        {
            withdrawalId,
            payoutId
        }
    );

    return Response.json(
        {
            success: false,
            error:
                "Payment was sent by FaucetPay, but database update failed. Do not retry automatically.",
            payout_id:
                payoutId
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
                    error?.message ||
                    "Unable to process withdrawal."
            },
            { status: 500 }
        );
    }

let faucetPayResult = null;

try {

    faucetPayResult =
        await faucetPayResponse.json();

} catch {

    faucetPayResult = null;

        }

console.log(
    "FAUCETPAY STATUS:",
    faucetPayResponse.status
);

console.log(
    "FAUCETPAY RESPONSE:",
    JSON.stringify(faucetPayResult)
);
}
