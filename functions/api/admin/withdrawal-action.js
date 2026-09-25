// ========================================
// ADMIN WITHDRAWAL ACTION
// POST /api/admin/withdrawal-action
// ========================================


function getCookie(request, name) {

    const cookieHeader =
        request.headers.get("Cookie");

    if (!cookieHeader) return null;

    for (const cookie of cookieHeader.split(";")) {

        const [key, ...value] =
            cookie.trim().split("=");

        if (key === name) {
            return value.join("=");
        }
    }

    return null;
}


// ========================================
// HASH SESSION TOKEN
// ========================================

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


// ========================================
// ADMIN WITHDRAWAL ACTION
// ========================================

export async function onRequestPost(context) {

    // ========================================
    // D1 SESSION
    // ========================================

    const db =
        context.env.DB.withSession(
            "first-primary"
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
                    error:
                        "Invalid request."
                },
                {
                    status: 400,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        const withdrawalId =
            Number(data?.withdrawalId);


        const action =
            String(data?.action || "")
                .trim()
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
                {
                    status: 400,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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
                {
                    status: 400,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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
                {
                    status: 401,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        const tokenHash =
            await hashSessionToken(
                sessionToken
            );


        /*
         * IMPORTANT:
         *
         * login.js stores expires_at as an ISO timestamp.
         * Compare against the same ISO format instead of
         * SQLite CURRENT_TIMESTAMP text format.
         */

        const session =
            await db
                .prepare(
                    `SELECT
                        user_id,
                        expires_at
                     FROM sessions
                     WHERE token_hash = ?
                       AND expires_at > ?
                     LIMIT 1`
                )
                .bind(
                    tokenHash,
                    new Date().toISOString()
                )
                .first();


        if (!session) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired session."
                },
                {
                    status: 401,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           4. ADMIN CHECK
        ===================================================== */

        const admin =
            await db
                .prepare(
                    `SELECT
                        user_id
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
                {
                    status: 403,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           5. GET WITHDRAWAL
        ===================================================== */

        const withdrawal =
            await db
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
                {
                    status: 404,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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
                {
                    status: 400,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           7. REJECT
           
           PENDING → REJECTED

           Existing D1 trigger refunds the reserved
           withdrawal amount.
        ===================================================== */

        if (action === "reject") {

            const result =
                await db
                    .prepare(
                        `UPDATE withdrawals
                         SET
                            status = 'rejected',
                            processed_at =
                                CURRENT_TIMESTAMP
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
                    "WITHDRAWAL REJECTION FAILED."
                );


                return Response.json(
                    {
                        success: false,
                        error:
                            "Withdrawal was already processed or is being processed."
                    },
                    {
                        status: 409,
                        headers: {
                            "Cache-Control": "no-store"
                        }
                    }
                );
            }


            return Response.json(
                {
                    success: true,
                    status: "rejected",
                    refunded: withdrawal.amount,
                    currency: "BTC"
                },
                {
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           8. APPROVE
           
           Atomically claim the withdrawal:

           PENDING → PROCESSING

           This prevents two admins from paying
           the same withdrawal simultaneously.
        ===================================================== */

        const claimResult =
            await db
                .prepare(
                    `UPDATE withdrawals
                     SET
                        status = 'processing'
                     WHERE id = ?
                       AND status = 'pending'`
                )
                .bind(withdrawalId)
                .run();


        if (
            !claimResult ||
            !claimResult.meta ||
            claimResult.meta.changes !== 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "This withdrawal is already being processed or has already been processed."
                },
                {
                    status: 409,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           9. FAUCETPAY API KEY
        ===================================================== */

        const apiKey =
            context.env.FAUCETPAY_API_KEY;


        if (!apiKey) {

            console.error(
                "FAUCETPAY_API_KEY IS NOT CONFIGURED."
            );


            /*
             * Payment was NOT attempted.
             *
             * Safe to restore pending.
             */

            await db
                .prepare(
                    `UPDATE withdrawals
                     SET
                        status = 'pending'
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
                {
                    status: 500,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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

            console.error(
                "INVALID BTC WITHDRAWAL AMOUNT."
            );


            await db
                .prepare(
                    `UPDATE withdrawals
                     SET
                        status = 'pending'
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
                {
                    status: 400,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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

            console.error(
                "INVALID BTC SATOSHI AMOUNT."
            );


            await db
                .prepare(
                    `UPDATE withdrawals
                     SET
                        status = 'pending'
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
                {
                    status: 400,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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

        } catch {

            console.error(
                "FAUCETPAY NETWORK ERROR."
            );


            /*
             * We do NOT know whether FaucetPay
             * received or processed the request.
             *
             * Keep PROCESSING.
             *
             * DO NOT retry automatically.
             */

            return Response.json(
                {
                    success: false,
                    error:
                        "FaucetPay could not be reached. Withdrawal remains processing and requires reconciliation."
                },
                {
                    status: 502,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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


        /* =====================================================
           14. INVALID / UNCERTAIN RESPONSE
        ===================================================== */

        if (!faucetPayResult) {

            console.error(
                "FAUCETPAY RETURNED INVALID RESPONSE."
            );


            /*
             * We cannot safely determine whether
             * the payment was processed.
             *
             * Keep PROCESSING.
             */

            return Response.json(
                {
                    success: false,
                    error:
                        "FaucetPay returned an invalid response. Withdrawal remains processing and requires reconciliation."
                },
                {
                    status: 502,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
   15. EXPLICIT FAUCETPAY FAILURE
===================================================== */

const faucetPayExplicitFailure =
    faucetPayResult.success === false;


if (faucetPayExplicitFailure) {

    console.error(
        "FAUCETPAY PAYMENT FAILED:",
        JSON.stringify(faucetPayResult)
    );


    /*
     * FaucetPay explicitly rejected the request.
     *
     * Restore PENDING.
     */

    await db
        .prepare(
            `UPDATE withdrawals
             SET
                status = 'pending'
             WHERE id = ?
               AND status = 'processing'`
        )
        .bind(withdrawalId)
        .run();


    /* TEMPORARY DIAGNOSTIC:
       Show FaucetPay's actual error message
       so we can identify why the normal BTC
       wallet address was rejected.
    */

    const faucetPayError =
        faucetPayResult?.message ||
        faucetPayResult?.error ||
        faucetPayResult?.data?.message ||
        faucetPayResult?.data?.error ||
        "Unknown FaucetPay error.";


    return Response.json(
        {
            success: false,
            error:
                `FaucetPay payment failed: ${faucetPayError}`,
            faucetpay_response:
                faucetPayResult
        },
        {
            status: 502,
            headers: {
                "Cache-Control": "no-store"
            }
        }
    );
}


        /* =====================================================
           16. GET PAYOUT ID
        ===================================================== */

        const payoutId =
            faucetPayResult?.data?.payout_id ||
            faucetPayResult?.payout_id ||
            null;


        /* =====================================================
           17. PAYOUT ID REQUIRED
        ===================================================== */

        if (!payoutId) {

            console.error(
                "FAUCETPAY SUCCESS WITHOUT PAYOUT ID."
            );


            /*
             * FaucetPay response is not sufficiently
             * complete for reliable reconciliation.
             *
             * DO NOT:
             * - retry payment
             * - return to pending
             * - mark rejected
             *
             * Keep PROCESSING.
             */

            return Response.json(
                {
                    success: false,
                    error:
                        "FaucetPay response did not contain a payout ID. Withdrawal remains processing and requires reconciliation."
                },
                {
                    status: 500,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           18. SAVE PAYOUT ID FIRST
           
           IMPORTANT:
           
           FaucetPay has already confirmed the payout.
           
           Save payout_id while the withdrawal is still
           PROCESSING so reconciliation can identify the
           payment even if the following status update fails.
        ===================================================== */

        const payoutSaveResult =
            await db
                .prepare(
                    `UPDATE withdrawals
                     SET
                        payout_id = ?
                     WHERE id = ?
                       AND status = 'processing'
                       AND (payout_id IS NULL OR payout_id = '')`
                )
                .bind(
                    String(payoutId),
                    withdrawalId
                )
                .run();


        if (
            !payoutSaveResult ||
            !payoutSaveResult.meta
        ) {

            console.error(
                "PAYOUT ID SAVE FAILED AFTER PAYMENT."
            );


            /*
             * Payment already happened.
             *
             * DO NOT retry.
             * DO NOT return to pending.
             * Keep PROCESSING.
             */

            return Response.json(
                {
                    success: false,
                    error:
                        "Payment was sent by FaucetPay, but the payout ID could not be saved. Do not retry automatically.",
                    payout_id:
                        String(payoutId)
                },
                {
                    status: 500,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           19. MARK APPROVED
           
           PROCESSING → APPROVED
           
           payout_id has already been persisted.
        ===================================================== */

        const updateResult =
            await db
                .prepare(
                    `UPDATE withdrawals
                     SET
                        status = 'approved',
                        processed_at =
                            CURRENT_TIMESTAMP
                     WHERE id = ?
                       AND status = 'processing'
                       AND payout_id = ?`
                )
                .bind(
                    withdrawalId,
                    String(payoutId)
                )
                .run();


        /* =====================================================
           20. DATABASE UPDATE FAILURE
        ===================================================== */

        if (
            !updateResult ||
            !updateResult.meta ||
            updateResult.meta.changes !== 1
        ) {

            console.error(
                "DATABASE STATUS UPDATE FAILED AFTER PAYMENT."
            );


            /*
             * FaucetPay already confirmed payment.
             *
             * payout_id is already stored.
             *
             * DO NOT:
             * - retry payment
             * - return to pending
             * - mark rejected
             *
             * Keep PROCESSING for reconciliation.
             */

            return Response.json(
                {
                    success: false,

                    error:
                        "Payment was sent by FaucetPay, but the database status update failed. Do not retry automatically.",

                    payout_id:
                        String(payoutId)
                },
                {
                    status: 500,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =====================================================
           21. SUCCESS
        ===================================================== */

        return Response.json(
            {
                success: true,

                status:
                    "approved",

                amount:
                    withdrawal.amount,

                currency:
                    "BTC",

                payout_id:
                    String(payoutId)
            },
            {
                headers: {
                    "Cache-Control": "no-store"
                }
            }
        );


    } catch {

        console.error(
            "ADMIN WITHDRAWAL ACTION ERROR."
        );


        /*
         * IMPORTANT:
         *
         * If an unexpected error happens after
         * FaucetPay may have been contacted, we
         * must NOT automatically return the
         * withdrawal to pending.
         *
         * The PROCESSING state prevents accidental
         * duplicate payment.
         */

        return Response.json(
            {
                success: false,
                error:
                    "Unable to process withdrawal. If payment may have been sent, the withdrawal remains processing and requires reconciliation."
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
