// ========================================
// FAUCETPAY WEBHOOK
// payout.sent / payout.failed
// ========================================


async function verifySignature(
    rawBody,
    signature,
    secret
) {

    if (!signature || !secret) {
        return false;
    }


    const expectedPrefix =
        "sha256=";


    if (
        !signature.startsWith(
            expectedPrefix
        )
    ) {
        return false;
    }


    const receivedHex =
        signature.slice(
            expectedPrefix.length
        );


    if (
        receivedHex.length !== 64 ||
        !/^[0-9a-fA-F]{64}$/.test(
            receivedHex
        )
    ) {
        return false;
    }


    const key =
        await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(secret),
            {
                name: "HMAC",
                hash: "SHA-256"
            },
            false,
            ["sign"]
        );


    const signatureBytes =
        await crypto.subtle.sign(
            "HMAC",
            key,
            new TextEncoder().encode(rawBody)
        );


    const expectedBytes =
        new Uint8Array(
            signatureBytes
        );


    const receivedBytes =
        new Uint8Array(32);


    for (
        let i = 0;
        i < 32;
        i++
    ) {

        receivedBytes[i] =
            parseInt(
                receivedHex.slice(
                    i * 2,
                    i * 2 + 2
                ),
                16
            );
    }


    /* ========================================
       CONSTANT-TIME COMPARISON
    ======================================== */

    let difference = 0;


    for (
        let i = 0;
        i < expectedBytes.length;
        i++
    ) {

        difference |=
            expectedBytes[i] ^
            receivedBytes[i];
    }


    return difference === 0;
}


// ========================================
// WEBHOOK
// ========================================

export async function onRequestPost(
    context
) {

    const db =
        context.env.DB.withSession(
            "first-primary"
        );


    try {

        /* =========================
           1. READ RAW BODY
        ========================= */

        const rawBody =
            await context.request.text();


        const signature =
            context.request.headers.get(
                "X-FaucetPay-Signature"
            );


        const secret =
            context.env.FAUCETPAY_WEBHOOK_SECRET;


        /* =========================
           2. CHECK SECRET
        ========================= */

        if (!secret) {

            console.error(
                "FAUCETPAY_WEBHOOK_SECRET is missing"
            );

            return new Response(
                "Webhook secret missing",
                {
                    status: 500
                }
            );
        }


        /* =========================
           3. VERIFY SIGNATURE
        ========================= */

        const valid =
            await verifySignature(
                rawBody,
                signature,
                secret
            );


        if (!valid) {

            console.error(
                "Invalid FaucetPay webhook signature"
            );

            return new Response(
                "Invalid signature",
                {
                    status: 401
                }
            );
        }


        /* =========================
           4. PARSE EVENT
        ========================= */

        let event;


        try {

            event =
                JSON.parse(rawBody);

        } catch {

            console.error(
                "Invalid FaucetPay webhook JSON"
            );

            return new Response(
                "Invalid JSON",
                {
                    status: 400
                }
            );
        }


        const eventId =
            event.id ?? null;


        const eventType =
            event.event ?? null;


        if (
            !eventId ||
            !eventType
        ) {

            console.error(
                "Invalid FaucetPay webhook event"
            );

            return new Response(
                "Invalid event",
                {
                    status: 400
                }
            );
        }


        /* =========================
           5. ONLY PAYOUT EVENTS
        ========================= */

        if (
            eventType !== "payout.sent" &&
            eventType !== "payout.failed"
        ) {

            return new Response(
                "OK",
                {
                    status: 200
                }
            );
        }


        /* =========================
           6. READ PAYOUT DATA
        ========================= */

        const payoutId =
            event.data?.payout_id ?? null;


        const currency =
            event.data?.currency ?? null;


        const amount =
            event.data?.amount ?? null;


        const walletAddress =
            event.data?.to ?? null;


        if (!payoutId) {

            console.error(
                "Webhook payout_id is missing"
            );

            return new Response(
                "Missing payout_id",
                {
                    status: 400
                }
            );
        }


        /* =========================
           7. BTC ONLY
        ========================= */

        if (
            currency &&
            String(currency).toUpperCase() !==
                "BTC"
        ) {

            console.error(
                "Non-BTC FaucetPay webhook:",
                currency
            );

            return new Response(
                "Unsupported currency",
                {
                    status: 400
                }
            );
        }


        /* =========================
           8. FIND WITHDRAWAL
        ========================= */

        const withdrawal =
            await db
                .prepare(`
                    SELECT
                        id,
                        user_id,
                        amount,
                        wallet_address,
                        currency,
                        status,
                        payout_id,
                        txid
                    FROM withdrawals
                    WHERE payout_id = ?
                    LIMIT 1
                `)
                .bind(
                    String(payoutId)
                )
                .first();


        /* =========================
           9. WITHDRAWAL NOT FOUND
        ========================= */

        if (!withdrawal) {

            console.warn(
                "No withdrawal found for payout_id:",
                payoutId
            );

            return new Response(
                "OK",
                {
                    status: 200
                }
            );
        }


        /* =========================
           10. WITHDRAWAL CURRENCY
        ========================= */

        if (
            withdrawal.currency &&
            String(
                withdrawal.currency
            ).toUpperCase() !== "BTC"
        ) {

            console.error(
                "Withdrawal currency is not BTC:",
                withdrawal.id
            );

            return new Response(
                "Unsupported currency",
                {
                    status: 400
                }
            );
        }


        /* =================================================
           11. PAYOUT SENT
        ================================================= */

        if (
            eventType === "payout.sent"
        ) {

            /* =========================
               ALREADY APPROVED
            ========================= */

            if (
                withdrawal.status ===
                "approved"
            ) {

                console.log(
                    "Withdrawal already approved:",
                    withdrawal.id
                );

                return new Response(
                    "OK",
                    {
                        status: 200
                    }
                );
            }


            /* =========================
               ONLY PROCESS PROCESSING
            ========================= */

            if (
                withdrawal.status !==
                "processing"
            ) {

                console.warn(
                    "Ignoring payout.sent for withdrawal status:",
                    withdrawal.status
                );

                return new Response(
                    "OK",
                    {
                        status: 200
                    }
                );
            }


            /* =========================
               ATOMIC APPROVAL + EVENT
            ========================= */

            try {

                const results =
                    await db.batch([

                        /*
                         * First change the withdrawal.
                         */

                        db.prepare(`
                            UPDATE withdrawals
                            SET
                                status = 'approved',
                                processed_at =
                                    CURRENT_TIMESTAMP
                            WHERE id = ?
                              AND status = 'processing'
                              AND payout_id = ?
                        `).bind(
                            withdrawal.id,
                            String(payoutId)
                        ),


                        /*
                         * Record the webhook event only
                         * when the withdrawal is approved.
                         *
                         * This also handles a concurrent
                         * successful transition safely.
                         */

                        db.prepare(`
                            INSERT INTO
                            faucetpay_webhook_events
                            (
                                event_id,
                                event_type,
                                payout_id
                            )
                            SELECT ?, ?, ?
                            WHERE EXISTS (
                                SELECT 1
                                FROM withdrawals
                                WHERE id = ?
                                  AND status = 'approved'
                                  AND payout_id = ?
                            )
                        `).bind(
                            String(eventId),
                            String(eventType),
                            String(payoutId),
                            withdrawal.id,
                            String(payoutId)
                        )

                    ]);


                const withdrawalChanges =
                    results[0]
                        ?.meta
                        ?.changes || 0;


                const eventChanges =
                    results[1]
                        ?.meta
                        ?.changes || 0;


                /*
                 * Normal processing:
                 * withdrawal changed and event recorded.
                 */

                if (
                    withdrawalChanges === 1 &&
                    eventChanges === 1
                ) {

                    console.log(
                        "WITHDRAWAL APPROVED BY WEBHOOK:",
                        JSON.stringify({
                            withdrawalId:
                                withdrawal.id,

                            payoutId:
                                payoutId,

                            amount:
                                amount,

                            walletAddress:
                                walletAddress
                        })
                    );

                    return new Response(
                        "OK",
                        {
                            status: 200
                        }
                    );
                }


                /*
                 * If another request already completed
                 * the payout, check the current state.
                 */

                const currentWithdrawal =
                    await db
                        .prepare(`
                            SELECT status
                            FROM withdrawals
                            WHERE id = ?
                              AND payout_id = ?
                            LIMIT 1
                        `)
                        .bind(
                            withdrawal.id,
                            String(payoutId)
                        )
                        .first();


                if (
                    currentWithdrawal?.status ===
                    "approved"
                ) {

                    console.log(
                        "Payout.sent already processed:",
                        eventId
                    );

                    return new Response(
                        "OK",
                        {
                            status: 200
                        }
                    );
                }


                console.error(
                    "PAYOUT SENT PROCESSING FAILED:",
                    JSON.stringify({
                        withdrawalId:
                            withdrawal.id,

                        payoutId:
                            payoutId,

                        withdrawalChanges:
                            withdrawalChanges,

                        eventChanges:
                            eventChanges
                    })
                );


                return new Response(
                    "Webhook processing error",
                    {
                        status: 500
                    }
                );


            } catch (error) {

                /*
                 * A duplicate event_id can cause the
                 * INSERT to fail.
                 *
                 * Because this is a D1 batch, the
                 * withdrawal update is rolled back too.
                 */

                const currentWithdrawal =
                    await db
                        .prepare(`
                            SELECT status
                            FROM withdrawals
                            WHERE id = ?
                              AND payout_id = ?
                            LIMIT 1
                        `)
                        .bind(
                            withdrawal.id,
                            String(payoutId)
                        )
                        .first();


                if (
                    currentWithdrawal?.status ===
                    "approved"
                ) {

                    console.log(
                        "Duplicate successful payout.sent:",
                        eventId
                    );

                    return new Response(
                        "OK",
                        {
                            status: 200
                        }
                    );
                }


                console.error(
                    "PAYOUT SENT PROCESSING FAILED:",
                    error instanceof Error
                        ? error.message
                        : "Unknown error"
                );


                return new Response(
                    "Webhook processing error",
                    {
                        status: 500
                    }
                );
            }
        }


        /* =================================================
           12. PAYOUT FAILED
        ================================================= */

        if (
            eventType === "payout.failed"
        ) {

            /* =========================
               ONLY PROCESS PROCESSING
            ========================= */

            if (
                withdrawal.status !==
                "processing"
            ) {

                console.warn(
                    "Ignoring payout.failed for withdrawal status:",
                    withdrawal.status
                );

                return new Response(
                    "OK",
                    {
                        status: 200
                    }
                );
            }


            /* =========================
               ATOMIC REFUND + REJECT
               + EVENT
            ========================= */

            try {

                const results =
                    await db.batch([

                        /* =====================
                           REFUND USER
                        ===================== */

                        db.prepare(`
                            UPDATE users
                            SET balance =
                                balance + (
                                    SELECT amount
                                    FROM withdrawals
                                    WHERE id = ?
                                      AND status =
                                          'processing'
                                      AND payout_id = ?
                                )
                            WHERE id = (
                                SELECT user_id
                                FROM withdrawals
                                WHERE id = ?
                                  AND status =
                                      'processing'
                                  AND payout_id = ?
                            )
                        `).bind(
                            withdrawal.id,
                            String(payoutId),

                            withdrawal.id,
                            String(payoutId)
                        ),


                        /* =====================
                           REJECT WITHDRAWAL
                        ===================== */

                        db.prepare(`
                            UPDATE withdrawals
                            SET
                                status = 'rejected',
                                processed_at =
                                    CURRENT_TIMESTAMP
                            WHERE id = ?
                              AND status =
                                  'processing'
                              AND payout_id = ?
                        `).bind(
                            withdrawal.id,
                            String(payoutId)
                        ),


                        /* =====================
                           SAVE EVENT ONLY AFTER
                           WITHDRAWAL IS REJECTED
                        ===================== */

                        db.prepare(`
                            INSERT INTO
                            faucetpay_webhook_events
                            (
                                event_id,
                                event_type,
                                payout_id
                            )
                            SELECT ?, ?, ?
                            WHERE EXISTS (
                                SELECT 1
                                FROM withdrawals
                                WHERE id = ?
                                  AND status = 'rejected'
                                  AND payout_id = ?
                            )
                        `).bind(
                            String(eventId),
                            String(eventType),
                            String(payoutId),
                            withdrawal.id,
                            String(payoutId)
                        )

                    ]);


                const refundChanges =
                    results[0]
                        ?.meta
                        ?.changes || 0;


                const withdrawalChanges =
                    results[1]
                        ?.meta
                        ?.changes || 0;


                const eventChanges =
                    results[2]
                        ?.meta
                        ?.changes || 0;


                /* =========================
                   NORMAL SUCCESS
                ========================= */

                if (
                    refundChanges === 1 &&
                    withdrawalChanges === 1 &&
                    eventChanges === 1
                ) {

                    console.log(
                        "WITHDRAWAL REJECTED AND REFUNDED:",
                        JSON.stringify({
                            withdrawalId:
                                withdrawal.id,

                            payoutId:
                                payoutId,

                            amount:
                                withdrawal.amount,

                            userId:
                                withdrawal.user_id
                        })
                    );

                    return new Response(
                        "OK",
                        {
                            status: 200
                        }
                    );
                }


                /*
                 * Check current state after a possible
                 * concurrent webhook/request.
                 */

                const currentWithdrawal =
                    await db
                        .prepare(`
                            SELECT status
                            FROM withdrawals
                            WHERE id = ?
                              AND payout_id = ?
                            LIMIT 1
                        `)
                        .bind(
                            withdrawal.id,
                            String(payoutId)
                        )
                        .first();


                if (
                    currentWithdrawal?.status ===
                    "rejected"
                ) {

                    console.log(
                        "Payout.failed already processed:",
                        eventId
                    );

                    return new Response(
                        "OK",
                        {
                            status: 200
                        }
                    );
                }


                console.error(
                    "PAYOUT FAILED REFUND/REJECT FAILED:",
                    JSON.stringify({
                        withdrawalId:
                            withdrawal.id,

                        payoutId:
                            payoutId,

                        refundChanges:
                            refundChanges,

                        withdrawalChanges:
                            withdrawalChanges,

                        eventChanges:
                            eventChanges
                    })
                );


                return new Response(
                    "Webhook processing error",
                    {
                        status: 500
                    }
                );


            } catch (error) {

                /*
                 * If the event already exists, the
                 * unique event_id constraint causes
                 * the batch to fail.
                 *
                 * The batch rollback protects against
                 * duplicate refunding.
                 */

                const currentWithdrawal =
                    await db
                        .prepare(`
                            SELECT status
                            FROM withdrawals
                            WHERE id = ?
                              AND payout_id = ?
                            LIMIT 1
                        `)
                        .bind(
                            withdrawal.id,
                            String(payoutId)
                        )
                        .first();


                if (
                    currentWithdrawal?.status ===
                    "rejected"
                ) {

                    console.log(
                        "Duplicate successful payout.failed:",
                        eventId
                    );

                    return new Response(
                        "OK",
                        {
                            status: 200
                        }
                    );
                }


                console.error(
                    "PAYOUT FAILED PROCESSING ERROR:",
                    error instanceof Error
                        ? error.message
                        : "Unknown error"
                );


                return new Response(
                    "Webhook processing error",
                    {
                        status: 500
                    }
                );
            }
        }


        /* =========================
           SUCCESS
        ========================= */

        return new Response(
            "OK",
            {
                status: 200
            }
        );


    } catch (error) {

        console.error(
            "FaucetPay webhook error:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return new Response(
            "Webhook error",
            {
                status: 500
            }
        );
    }
}
