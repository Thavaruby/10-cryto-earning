// ========================================
// FAUCETPAY WEBHOOK
// payout.sent / payout.failed
// ========================================


async function verifySignature(rawBody, signature, secret) {

    if (!signature || !secret) {
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

    const expectedHex =
        Array.from(
            new Uint8Array(signatureBytes)
        )
        .map(
            b => b.toString(16).padStart(2, "0")
        )
        .join("");

    return signature ===
        `sha256=${expectedHex}`;
}


// ========================================
// WEBHOOK
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
                { status: 500 }
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
                { status: 401 }
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
                { status: 400 }
            );
        }


        const eventId =
            event.id ?? null;


        const eventType =
            event.event ?? null;


        if (!eventId || !eventType) {

            console.error(
                "Invalid FaucetPay webhook event"
            );

            return new Response(
                "Invalid event",
                { status: 400 }
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
                { status: 200 }
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
                { status: 400 }
            );
        }


        /* =========================
           7. DUPLICATE EVENT CHECK
        ========================= */

        const existingEvent =
            await db
                .prepare(`
                    SELECT id
                    FROM faucetpay_webhook_events
                    WHERE event_id = ?
                    LIMIT 1
                `)
                .bind(
                    String(eventId)
                )
                .first();


        if (existingEvent) {

            console.log(
                "Duplicate FaucetPay webhook:",
                eventId
            );

            return new Response(
                "OK",
                { status: 200 }
            );
        }


        /* =========================
           8. BTC ONLY
        ========================= */

        if (
            currency &&
            String(currency).toUpperCase() !== "BTC"
        ) {

            console.error(
                "Non-BTC FaucetPay webhook:",
                currency
            );

            return new Response(
                "Unsupported currency",
                { status: 400 }
            );
        }


        /* =========================
           9. FIND WITHDRAWAL
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
           10. WITHDRAWAL NOT FOUND
        ========================= */

        if (!withdrawal) {

            console.warn(
                "No withdrawal found for payout_id:",
                payoutId
            );

            return new Response(
                "OK",
                { status: 200 }
            );
        }


        /* =========================
           11. SAVE WEBHOOK EVENT
        ========================= */

        await db
            .prepare(`
                INSERT INTO faucetpay_webhook_events
                (
                    event_id,
                    event_type,
                    payout_id
                )
                VALUES (?, ?, ?)
            `)
            .bind(
                String(eventId),
                String(eventType),
                String(payoutId)
            )
            .run();


        /* =================================================
           12. PAYOUT SENT
        ================================================= */

        if (
            eventType === "payout.sent"
        ) {

            /* =========================
               ALREADY APPROVED
            ========================= */

            if (
                withdrawal.status === "approved"
            ) {

                console.log(
                    "Withdrawal already approved:",
                    withdrawal.id
                );

                return new Response(
                    "OK",
                    { status: 200 }
                );
            }


            /* =========================
               ONLY PROCESS PROCESSING
            ========================= */

            if (
                withdrawal.status !== "processing"
            ) {

                console.warn(
                    "Ignoring payout.sent for withdrawal status:",
                    withdrawal.status
                );

                return new Response(
                    "OK",
                    { status: 200 }
                );
            }


            /* =========================
               APPROVE WITHDRAWAL
            ========================= */

            const result =
                await db
                    .prepare(`
                        UPDATE withdrawals
                        SET
                            status = 'approved',
                            processed_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                          AND status = 'processing'
                          AND payout_id = ?
                    `)
                    .bind(
                        withdrawal.id,
                        String(payoutId)
                    )
                    .run();


            if (
                result.meta.changes !== 1
            ) {

                console.warn(
                    "Withdrawal was not updated:",
                    withdrawal.id
                );

                return new Response(
                    "OK",
                    { status: 200 }
                );
            }


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
        }


        /* =================================================
           13. PAYOUT FAILED
        ================================================= */

        if (
            eventType === "payout.failed"
        ) {

            /* =========================
               ONLY PROCESS PROCESSING
            ========================= */

            if (
                withdrawal.status !== "processing"
            ) {

                console.warn(
                    "Ignoring payout.failed for withdrawal status:",
                    withdrawal.status
                );

                return new Response(
                    "OK",
                    { status: 200 }
                );
            }


            /* =========================
               SAFELY REFUND + REJECT
            ========================= */

            const results =
                await db.batch([

                    db.prepare(`
                        UPDATE users
                        SET balance =
                            balance + (
                                SELECT amount
                                FROM withdrawals
                                WHERE id = ?
                                  AND status = 'processing'
                                  AND payout_id = ?
                            )
                        WHERE id = (
                            SELECT user_id
                            FROM withdrawals
                            WHERE id = ?
                              AND status = 'processing'
                              AND payout_id = ?
                        )
                    `).bind(
                        withdrawal.id,
                        String(payoutId),
                        withdrawal.id,
                        String(payoutId)
                    ),

                    db.prepare(`
                        UPDATE withdrawals
                        SET
                            status = 'rejected',
                            processed_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                          AND status = 'processing'
                          AND payout_id = ?
                    `).bind(
                        withdrawal.id,
                        String(payoutId)
                    )
                ]);


            const refundChanges =
                results[0]?.meta?.changes || 0;


            const withdrawalChanges =
                results[1]?.meta?.changes || 0;


            /* =========================
               VERIFY BOTH OPERATIONS
            ========================= */

            if (
                refundChanges !== 1 ||
                withdrawalChanges !== 1
            ) {

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
                            withdrawalChanges
                    })
                );

                /*
                 * D1 batch is transactional.
                 * If the batch failed, changes are rolled back.
                 */

                return new Response(
                    "Webhook processing error",
                    { status: 500 }
                );
            }


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
        }


        /* =========================
           SUCCESS
        ========================= */

        return new Response(
            "OK",
            { status: 200 }
        );


    } catch (error) {

        console.error(
            "FaucetPay webhook error:",
            error
        );

        return new Response(
            "Webhook error",
            { status: 500 }
        );
    }
}
