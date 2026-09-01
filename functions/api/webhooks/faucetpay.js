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


export async function onRequestPost(context) {

    try {

        const rawBody =
            await context.request.text();

        const signature =
            context.request.headers.get(
                "X-FaucetPay-Signature"
            );

        const secret =
            context.env.FAUCETPAY_WEBHOOK_SECRET;


        /* =========================================
           CHECK SECRET
        ========================================= */

        if (!secret) {

            console.error(
                "FAUCETPAY_WEBHOOK_SECRET is missing"
            );

            return new Response(
                "Webhook secret missing",
                { status: 500 }
            );
        }


        /* =========================================
           VERIFY SIGNATURE
        ========================================= */

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


        /* =========================================
           PARSE EVENT
        ========================================= */

        const event =
            JSON.parse(rawBody);

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


        console.log(
            "FAUCETPAY WEBHOOK EVENT:",
            JSON.stringify(
                event,
                null,
                2
            )
        );


        /* =========================================
           ONLY PROCESS payout.sent
        ========================================= */

        if (
            eventType === "payout.sent"
        ) {

            const payoutId =
                event.data?.payout_id ?? null;

            const currency =
                event.data?.currency ?? null;

            const amount =
                event.data?.amount ?? null;

            const walletAddress =
                event.data?.to ?? null;


            console.log(
                "FAUCETPAY PAYOUT SENT:",
                JSON.stringify({
                    payoutId,
                    currency,
                    amount,
                    walletAddress
                })
            );


            if (!payoutId) {

                console.error(
                    "Webhook payout_id is missing"
                );

                return new Response(
                    "Missing payout_id",
                    { status: 400 }
                );
            }


            /* =====================================
               DUPLICATE EVENT CHECK
            ===================================== */

            const existingEvent =
                await context.env.DB
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


            /* =====================================
               FIND WITHDRAWAL
            ===================================== */

            const withdrawal =
                await context.env.DB
                    .prepare(`
                        SELECT
                            id,
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


            /* =====================================
               WITHDRAWAL NOT FOUND
            ===================================== */

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


            /* =====================================
               SAVE WEBHOOK EVENT
            ===================================== */

            await context.env.DB
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


            /* =====================================
               ALREADY APPROVED
            ===================================== */

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


            /* =====================================
               UPDATE WITHDRAWAL
            ===================================== */

            await context.env.DB
                .prepare(`
                    UPDATE withdrawals
                    SET
                        status = 'approved',
                        processed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `)
                .bind(
                    withdrawal.id
                )
                .run();


            console.log(
                "WITHDRAWAL UPDATED:",
                JSON.stringify({
                    withdrawalId:
                        withdrawal.id,

                    payoutId:
                        payoutId,

                    txid:
                        withdrawal.txid
                })
            );
        }


        /* =========================================
           SUCCESS
        ========================================= */

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
