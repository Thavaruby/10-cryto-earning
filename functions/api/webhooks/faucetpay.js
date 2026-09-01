async function verifySignature(rawBody, signature, secret) {
    if (!signature || !secret) {
        return false;
    }

    const expectedData = new TextEncoder().encode(
        secret
    );

    const key = await crypto.subtle.importKey(
        "raw",
        expectedData,
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
            .map(b =>
                b.toString(16).padStart(2, "0")
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

        if (!secret) {

            console.error(
                "FAUCETPAY_WEBHOOK_SECRET is missing"
            );

            return new Response(
                "Webhook secret missing",
                { status: 500 }
            );
        }


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


        const event =
            JSON.parse(rawBody);


        console.log(
            "FAUCETPAY WEBHOOK EVENT:",
            JSON.stringify(
                event,
                null,
                2
            )
        );


        if (event.event === "payout.sent") {

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

    /*
     * Find the withdrawal created by
     * the FaucetPay payout.
     */
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
            .bind(String(payoutId))
            .first();


    /*
     * Withdrawal not found.
     */
    if (!withdrawal) {

        console.warn(
            "No withdrawal found for payout_id:",
            payoutId
        );

        /*
         * Still return 200 so FaucetPay
         * does not repeatedly retry the event.
         */
        return new Response(
            "OK",
            { status: 200 }
        );
    }


    /*
     * Already processed.
     */
    if (
        withdrawal.status === "approved"
        &&
        withdrawal.payout_id
    ) {

        console.log(
            "Withdrawal already processed:",
            withdrawal.id
        );

        return new Response(
            "OK",
            { status: 200 }
        );
    }


    /*
     * Update withdrawal.
     *
     * TXID remains NULL because the
     * payout.sent webhook does not contain
     * a blockchain transaction hash.
     */
    await context.env.DB
        .prepare(`
            UPDATE withdrawals
            SET
                status = 'approved',
                processed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `)
        .bind(withdrawal.id)
        .run();


    console.log(
        "WITHDRAWAL UPDATED:",
        JSON.stringify({
            withdrawalId: withdrawal.id,
            payoutId: payoutId,
            txid: withdrawal.txid
        })
    );
}


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
