const MIN_WITHDRAWAL = 0.0000001;

/*
 * Basic Bitcoin address validation.
 *
 * Supports:
 * - Legacy: 1...
 * - P2SH: 3...
 * - Native SegWit: bc1q...
 * - Taproot: bc1p...
 *
 * This is format validation only.
 * It does NOT verify that the address actually exists
 * or belongs to the user.
 */
function isValidBitcoinAddress(address) {

    const value = String(address || "").trim();

    if (value.length < 14 || value.length > 90) {
        return false;
    }

    const legacy =
        /^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/;

    const bech32 =
        /^bc1[ac-hj-np-z02-9]{11,87}$/;

    return (
        legacy.test(value) ||
        bech32.test(value.toLowerCase())
    );
}


function getCookie(request, name) {

    const cookieHeader =
        request.headers.get("Cookie");

    if (!cookieHeader) {
        return null;
    }

    for (
        const cookie of cookieHeader.split(";")
    ) {

        const [key, ...value] =
            cookie.trim().split("=");

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


        const amount =
            Number(data.amount);


        const walletAddress =
            String(
                data.walletAddress || ""
            ).trim();


        /* BTC ONLY */

        const currency = "BTC";


        /* =====================================================
           2. AMOUNT VALIDATION
        ===================================================== */

        if (
            !Number.isFinite(amount) ||
            amount <= 0
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid withdrawal amount."
                },
                { status: 400 }
            );
        }


        if (
            amount < MIN_WITHDRAWAL
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Minimum withdrawal is 0.0000001 BTC."
                },
                { status: 400 }
            );
        }


        /*
         * Prevent extremely long decimal values.
         *
         * BTC uses 8 decimal places.
         */

        const satoshis =
            Math.round(
                amount * 100000000
            );


        if (
            !Number.isSafeInteger(
                satoshis
            ) ||
            satoshis <= 0
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid BTC amount."
                },
                { status: 400 }
            );
        }


        const normalizedAmount =
            satoshis / 100000000;


        if (
            normalizedAmount !== amount
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "BTC amount can have a maximum of 8 decimal places."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           3. WALLET VALIDATION
        ===================================================== */

        if (!walletAddress) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Bitcoin wallet address is required."
                },
                { status: 400 }
            );
        }


        if (
            !isValidBitcoinAddress(
                walletAddress
            )
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid Bitcoin wallet address."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           4. SESSION
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


        /* =====================================================
           5. VERIFY SESSION
        ===================================================== */

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
           6. CHECK USER
        ===================================================== */

        const user =
            await context.env.DB
                .prepare(
                    `SELECT
                        id,
                        balance
                     FROM users
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();


        if (!user) {

            return Response.json(
                {
                    success: false,
                    error:
                        "User account not found."
                },
                { status: 404 }
            );
        }


        /* =====================================================
           7. PREVENT MULTIPLE PENDING WITHDRAWALS
        ===================================================== */

        const existingPending =
            await context.env.DB
                .prepare(
                    `SELECT id
                     FROM withdrawals
                     WHERE user_id = ?
                       AND status = 'pending'
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();


        if (existingPending) {

            return Response.json(
                {
                    success: false,
                    error:
                        "You already have a pending withdrawal."
                },
                { status: 409 }
            );
        }


        /* =====================================================
           8. RESERVE BALANCE
        ===================================================== */

        const reserveBalance =
            await context.env.DB
                .prepare(
                    `UPDATE users
                     SET balance = balance - ?
                     WHERE id = ?
                       AND balance >= ?`
                )
                .bind(
                    normalizedAmount,
                    session.user_id,
                    normalizedAmount
                )
                .run();


        if (
            !reserveBalance.meta ||
            reserveBalance.meta.changes !== 1
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Insufficient BTC balance."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           9. CREATE PENDING WITHDRAWAL
        ===================================================== */

        try {

            await context.env.DB
                .prepare(
                    `INSERT INTO withdrawals
                    (
                        user_id,
                        amount,
                        wallet_address,
                        currency,
                        status
                    )
                    VALUES (?, ?, ?, ?, 'pending')`
                )
                .bind(
                    session.user_id,
                    normalizedAmount,
                    walletAddress,
                    currency
                )
                .run();


        } catch (insertError) {

            /*
             * Restore balance if withdrawal creation fails.
             */

            await context.env.DB
                .prepare(
                    `UPDATE users
                     SET balance = balance + ?
                     WHERE id = ?`
                )
                .bind(
                    normalizedAmount,
                    session.user_id
                )
                .run();


            throw insertError;
        }


        /* =====================================================
           10. GET UPDATED BALANCE
        ===================================================== */

        const updatedUser =
            await context.env.DB
                .prepare(
                    `SELECT
                        balance
                     FROM users
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();


        if (!updatedUser) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Unable to load updated balance."
                },
                { status: 500 }
            );
        }


        /* =====================================================
           11. SUCCESS
        ===================================================== */

        return Response.json({

            success: true,

            message:
                "Withdrawal request submitted successfully.",

            status:
                "pending",

            amount:
                normalizedAmount,

            currency:
                "BTC",

            balance:
                updatedUser.balance
        });


    } catch (error) {

        console.error(
            "Withdrawal error:",
            error
        );


        /*
         * Do not expose internal database errors
         * to users.
         */

        return Response.json(
            {
                success: false,
                error:
                    "Unable to process withdrawal request."
            },
            { status: 500 }
        );
    }
}
