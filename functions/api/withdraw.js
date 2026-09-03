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
                       AND expires_at > CURRENT_TIMESTAMP
                     LIMIT 1`
                )
                .bind(tokenHash)
                .first();


        if (!session) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired session."
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
           7. FRIENDLY PRE-CHECK
        ===================================================== */

        const existingWithdrawal =
            await context.env.DB
                .prepare(
                    `SELECT
                        id,
                        status
                     FROM withdrawals
                     WHERE user_id = ?
                       AND status IN ('pending', 'processing')
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();


        if (existingWithdrawal) {

            return Response.json(
                {
                    success: false,
                    error:
                        "You already have a withdrawal being processed."
                },
                { status: 409 }
            );
        }


        /* =====================================================
           8. ATOMIC BALANCE + WITHDRAWAL CREATION
        ===================================================== */

        /*
         * IMPORTANT:
         *
         * The balance deduction and withdrawal INSERT
         * are executed in ONE atomic D1 batch.
         *
         * The balance UPDATE itself also checks that there is
         * no pending/processing withdrawal.
         *
         * This protects against concurrent withdrawal requests.
         */

        const atomicResult =
            await context.env.DB.batch([

                /* ---------------------------------------------
                   A. RESERVE BALANCE
                --------------------------------------------- */

                context.env.DB
                    .prepare(
                        `UPDATE users
                         SET balance = balance - ?
                         WHERE id = ?
                           AND balance >= ?
                           AND NOT EXISTS (
                               SELECT 1
                               FROM withdrawals
                               WHERE user_id = ?
                                 AND status IN ('pending', 'processing')
                           )`
                    )
                    .bind(
                        normalizedAmount,
                        session.user_id,
                        normalizedAmount,
                        session.user_id
                    ),


                /* ---------------------------------------------
                   B. CREATE WITHDRAWAL
                --------------------------------------------- */

                context.env.DB
                    .prepare(
                        `INSERT INTO withdrawals
                        (
                            user_id,
                            amount,
                            wallet_address,
                            currency,
                            status
                        )
                        SELECT
                            ?,
                            ?,
                            ?,
                            ?,
                            'pending'
                        WHERE EXISTS (
                            SELECT 1
                            FROM users
                            WHERE id = ?
                        )
                        AND NOT EXISTS (
                            SELECT 1
                            FROM withdrawals
                            WHERE user_id = ?
                              AND status IN ('pending', 'processing')
                        )`
                    )
                    .bind(
                        session.user_id,
                        normalizedAmount,
                        walletAddress,
                        currency,
                        session.user_id,
                        session.user_id
                    )
            ]);


        /* =====================================================
           9. VERIFY ATOMIC OPERATION
        ===================================================== */

        const balanceUpdate =
            atomicResult[0];

        const withdrawalInsert =
            atomicResult[1];


        if (
            !balanceUpdate.meta ||
            balanceUpdate.meta.changes !== 1 ||
            !withdrawalInsert.meta ||
            withdrawalInsert.meta.changes !== 1
        ) {

            /*
             * D1 batch is atomic.
             *
             * If either operation failed, the entire batch
             * is rolled back.
             *
             * Therefore NO manual refund is performed here.
             */

            const currentState =
                await context.env.DB
                    .prepare(
                        `SELECT
                            balance,
                            (
                                SELECT id
                                FROM withdrawals
                                WHERE user_id = ?
                                  AND status IN ('pending', 'processing')
                                LIMIT 1
                            ) AS existing_withdrawal
                         FROM users
                         WHERE id = ?
                         LIMIT 1`
                    )
                    .bind(
                        session.user_id,
                        session.user_id
                    )
                    .first();


            if (
                currentState &&
                currentState.existing_withdrawal
            ) {

                return Response.json(
                    {
                        success: false,
                        error:
                            "You already have a withdrawal being processed."
                    },
                    { status: 409 }
                );
            }


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

            /*
             * The withdrawal has already been created.
             *
             * Do NOT attempt another balance modification here.
             * The balance is already correctly reserved.
             */

            console.error(
                "Withdrawal created but updated balance could not be loaded.",
                {
                    userId: session.user_id
                }
            );

            return Response.json(
                {
                    success: false,
                    error:
                        "Withdrawal submitted, but balance could not be loaded."
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
