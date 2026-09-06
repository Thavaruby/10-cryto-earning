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


/*
 * Get cookie value.
 */
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


/*
 * SHA-256 session token hash.
 */
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


        /*
         * BTC ONLY
         */

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

        /*
         * This is only a friendly response.
         *
         * The database trigger is the REAL protection.
         */

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
           8. CREATE WITHDRAWAL
        ===================================================== */

        /*
         * IMPORTANT
         *
         * Balance deduction is handled by the
         * database trigger:
         *
         * validate_withdrawal_before_insert
         *
         * The trigger checks:
         *
         * 1. User exists
         * 2. No pending/processing withdrawal
         * 3. Balance >= withdrawal amount
         *
         * Then it deducts the balance.
         *
         * If any check fails, SQLite aborts the INSERT.
         *
         * Therefore:
         *
         * withdrawal creation + balance deduction
         * happen atomically.
         */

        let withdrawalResult;

        try {

            withdrawalResult =
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
                        VALUES
                        (?, ?, ?, ?, 'pending')`
                    )
                    .bind(
                        session.user_id,
                        normalizedAmount,
                        walletAddress,
                        currency
                    )
                    .run();

        } catch (error) {

            const message =
                String(
                    error?.message || ""
                );


            /* ---------------------------------------------
               INSUFFICIENT BALANCE
               --------------------------------------------- */

            if (
                message.includes(
                    "INSUFFICIENT_BALANCE"
                )
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


            /* ---------------------------------------------
               DUPLICATE WITHDRAWAL
               --------------------------------------------- */

            if (
                message.includes(
                    "WITHDRAWAL_ALREADY_PENDING"
                )
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


            /* ---------------------------------------------
               USER NOT FOUND
               --------------------------------------------- */

            if (
                message.includes(
                    "USER_NOT_FOUND"
                )
            ) {

                return Response.json(
                    {
                        success: false,
                        error:
                            "User account not found."
                    },
                    { status: 404 }
                );
            }


            /*
             * Unexpected database error.
             */

            console.error(
                "Withdrawal insert error:",
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


        /* =====================================================
           9. VERIFY INSERT
        ===================================================== */

        if (
            !withdrawalResult.meta ||
            withdrawalResult.meta.changes !== 1
        ) {

            console.error(
                "Withdrawal insert did not create exactly one row.",
                {
                    userId:
                        session.user_id,

                    amount:
                        normalizedAmount
                }
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
             * Withdrawal already exists and balance was already
             * deducted by the database trigger.
             *
             * DO NOT modify the balance again.
             */

            console.error(
                "Withdrawal created but updated balance could not be loaded.",
                {
                    userId:
                        session.user_id
                }
            );


            return Response.json(
                {
                    success: false,
                    error:
                        "Your withdrawal was submitted successfully. Please check your balance again shortly."
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
