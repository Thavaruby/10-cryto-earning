const MIN_WITHDRAWAL = 0.0000001;

/*
 * Bitcoin address format validation.
 *
 * Supports:
 * - Legacy: 1...
 * - P2SH: 3...
 * - Native SegWit: bc1q...
 * - Taproot: bc1p...
 *
 * This is format validation only.
 * It does NOT verify the Bitcoin address checksum.
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

    for (const cookie of cookieHeader.split(";")) {
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

/*
 * Standard JSON response.
 */
function jsonResponse(data, status = 200) {
    return Response.json(data, {
        status,
        headers: {
            "Cache-Control":
                "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    });
}

export async function onRequestPost(context) {
    try {
        const db =
            context.env.DB.withSession("first-primary");

        /* =====================================================
           1. READ REQUEST
        ===================================================== */

        let data;

        try {
            data =
                await context.request.json();
        } catch {
            return jsonResponse(
                {
                    success: false,
                    error: "Invalid request."
                },
                400
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
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid withdrawal amount."
                },
                400
            );
        }

        if (amount < MIN_WITHDRAWAL) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Minimum withdrawal is 0.0000001 BTC."
                },
                400
            );
        }

        /*
         * BTC has 8 decimal places.
         *
         * Convert to satoshis first so that we never
         * accept a value with more than 8 decimals.
         */
        const satoshis =
            Math.round(
                amount * 100000000
            );

        if (
            !Number.isSafeInteger(satoshis) ||
            satoshis <= 0
        ) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid BTC amount."
                },
                400
            );
        }

        const normalizedAmount =
            satoshis / 100000000;

        if (
            normalizedAmount !== amount
        ) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "BTC amount can have a maximum of 8 decimal places."
                },
                400
            );
        }

        /* =====================================================
           3. WALLET VALIDATION
        ===================================================== */

        if (!walletAddress) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Bitcoin wallet address is required."
                },
                400
            );
        }

        if (
            !isValidBitcoinAddress(
                walletAddress
            )
        ) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid Bitcoin wallet address."
                },
                400
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
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Please login first."
                },
                401
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
            await db
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
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid or expired session."
                },
                401
            );
        }

        const userId =
            Number(session.user_id);

        if (
            !Number.isInteger(userId) ||
            userId <= 0
        ) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid user session."
                },
                401
            );
        }

        /* =====================================================
           6. VERIFY USER
        ===================================================== */

        const user =
            await db
                .prepare(
                    `SELECT
                        id,
                        balance
                     FROM users
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(userId)
                .first();

        if (!user) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "User account not found."
                },
                404
            );
        }

        /* =====================================================
           7. FRIENDLY DUPLICATE CHECK
           ===================================================== */

        /*
         * This check is only for a fast user-friendly response.
         *
         * It is NOT the real security protection.
         *
         * The database trigger remains authoritative and
         * protects against concurrent requests.
         */

        const existingWithdrawal =
            await db
                .prepare(
                    `SELECT
                        id,
                        status
                     FROM withdrawals
                     WHERE user_id = ?
                       AND status IN ('pending', 'processing')
                     LIMIT 1`
                )
                .bind(userId)
                .first();

        if (existingWithdrawal) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "You already have a withdrawal being processed."
                },
                409
            );
        }

        /* =====================================================
           8. CREATE WITHDRAWAL
           ===================================================== */

        /*
         * IMPORTANT:
         *
         * The database trigger
         * validate_withdrawal_before_insert
         * performs the authoritative checks:
         *
         * 1. User exists
         * 2. No pending/processing withdrawal
         * 3. Balance is sufficient
         * 4. Balance is deducted
         *
         * If a check fails, SQLite aborts the INSERT.
         *
         * Therefore the withdrawal creation and balance
         * deduction are atomic at the database level.
         */

        let withdrawalResult;

        try {
            withdrawalResult =
                await db
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
                        userId,
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

            if (
                message.includes(
                    "INSUFFICIENT_BALANCE"
                )
            ) {
                return jsonResponse(
                    {
                        success: false,
                        error:
                            "Insufficient BTC balance."
                    },
                    400
                );
            }

            if (
                message.includes(
                    "WITHDRAWAL_ALREADY_PENDING"
                )
            ) {
                return jsonResponse(
                    {
                        success: false,
                        error:
                            "You already have a withdrawal being processed."
                    },
                    409
                );
            }

            if (
                message.includes(
                    "USER_NOT_FOUND"
                )
            ) {
                return jsonResponse(
                    {
                        success: false,
                        error:
                            "User account not found."
                    },
                    404
                );
            }

            console.error(
                "Withdrawal insert error:",
                error
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to process withdrawal request."
                },
                500
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
                    userId,
                    amount: normalizedAmount
                }
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to process withdrawal request."
                },
                500
            );
        }

        /* =====================================================
           10. GET UPDATED BALANCE
           ===================================================== */

        const updatedUser =
            await db
                .prepare(
                    `SELECT
                        balance
                     FROM users
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(userId)
                .first();

        if (!updatedUser) {
            /*
             * IMPORTANT:
             *
             * The withdrawal was already created and the
             * balance was already deducted.
             *
             * Never deduct the balance again here.
             */

            console.error(
                "Withdrawal created but updated balance could not be loaded.",
                {
                    userId
                }
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Your withdrawal was submitted successfully. Please check your balance again shortly."
                },
                500
            );
        }

        const balance =
            Number(updatedUser.balance);

        if (
            !Number.isFinite(balance) ||
            balance < 0
        ) {
            console.error(
                "Invalid balance returned after withdrawal.",
                {
                    userId,
                    balance: updatedUser.balance
                }
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Your withdrawal was submitted successfully. Please check your balance again shortly."
                },
                500
            );
        }

        /* =====================================================
           11. SUCCESS
           ===================================================== */

        return jsonResponse({
            success: true,

            message:
                "Withdrawal request submitted successfully.",

            status: "pending",

            amount:
                normalizedAmount,

            currency: "BTC",

            balance
        });

    } catch (error) {
        console.error(
            "Withdrawal error:",
            error
        );

        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to process withdrawal request."
            },
            500
        );
    }
}
