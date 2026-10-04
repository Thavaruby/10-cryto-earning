// ========================================
// ADMIN DETAILS
// GET /api/admin/details
//
// type:
// users
// claims
// withdrawals
//
// status:
// all
// pending
// processing
// approved
// rejected
//
// page:
// 1, 2, 3...
//
// limit:
// max 50
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


/* =====================================================
   HASH SESSION TOKEN
===================================================== */

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


/* =====================================================
   ADMIN AUTH
===================================================== */

async function checkAdmin(context, db) {

    const sessionToken =
        getCookie(
            context.request,
            "session"
        );

    if (!sessionToken) {
        return false;
    }


    const tokenHash =
        await hashSessionToken(
            sessionToken
        );


    const session =
        await db
            .prepare(
                `SELECT
                    user_id
                 FROM sessions
                 WHERE token_hash = ?
                   AND expires_at > CURRENT_TIMESTAMP
                 LIMIT 1`
            )
            .bind(tokenHash)
            .first();


    if (!session) {
        return false;
    }


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


    return !!admin;
}


/* =====================================================
   GET DETAILS
===================================================== */

export async function onRequestGet(context) {

    const db =
        context.env.DB.withSession(
            "first-primary"
        );


    try {

        /* =========================================
           ADMIN AUTHENTICATION
        ========================================= */

        const isAdmin =
            await checkAdmin(
                context,
                db
            );


        if (!isAdmin) {

            return Response.json(
                {
                    success: false,
                    error: "Unauthorized"
                },
                {
                    status: 401,
                    headers: {
                        "Cache-Control":
                            "no-store"
                    }
                }
            );
        }


        /* =========================================
           QUERY PARAMETERS
        ========================================= */

        const url =
            new URL(
                context.request.url
            );


        const type =
            String(
                url.searchParams.get("type") ||
                ""
            )
                .trim()
                .toLowerCase();


        const status =
            String(
                url.searchParams.get("status") ||
                "all"
            )
                .trim()
                .toLowerCase();


        const search =
            String(
                url.searchParams.get("search") ||
                ""
            )
                .trim()
                .toLowerCase();


        let page =
            Number(
                url.searchParams.get("page") ||
                1
            );


        let limit =
            Number(
                url.searchParams.get("limit") ||
                20
            );


        if (
            !Number.isInteger(page) ||
            page < 1
        ) {
            page = 1;
        }


        if (
            !Number.isInteger(limit) ||
            limit < 1
        ) {
            limit = 20;
        }


        /* Maximum 50 records per request */

        limit =
            Math.min(
                limit,
                50
            );


        const offset =
            (page - 1) * limit;


        /* =========================================
           ALLOWED TYPES
        ========================================= */

        const allowedTypes = [
            "users",
            "claims",
            "withdrawals"
        ];


        if (
            !allowedTypes.includes(type)
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid details type"
                },
                { status: 400 }
            );
        }


        /* =================================================
           USERS
        ================================================= */

        if (type === "users") {

            const searchPattern =
                `%${search}%`;


            const countResult =
                await db
                    .prepare(
                        `SELECT
                            COUNT(*) AS total
                         FROM users
                         WHERE
                            ? = ''
                            OR LOWER(email) LIKE ?`
                    )
                    .bind(
                        search,
                        searchPattern
                    )
                    .first();


            const users =
                await db
                    .prepare(
                        `SELECT
                            id,
                            email,
                            balance
                         FROM users
                         WHERE
                            ? = ''
                            OR LOWER(email) LIKE ?

                         ORDER BY id DESC

                         LIMIT ?
                         OFFSET ?`
                    )
                    .bind(
                        search,
                        searchPattern,
                        limit,
                        offset
                    )
                    .all();


            const total =
                Number(
                    countResult?.total || 0
                );


            return Response.json({

                success: true,

                type: "users",

                page,

                limit,

                total,

                totalPages:
                    Math.ceil(
                        total / limit
                    ),

                users:
                    users.results || []

            });
        }


        /* =================================================
           CLAIMS
        ================================================= */

        if (type === "claims") {

            const searchPattern =
                `%${search}%`;


            const countResult =
                await db
                    .prepare(
                        `SELECT
                            COUNT(*) AS total
                         FROM claims
                         JOIN users
                           ON users.id =
                              claims.user_id
                         WHERE
                            ? = ''
                            OR LOWER(users.email) LIKE ?`
                    )
                    .bind(
                        search,
                        searchPattern
                    )
                    .first();


            const claims =
                await db
                    .prepare(
                        `SELECT
                            claims.id,
                            claims.user_id,
                            users.email,
                            claims.reward,
                            claims.claimed_at
                         FROM claims
                         JOIN users
                           ON users.id =
                              claims.user_id
                         WHERE
                            ? = ''
                            OR LOWER(users.email) LIKE ?

                         ORDER BY claims.id DESC

                         LIMIT ?
                         OFFSET ?`
                    )
                    .bind(
                        search,
                        searchPattern,
                        limit,
                        offset
                    )
                    .all();


            const total =
                Number(
                    countResult?.total || 0
                );


            return Response.json({

                success: true,

                type: "claims",

                page,

                limit,

                total,

                totalPages:
                    Math.ceil(
                        total / limit
                    ),

                claims:
                    claims.results || []

            });
        }


        /* =================================================
           WITHDRAWALS
        ================================================= */

        if (type === "withdrawals") {

            const allowedStatuses = [
                "all",
                "pending",
                "processing",
                "approved",
                "rejected"
            ];


            if (
                !allowedStatuses.includes(
                    status
                )
            ) {

                return Response.json(
                    {
                        success: false,
                        error:
                            "Invalid withdrawal status"
                    },
                    { status: 400 }
                );
            }


            const searchPattern =
                `%${search}%`;


            const statusFilter =
                status === "all"
                    ? ""
                    : status;


            const countResult =
                await db
                    .prepare(
                        `SELECT
                            COUNT(*) AS total
                         FROM withdrawals
                         JOIN users
                           ON users.id =
                              withdrawals.user_id

                         WHERE
                            withdrawals.currency = 'BTC'

                            AND (
                                ? = ''
                                OR withdrawals.status = ?
                            )

                            AND (
                                ? = ''
                                OR LOWER(users.email) LIKE ?
                                OR LOWER(
                                    withdrawals.wallet_address
                                ) LIKE ?
                                OR LOWER(
                                    COALESCE(
                                        withdrawals.txid,
                                        ''
                                    )
                                ) LIKE ?
                                OR LOWER(
                                    COALESCE(
                                        withdrawals.payout_id,
                                        ''
                                    )
                                ) LIKE ?
                            )`
                    )
                    .bind(
                        statusFilter,
                        statusFilter,
                        search,
                        searchPattern,
                        searchPattern,
                        searchPattern,
                        searchPattern
                    )
                    .first();


            const withdrawals =
                await db
                    .prepare(
                        `SELECT
                            withdrawals.id,
                            withdrawals.user_id,
                            users.email,
                            withdrawals.amount,
                            withdrawals.balance_before,
                            users.balance AS current_balance,
                            withdrawals.wallet_address,
                            withdrawals.currency,
                            withdrawals.status,
                            withdrawals.created_at,
                            withdrawals.processed_at,
                            withdrawals.txid,
                            withdrawals.payout_id

                         FROM withdrawals

                         JOIN users
                           ON users.id =
                              withdrawals.user_id

                         WHERE
                            withdrawals.currency = 'BTC'

                            AND (
                                ? = ''
                                OR withdrawals.status = ?
                            )

                            AND (
                                ? = ''
                                OR LOWER(users.email) LIKE ?
                                OR LOWER(
                                    withdrawals.wallet_address
                                ) LIKE ?
                                OR LOWER(
                                    COALESCE(
                                        withdrawals.txid,
                                        ''
                                    )
                                ) LIKE ?
                                OR LOWER(
                                    COALESCE(
                                        withdrawals.payout_id,
                                        ''
                                    )
                                ) LIKE ?
                            )

                         ORDER BY
                            withdrawals.id DESC

                         LIMIT ?
                         OFFSET ?`
                    )
                    .bind(
                        statusFilter,
                        statusFilter,
                        search,
                        searchPattern,
                        searchPattern,
                        searchPattern,
                        searchPattern,
                        limit,
                        offset
                    )
                    .all();


            const total =
                Number(
                    countResult?.total || 0
                );


            return Response.json({

                success: true,

                type: "withdrawals",

                status,

                page,

                limit,

                total,

                totalPages:
                    Math.ceil(
                        total / limit
                    ),

                withdrawals:
                    withdrawals.results || []

            });
        }


    } catch (error) {

        console.error(
            "ADMIN DETAILS ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to load admin details."
            },
            {
                status: 500,
                headers: {
                    "Cache-Control":
                        "no-store"
                }
            }
        );
    }
      }
