// ========================================
// ADMIN SUPPORT
// GET  /api/admin/support
// POST /api/admin/support
// ========================================


// ========================================
// GET COOKIE
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
// ADMIN AUTHENTICATION
// ========================================

async function getAdmin(context, db) {

    const sessionToken =
        getCookie(
            context.request,
            "session"
        );


    if (!sessionToken) {

        return {
            success: false,
            response: Response.json(
                {
                    success: false,
                    error: "Please login first"
                },
                { status: 401 }
            )
        };
    }


    const tokenHash =
        await hashSessionToken(
            sessionToken
        );


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

        return {
            success: false,
            response: Response.json(
                {
                    success: false,
                    error:
                        "Invalid or expired session"
                },
                { status: 401 }
            )
        };
    }


    const admin =
        await db
            .prepare(
                `SELECT user_id
                 FROM admins
                 WHERE user_id = ?
                 LIMIT 1`
            )
            .bind(session.user_id)
            .first();


    if (!admin) {

        return {
            success: false,
            response: Response.json(
                {
                    success: false,
                    error:
                        "Admin access required"
                },
                { status: 403 }
            )
        };
    }


    return {
        success: true,
        userId: session.user_id
    };
}


// ========================================
// GET SUPPORT
// ========================================

export async function onRequestGet(context) {

    const db =
        context.env.DB.withSession(
            "first-primary"
        );


    try {

        // ========================================
        // 1. ADMIN AUTH
        // ========================================

        const auth =
            await getAdmin(
                context,
                db
            );


        if (!auth.success) {
            return auth.response;
        }


        // ========================================
        // 2. READ PARAMETERS
        // ========================================

        const url =
            new URL(
                context.request.url
            );


        const ticketId =
            url.searchParams.get(
                "ticketId"
            );


        // ========================================
        // 3. LOAD ONE TICKET
        // ========================================

        if (ticketId) {

            const ticket =
                await db
                    .prepare(
                        `SELECT
                            support_tickets.id,
                            support_tickets.user_id,
                            users.email,
                            support_tickets.subject,
                            support_tickets.status,
                            support_tickets.created_at,
                            support_tickets.updated_at
                         FROM support_tickets
                         JOIN users
                           ON users.id =
                              support_tickets.user_id
                         WHERE support_tickets.id = ?
                         LIMIT 1`
                    )
                    .bind(ticketId)
                    .first();


            if (!ticket) {

                return Response.json(
                    {
                        success: false,
                        error:
                            "Support ticket not found"
                    },
                    { status: 404 }
                );
            }


            // ========================================
            // MARK USER MESSAGES AS READ BY ADMIN
            // ========================================

            await db
                .prepare(
                    `UPDATE support_messages
                     SET is_read = 1
                     WHERE ticket_id = ?
                       AND sender_type = 'user'`
                )
                .bind(ticketId)
                .run();


            // ========================================
            // LOAD MESSAGES
            // ========================================

            const messages =
                await db
                    .prepare(
                        `SELECT
                            id,
                            ticket_id,
                            sender_type,
                            message,
                            is_read,
                            created_at
                         FROM support_messages
                         WHERE ticket_id = ?
                         ORDER BY id ASC`
                    )
                    .bind(ticketId)
                    .all();


            return Response.json({

                success: true,

                ticket: ticket,

                messages:
                    messages.results || []

            });
        }


        // ========================================
        // 4. LOAD TICKET LIST
        // ========================================

        const requestedStatus =
            String(
                url.searchParams.get(
                    "status"
                ) || "all"
            ).toLowerCase();


        const allowedStatuses = [
            "all",
            "open",
            "replied",
            "closed"
        ];


        if (
            !allowedStatuses.includes(
                requestedStatus
            )
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid support status"
                },
                { status: 400 }
            );
        }


        let tickets;


        if (requestedStatus === "all") {

            tickets =
                await db
                    .prepare(
                        `SELECT
                            support_tickets.id,
                            support_tickets.user_id,
                            users.email,
                            support_tickets.subject,
                            support_tickets.status,
                            support_tickets.created_at,
                            support_tickets.updated_at,
                            (
                                SELECT message
                                FROM support_messages
                                WHERE ticket_id =
                                      support_tickets.id
                                ORDER BY id DESC
                                LIMIT 1
                            ) AS latest_message,
                            (
                                SELECT sender_type
                                FROM support_messages
                                WHERE ticket_id =
                                      support_tickets.id
                                ORDER BY id DESC
                                LIMIT 1
                            ) AS latest_sender
                         FROM support_tickets
                         JOIN users
                           ON users.id =
                              support_tickets.user_id
                         ORDER BY
                            support_tickets.updated_at DESC,
                            support_tickets.id DESC`
                    )
                    .all();

        } else {

            tickets =
                await db
                    .prepare(
                        `SELECT
                            support_tickets.id,
                            support_tickets.user_id,
                            users.email,
                            support_tickets.subject,
                            support_tickets.status,
                            support_tickets.created_at,
                            support_tickets.updated_at,
                            (
                                SELECT message
                                FROM support_messages
                                WHERE ticket_id =
                                      support_tickets.id
                                ORDER BY id DESC
                                LIMIT 1
                            ) AS latest_message,
                            (
                                SELECT sender_type
                                FROM support_messages
                                WHERE ticket_id =
                                      support_tickets.id
                                ORDER BY id DESC
                                LIMIT 1
                            ) AS latest_sender
                         FROM support_tickets
                         JOIN users
                           ON users.id =
                              support_tickets.user_id
                         WHERE support_tickets.status = ?
                         ORDER BY
                            support_tickets.updated_at DESC,
                            support_tickets.id DESC`
                    )
                    .bind(requestedStatus)
                    .all();
        }


        return Response.json({

            success: true,

            status:
                requestedStatus,

            tickets:
                tickets.results || []

        });


    } catch (error) {

        console.error(
            "ADMIN SUPPORT GET ERROR:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Internal server error"
            },
            { status: 500 }
        );
    }
}


// ========================================
// POST SUPPORT
// ADMIN REPLY
// ========================================

export async function onRequestPost(context) {

    const db =
        context.env.DB.withSession(
            "first-primary"
        );


    try {

        // ========================================
        // 1. ADMIN AUTH
        // ========================================

        const auth =
            await getAdmin(
                context,
                db
            );


        if (!auth.success) {
            return auth.response;
        }


        // ========================================
        // 2. READ JSON
        // ========================================

        let body;

        try {

            body =
                await context.request.json();

        } catch {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid request"
                },
                { status: 400 }
            );
        }


        const ticketId =
            Number(
                body.ticketId
            );


        const message =
            typeof body.message === "string"
                ? body.message.trim()
                : "";


        // ========================================
        // 3. VALIDATE TICKET ID
        // ========================================

        if (
            !Number.isInteger(ticketId) ||
            ticketId <= 0
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid ticket"
                },
                { status: 400 }
            );
        }


        // ========================================
        // 4. VALIDATE MESSAGE
        // ========================================

        if (!message) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Please enter a message"
                },
                { status: 400 }
            );
        }


        if (message.length > 3000) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Message is too long"
                },
                { status: 400 }
            );
        }


        // ========================================
        // 5. CHECK TICKET
        // ========================================

        const ticket =
            await db
                .prepare(
                    `SELECT
                        id,
                        user_id,
                        status
                     FROM support_tickets
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(ticketId)
                .first();


        if (!ticket) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Support ticket not found"
                },
                { status: 404 }
            );
        }


        // ========================================
        // 6. INSERT ADMIN MESSAGE
        // ========================================

        await db
            .prepare(
                `INSERT INTO support_messages
                    (
                        ticket_id,
                        sender_type,
                        message,
                        is_read
                    )
                 VALUES
                    (?, 'admin', ?, 0)`
            )
            .bind(
                ticketId,
                message
            )
            .run();


        // ========================================
        // 7. UPDATE TICKET
        // ========================================

        await db
            .prepare(
                `UPDATE support_tickets
                 SET
                    status = 'replied',
                    updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?`
            )
            .bind(ticketId)
            .run();


        // ========================================
        // 8. RESPONSE
        // ========================================

        return Response.json({

            success: true,

            message:
                "Reply sent successfully."

        });


    } catch (error) {

        console.error(
            "ADMIN SUPPORT POST ERROR:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Internal server error"
            },
            { status: 500 }
        );
    }
}
