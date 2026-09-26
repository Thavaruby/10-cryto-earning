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


function getCookie(request, name) {

    const cookieHeader =
        request.headers.get("Cookie");

    if (!cookieHeader) return null;

    const cookies =
        cookieHeader.split(";");

    for (const cookie of cookies) {

        const [
            key,
            ...value
        ] =
            cookie.trim().split("=");

        if (key === name) {

            try {

                return decodeURIComponent(
                    value.join("=")
                );

            } catch {

                return null;
            }
        }
    }

    return null;
}


function jsonResponse(
    data,
    status = 200
) {

    return new Response(
        JSON.stringify(data),
        {
            status,

            headers: {
                "Content-Type":
                    "application/json",

                "Cache-Control":
                    "no-store"
            }
        }
    );
}


/* =================================================
   GET SUPPORT TICKETS
================================================= */

export async function onRequestGet(
    context
) {

    try {

        const db =
            context.env.DB
                .withSession(
                    "first-primary"
                );


        /* =========================================
           SESSION
        ========================================= */

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
                        "Not logged in"
                },
                401
            );
        }


        const tokenHash =
            await hashSessionToken(
                sessionToken
            );


        const session =
            await db
                .prepare(
                    `SELECT
                        sessions.user_id,
                        sessions.expires_at
                     FROM sessions
                     WHERE sessions.token_hash = ?
                     LIMIT 1`
                )
                .bind(tokenHash)
                .first();


        if (!session) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid session"
                },
                401
            );
        }


        const expiresAt =
            new Date(
                session.expires_at
            );


        if (
            Number.isNaN(
                expiresAt.getTime()
            ) ||
            expiresAt <= new Date()
        ) {

            await db
                .prepare(
                    `DELETE FROM sessions
                     WHERE token_hash = ?`
                )
                .bind(tokenHash)
                .run();


            return jsonResponse(
                {
                    success: false,
                    error:
                        "Session expired"
                },
                401
            );
        }


        const userId =
            Number(
                session.user_id
            );


        /* =========================================
           LOAD USER'S TICKETS
        ========================================= */

        const tickets =
            await db
                .prepare(
                    `SELECT
                        id,
                        subject,
                        status,
                        created_at,
                        updated_at
                     FROM support_tickets
                     WHERE user_id = ?
                     ORDER BY updated_at DESC`
                )
                .bind(userId)
                .all();


        const ticketList =
            tickets.results || [];


        /* =========================================
           LOAD MESSAGES
        ========================================= */

        for (
            const ticket
            of ticketList
        ) {

            const messages =
                await db
                    .prepare(
                        `SELECT
                            id,
                            sender_type,
                            message,
                            is_read,
                            created_at
                         FROM support_messages
                         WHERE ticket_id = ?
                         ORDER BY id ASC`
                    )
                    .bind(ticket.id)
                    .all();


            ticket.messages =
                messages.results || [];
        }


        return jsonResponse(
            {
                success: true,
                tickets:
                    ticketList
            }
        );


    } catch (error) {

        console.error(
            "SUPPORT GET ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );


        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to load support messages."
            },
            500
        );
    }
}


/* =================================================
   CREATE SUPPORT TICKET
================================================= */

export async function onRequestPost(
    context
) {

    try {

        const db =
            context.env.DB
                .withSession(
                    "first-primary"
                );


        /* =========================================
           SESSION
        ========================================= */

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
                        "Not logged in"
                },
                401
            );
        }


        const tokenHash =
            await hashSessionToken(
                sessionToken
            );


        const session =
            await db
                .prepare(
                    `SELECT
                        sessions.user_id,
                        sessions.expires_at
                     FROM sessions
                     WHERE sessions.token_hash = ?
                     LIMIT 1`
                )
                .bind(tokenHash)
                .first();


        if (!session) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid session"
                },
                401
            );
        }


        const expiresAt =
            new Date(
                session.expires_at
            );


        if (
            Number.isNaN(
                expiresAt.getTime()
            ) ||
            expiresAt <= new Date()
        ) {

            await db
                .prepare(
                    `DELETE FROM sessions
                     WHERE token_hash = ?`
                )
                .bind(tokenHash)
                .run();


            return jsonResponse(
                {
                    success: false,
                    error:
                        "Session expired"
                },
                401
            );
        }


        const userId =
            Number(
                session.user_id
            );


        /* =========================================
           REQUEST BODY
        ========================================= */

        let body;

        try {

            body =
                await context.request.json();

        } catch {

            return jsonResponse(
                {
                    success: false,
                    errorMessage:
                        "Invalid request."
                },
                400
            );
        }


        const subject =
            String(
                body.subject || ""
            ).trim();


        const message =
            String(
                body.message || ""
            ).trim();


        /* =========================================
           VALIDATION
        ========================================= */

        if (!subject) {

            return jsonResponse(
                {
                    success: false,
                    errorMessage:
                        "Please enter a subject."
                },
                400
            );
        }


        if (subject.length > 100) {

            return jsonResponse(
                {
                    success: false,
                    errorMessage:
                        "Subject is too long."
                },
                400
            );
        }


        if (!message) {

            return jsonResponse(
                {
                    success: false,
                    errorMessage:
                        "Please enter your message."
                },
                400
            );
        }


        if (message.length > 3000) {

            return jsonResponse(
                {
                    success: false,
                    errorMessage:
                        "Message is too long. Maximum 3000 characters."
                },
                400
            );
        }


        /* =========================================
           CREATE TICKET
        ========================================= */

        const ticketResult =
            await db
                .prepare(
                    `INSERT INTO support_tickets
                    (
                        user_id,
                        subject,
                        status
                    )
                    VALUES (?, ?, 'open')`
                )
                .bind(
                    userId,
                    subject
                )
                .run();


        const ticketId =
            ticketResult.meta
                ?.last_row_id;


        if (!ticketId) {

            console.error(
                "SUPPORT TICKET INSERT FAILED."
            );


            return jsonResponse(
                {
                    success: false,
                    errorMessage:
                        "Unable to create support request."
                },
                500
            );
        }


        /* =========================================
           SAVE USER MESSAGE
        ========================================= */

        await db
            .prepare(
                `INSERT INTO support_messages
                (
                    ticket_id,
                    sender_type,
                    message,
                    is_read
                )
                VALUES (?, 'user', ?, 0)`
            )
            .bind(
                ticketId,
                message
            )
            .run();


        /* =========================================
           SUCCESS
        ========================================= */

        return jsonResponse(
            {
                success: true,

                message:
                    "Your support request has been sent.",

                ticket_id:
                    ticketId
            }
        );


    } catch (error) {

        console.error(
            "SUPPORT POST ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );


        return jsonResponse(
            {
                success: false,
                errorMessage:
                    "Unable to send support request."
            },
            500
        );
    }
}
