export async function onRequest(context) {

    const {
        request,
        env
    } = context;


    /* =================================================
       RESPONSE HELPER
    ================================================= */

    function jsonResponse(data, status = 200) {

        return new Response(
            JSON.stringify(data),
            {
                status,

                headers: {
                    "Content-Type":
                        "application/json"
                }
            }
        );
    }


    /* =================================================
       METHOD
    ================================================= */

    if (
        request.method !== "GET" &&
        request.method !== "POST"
    ) {

        return jsonResponse(
            {
                success: false,
                errorMessage:
                    "Method not allowed."
            },
            405
        );
    }


    /* =================================================
       SESSION
    ================================================= */

    const session =
        await env.DB
            .prepare(`
                SELECT
                    user_id
                FROM sessions
                WHERE token = ?
                  AND expires_at > datetime('now')
                LIMIT 1
            `)
            .bind(
                request.headers
                    .get("Cookie")
                    ?.match(
                        /session_token=([^;]+)/
                    )?.[1] || ""
            )
            .first();


    if (!session) {

        return jsonResponse(
            {
                success: false,
                errorMessage:
                    "Please log in first."
            },
            401
        );
    }


    const userId =
        Number(session.user_id);


    /* =================================================
       GET SUPPORT TICKETS
    ================================================= */

    if (request.method === "GET") {

        const tickets =
            await env.DB
                .prepare(`
                    SELECT
                        id,
                        subject,
                        status,
                        created_at,
                        updated_at
                    FROM support_tickets
                    WHERE user_id = ?
                    ORDER BY updated_at DESC
                `)
                .bind(userId)
                .all();


        const ticketList =
            tickets.results || [];


        for (
            const ticket
            of ticketList
        ) {

            const messages =
                await env.DB
                    .prepare(`
                        SELECT
                            id,
                            sender_type,
                            message,
                            is_read,
                            created_at
                        FROM support_messages
                        WHERE ticket_id = ?
                        ORDER BY id ASC
                    `)
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
    }


    /* =================================================
       POST NEW SUPPORT TICKET
    ================================================= */

    let body;

    try {

        body =
            await request.json();

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


    /* =================================================
       VALIDATION
    ================================================= */

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


    /* =================================================
       CREATE TICKET
    ================================================= */

    const ticketResult =
        await env.DB
            .prepare(`
                INSERT INTO support_tickets
                (
                    user_id,
                    subject,
                    status
                )
                VALUES (?, ?, 'open')
            `)
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


    /* =================================================
       SAVE USER MESSAGE
    ================================================= */

    await env.DB
        .prepare(`
            INSERT INTO support_messages
            (
                ticket_id,
                sender_type,
                message,
                is_read
            )
            VALUES (?, 'user', ?, 0)
        `)
        .bind(
            ticketId,
            message
        )
        .run();


    /* =================================================
       RESPONSE
    ================================================= */

    return jsonResponse(
        {
            success: true,

            message:
                "Your support request has been sent.",

            ticket_id:
                ticketId
        }
    );
}
