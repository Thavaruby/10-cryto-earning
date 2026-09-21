/* =====================================================
   COOKIE
===================================================== */

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
            return decodeURIComponent(
                value.join("=")
            );
        }
    }

    return null;
}


/* =====================================================
   SESSION TOKEN HASH
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
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");
}


/* =====================================================
   JSON RESPONSE
===================================================== */

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
                    "no-store, no-cache, must-revalidate, max-age=0",

                "Pragma":
                    "no-cache",

                "Expires":
                    "0"
            }
        }
    );
}


/* =====================================================
   CLAIM HISTORY
===================================================== */

export async function onRequestGet(context) {

    try {

        /* =================================================
           D1 PRIMARY SESSION
        ================================================= */

        const db =
            context.env.DB.withSession(
                "first-primary"
            );


        /* =================================================
           GET SESSION COOKIE
        ================================================= */

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
                        "Please login first"
                },
                401
            );
        }


        const tokenHash =
            await hashSessionToken(
                sessionToken
            );


        /* =================================================
           VERIFY SESSION
        ================================================= */

        const session =
            await db
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

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid session"
                },
                401
            );
        }


        /* =================================================
           CHECK EXPIRY
        ================================================= */

        if (
            new Date(session.expires_at) <=
            new Date()
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


        /* =================================================
           GET CLAIM HISTORY
        ================================================= */

        const claims =
            await db
                .prepare(
                    `SELECT
                        id,
                        reward,
                        claimed_at
                     FROM claims
                     WHERE user_id = ?
                     ORDER BY id DESC
                     LIMIT 20`
                )
                .bind(session.user_id)
                .all();


        /* =================================================
           RESPONSE
        ================================================= */

        return jsonResponse({
            success: true,
            claims:
                claims.results || []
        });


    } catch (error) {

        console.error(
            "CLAIM HISTORY ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to load claim history."
            },
            500
        );
    }
}
