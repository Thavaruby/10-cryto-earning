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
            return value.join("=");
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

            return Response.json(
                {
                    success: false,
                    error:
                        "Please login first"
                },
                {
                    status: 401,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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

            return Response.json(
                {
                    success: false,
                    error:
                        "Invalid session"
                },
                {
                    status: 401,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
            );
        }


        /* =================================================
           CHECK EXPIRY
        ================================================= */

        if (
            new Date(session.expires_at) <=
            new Date()
        ) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Session expired"
                },
                {
                    status: 401,
                    headers: {
                        "Cache-Control": "no-store"
                    }
                }
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

        return Response.json(
            {
                success: true,
                claims:
                    claims.results || []
            },
            {
                headers: {
                    "Cache-Control":
                        "no-store, no-cache, must-revalidate, max-age=0",

                    "Pragma":
                        "no-cache",

                    "Expires":
                        "0"
                }
            }
        );


    } catch (error) {

        console.error(
            "Claims history error:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to load claim history."
            },
            {
                status: 500,
                headers: {
                    "Cache-Control": "no-store"
                }
            }
        );
    }
}
