const COOLDOWN_SECONDS = 60 * 60;


/* =====================================================
   COOKIE
===================================================== */

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
   CLAIM STATUS
===================================================== */

export async function onRequestGet(context) {

    try {

        const db =
            context.env.DB.withSession(
                "first-primary"
            );


        /* =================================================
           SESSION COOKIE
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
           SESSION
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
           EXPIRY
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
           LAST CLAIM
        ================================================= */

        const lastClaim =
            await db
                .prepare(
                    `SELECT
                        claimed_at
                     FROM claims
                     WHERE user_id = ?
                     ORDER BY claimed_at DESC
                     LIMIT 1`
                )
                .bind(session.user_id)
                .first();


        /* =================================================
           NO CLAIM YET
        ================================================= */

        if (!lastClaim) {

            return Response.json(
                {
                    success: true,
                    canClaim: true,
                    remainingSeconds: 0
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
        }


        /* =================================================
           CALCULATE REMAINING TIME
        ================================================= */

        const lastTime =
            new Date(
                lastClaim.claimed_at
            ).getTime();


        const elapsed =
            Math.floor(
                (
                    Date.now() -
                    lastTime
                ) / 1000
            );


        const remaining =
            Math.max(
                0,
                COOLDOWN_SECONDS -
                elapsed
            );


        /* =================================================
           RESPONSE
        ================================================= */

        return Response.json(
            {
                success: true,

                canClaim:
                    remaining <= 0,

                remainingSeconds:
                    remaining
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
            "Claim status error:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to check claim status."
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
