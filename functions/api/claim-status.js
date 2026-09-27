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
    status = 200,
    extraHeaders = {}
) {

    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: {
                "Content-Type":
                    "application/json",

                "Cache-Control":
                    "no-store",

                ...extraHeaders
            }
        }
    );
}


/* =====================================================
   PARSE SQLITE UTC TIMESTAMP
===================================================== */

function parseSqliteUtcTimestamp(value) {

    if (
        typeof value !== "string" ||
        !value.trim()
    ) {
        return NaN;
    }

    const timestamp =
        value.trim();

    const isoTimestamp =
        timestamp.includes("T")
            ? (
                timestamp.endsWith("Z")
                    ? timestamp
                    : `${timestamp}Z`
            )
            : `${timestamp.replace(" ", "T")}Z`;

    return Date.parse(
        isoTimestamp
    );
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
           EXPIRY
        ================================================= */

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

            return jsonResponse({
                success: true,
                canClaim: true,
                remainingSeconds: 0
            });
        }


        /* =================================================
           PARSE LAST CLAIM TIME
        ================================================= */

        const lastTime =
            parseSqliteUtcTimestamp(
                lastClaim.claimed_at
            );


        /*
         * Invalid database timestamp should
         * never produce NaN or accidentally
         * allow/deny a claim.
         */
        if (
            !Number.isFinite(
                lastTime
            )
        ) {

            console.error(
                "INVALID CLAIM TIMESTAMP"
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to check claim status."
                },
                500
            );
        }


        /* =================================================
           CALCULATE REMAINING TIME
        ================================================= */

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

        return jsonResponse({

            success: true,

            canClaim:
                remaining <= 0,

            remainingSeconds:
                remaining
        });


    } catch (error) {

        console.error(
            "CLAIM STATUS ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );


        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to check claim status."
            },
            500
        );
    }
}
