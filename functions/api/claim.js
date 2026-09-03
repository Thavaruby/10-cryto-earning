const REWARD = 0.00000001;
const COOLDOWN_SECONDS = 60 * 60;


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


        const turnstileToken =
            String(
                data.turnstileToken || ""
            );


        if (!turnstileToken) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Please complete verification."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           2. GET SESSION
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
           3. VERIFY SESSION
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
           4. VERIFY TURNSTILE
        ===================================================== */

        const verifyResponse =
            await fetch(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/x-www-form-urlencoded"
                    },

                    body:
                        new URLSearchParams({

                            secret:
                                context.env.TURNSTILE_SECRET,

                            response:
                                turnstileToken
                        })
                }
            );


        if (!verifyResponse.ok) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Verification service unavailable."
                },
                { status: 503 }
            );
        }


        const verifyResult =
            await verifyResponse.json();


        if (!verifyResult.success) {

            return Response.json(
                {
                    success: false,
                    error:
                        "Verification failed."
                },
                { status: 400 }
            );
        }


        /* =====================================================
           5. ATOMIC CLAIM
           
           INSERT claim only.
           
           The database trigger:
           
           claims INSERT
                ↓
           users.balance + reward
           
           This keeps the claim and balance update together.
        ===================================================== */

        const claimResult =
            await context.env.DB
                .prepare(
                    `INSERT INTO claims
                    (
                        user_id,
                        reward
                    )
                    SELECT
                        ?,
                        ?
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM claims
                        WHERE user_id = ?
                          AND claimed_at >
                              datetime('now', ?)
                    )`
                )
                .bind(
                    session.user_id,
                    REWARD,
                    session.user_id,
                    `-${COOLDOWN_SECONDS} seconds`
                )
                .run();


        /* =====================================================
           6. COOLDOWN ACTIVE
        ===================================================== */

        if (
            !claimResult.meta ||
            claimResult.meta.changes !== 1
        ) {

            const lastClaim =
                await context.env.DB
                    .prepare(
                        `SELECT claimed_at
                         FROM claims
                         WHERE user_id = ?
                         ORDER BY claimed_at DESC
                         LIMIT 1`
                    )
                    .bind(session.user_id)
                    .first();


            let remainingSeconds =
                COOLDOWN_SECONDS;


            if (lastClaim?.claimed_at) {

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


                remainingSeconds =
                    Math.max(
                        0,
                        COOLDOWN_SECONDS -
                        elapsed
                    );
            }


            const hours =
                Math.floor(
                    remainingSeconds / 3600
                );


            const minutes =
                Math.floor(
                    (
                        remainingSeconds % 3600
                    ) / 60
                );


            const seconds =
                remainingSeconds % 60;


            return Response.json(
                {
                    success: false,

                    error:
                        `Please wait ${hours}h ${minutes}m ${seconds}s before claiming again.`
                },
                { status: 429 }
            );
        }


        /* =====================================================
           7. GET UPDATED BALANCE
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

            console.error(
                "Claim created but user balance could not be loaded.",
                {
                    userId:
                        session.user_id
                }
            );


            return Response.json(
                {
                    success: false,
                    error:
                        "Unable to load updated balance."
                },
                { status: 500 }
            );
        }


        /* =====================================================
           8. SUCCESS
        ===================================================== */

        return Response.json({

            success: true,

            message:
                "Reward claimed successfully!",

            reward:
                REWARD,

            balance:
                updatedUser.balance
        });


    } catch (error) {

        console.error(
            "Claim error:",
            error
        );


        return Response.json(
            {
                success: false,
                error:
                    "Unable to process claim."
            },
            { status: 500 }
        );
    }
}
