const REWARD = 0.00000001;
const COOLDOWN_SECONDS = 60 * 60;

/* COOKIE */
function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) return null;

    for (const cookie of cookieHeader.split(";")) {
        const [key, ...value] = cookie.trim().split("=");

        if (key === name) {
            return value.join("=");
        }
    }

    return null;
}

/* SESSION TOKEN HASH */
async function hashSessionToken(token) {
    const data = new TextEncoder().encode(token);

    const hash = await crypto.subtle.digest(
        "SHA-256",
        data
    );

    return Array.from(new Uint8Array(hash))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

/* RESPONSE */
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

/* CLAIM */
export async function onRequestPost(context) {
    try {
        const db = context.env.DB.withSession("first-primary");

        /* -----------------------------
           1. READ REQUEST
        ----------------------------- */

        let data;

        try {
            data = await context.request.json();
        } catch {
            return jsonResponse(
                {
                    success: false,
                    error: "Invalid request."
                },
                400
            );
        }

        const turnstileToken = String(
            data.turnstileToken || ""
        );

        if (!turnstileToken) {
            return jsonResponse(
                {
                    success: false,
                    error: "Please complete verification."
                },
                400
            );
        }

        /* -----------------------------
           2. CHECK SESSION
        ----------------------------- */

        const sessionToken = getCookie(
            context.request,
            "session"
        );

        if (!sessionToken) {
            return jsonResponse(
                {
                    success: false,
                    error: "Please login first."
                },
                401
            );
        }

        const tokenHash =
            await hashSessionToken(sessionToken);

        const session = await db
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
                    error: "Invalid or expired session."
                },
                401
            );
        }

        const userId = Number(session.user_id);

        if (!Number.isInteger(userId) || userId <= 0) {
            return jsonResponse(
                {
                    success: false,
                    error: "Invalid user session."
                },
                401
            );
        }

        /* -----------------------------
           3. VERIFY TURNSTILE
        ----------------------------- */

        const verifyResponse = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: new URLSearchParams({
                    secret: context.env.TURNSTILE_SECRET,
                    response: turnstileToken
                })
            }
        );

        if (!verifyResponse.ok) {
            return jsonResponse(
                {
                    success: false,
                    error:
                        "Verification service unavailable."
                },
                503
            );
        }

        const verifyResult =
            await verifyResponse.json();

        if (!verifyResult.success) {
            return jsonResponse(
                {
                    success: false,
                    error: "Verification failed."
                },
                400
            );
        }

        /* -----------------------------
           4. ATOMIC CLAIM
        ----------------------------- */

        /*
         * First statement creates the claim only
         * when the user has no claim during the
         * last hour.
         *
         * Second statement increases the balance.
         *
         * Both statements are executed inside one
         * D1 batch transaction.
         */

        const results = await db.batch([
            db.prepare(
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
            ).bind(
                userId,
                REWARD,
                userId,
                `-${COOLDOWN_SECONDS} seconds`
            ),

            db.prepare(
                `UPDATE users
                 SET balance = balance + ?
                 WHERE id = ?
                   AND EXISTS (
                       SELECT 1
                       FROM claims
                       WHERE user_id = ?
                         AND reward = ?
                         AND claimed_at >=
                             datetime('now', '-2 seconds')
                   )`
            ).bind(
                REWARD,
                userId,
                userId,
                REWARD
            )
        ]);

        /* -----------------------------
           5. CHECK CLAIM RESULT
        ----------------------------- */

        const claimChanges =
            results?.[0]?.meta?.changes ?? 0;

        if (claimChanges !== 1) {
            const lastClaim = await db
                .prepare(
                    `SELECT
                        claimed_at
                     FROM claims
                     WHERE user_id = ?
                     ORDER BY claimed_at DESC
                     LIMIT 1`
                )
                .bind(userId)
                .first();

            let remainingSeconds =
                COOLDOWN_SECONDS;

            if (lastClaim?.claimed_at) {
                const lastTime =
                    new Date(
                        lastClaim.claimed_at
                    ).getTime();

                const elapsed = Math.floor(
                    (Date.now() - lastTime) / 1000
                );

                remainingSeconds = Math.max(
                    0,
                    COOLDOWN_SECONDS - elapsed
                );
            }

            const hours = Math.floor(
                remainingSeconds / 3600
            );

            const minutes = Math.floor(
                (remainingSeconds % 3600) / 60
            );

           
