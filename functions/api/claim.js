const REWARD = 0.00000001;
const COOLDOWN_SECONDS = 60 * 60;

const DEVICE_COOKIE_NAME = "mcf_device";
const MAX_TURNSTILE_TOKEN_LENGTH = 2048;


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
   DEVICE TOKEN HASH
===================================================== */

function toBase64Url(bytes) {

    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}


async function hashDeviceToken(token) {

    const data =
        new TextEncoder().encode(token);

    const hash =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    return toBase64Url(
        new Uint8Array(hash)
    );
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
   CLAIM
===================================================== */

export async function onRequestPost(context) {

    try {

        const db =
            context.env.DB.withSession(
                "first-primary"
            );


        /* =================================================
           REQUEST JSON
        ================================================= */

        let data;

        try {

            data =
                await context.request.json();

        } catch {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid request."
                },
                400
            );
        }


        if (
            !data ||
            typeof data !== "object" ||
            Array.isArray(data)
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid request."
                },
                400
            );
        }


        /* =================================================
           TURNSTILE TOKEN
        ================================================= */

        const turnstileToken =
            typeof data.turnstileToken === "string"
                ? data.turnstileToken.trim()
                : "";


        if (
            !turnstileToken ||
            turnstileToken.length >
                MAX_TURNSTILE_TOKEN_LENGTH
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid verification token."
                },
                400
            );
        }


        /* =================================================
           SESSION
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
                        "Please login first."
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
                        user_id,
                        expires_at
                     FROM sessions
                     WHERE token_hash = ?
                     AND expires_at > ?
                     LIMIT 1`
                )
                .bind(
                    tokenHash,
                    new Date().toISOString()
                )
                .first();


        if (!session) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid or expired session."
                },
                401
            );
        }


        const userId =
            Number(
                session.user_id
            );


        if (
            !Number.isInteger(userId) ||
            userId <= 0
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid user session."
                },
                401
            );
        }


        /* =================================================
           DEVICE
        ================================================= */

        const deviceToken =
            getCookie(
                context.request,
                DEVICE_COOKIE_NAME
            );


        if (!deviceToken) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Device verification required. Please login again."
                },
                401
            );
        }


        const deviceIdHash =
            await hashDeviceToken(
                deviceToken
            );


        const device =
            await db
                .prepare(
                    `SELECT
                        id,
                        user_id,
                        last_claim_at
                     FROM user_devices
                     WHERE device_id_hash = ?
                     LIMIT 1`
                )
                .bind(
                    deviceIdHash
                )
                .first();


        if (!device) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Device verification required. Please login again."
                },
                401
            );
        }


        /* =================================================
           DEVICE → SESSION ACCOUNT CHECK
        ================================================= */

        if (
            Number(device.user_id) !== userId
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Device verification required. Please login again."
                },
                401
            );
        }


        /*
         * Device-level cooldown is intentionally
         * NOT enforced here.
         *
         * Same-device / multiple-account protection
         * remains a separate final security task.
         */


        /* =================================================
           TURNSTILE
        ================================================= */

        const turnstileSecret =
            context.env.TURNSTILE_SECRET;


        if (!turnstileSecret) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Verification service unavailable."
                },
                503
            );
        }


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
                                turnstileSecret,

                            response:
                                turnstileToken
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


        if (
            !verifyResult ||
            verifyResult.success !== true
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Verification failed."
                },
                400
            );
        }


        /* =================================================
           ATOMIC CLAIM
        ================================================= */

        const results =
            await db.batch([

                db.prepare(
                    `UPDATE users
                     SET balance = balance + ?
                     WHERE id = ?
                       AND NOT EXISTS (
                           SELECT 1
                           FROM claims
                           WHERE user_id = ?
                             AND claimed_at >
                                 datetime('now', ?)
                       )`
                ).bind(
                    REWARD,
                    userId,
                    userId,
                    `-${COOLDOWN_SECONDS} seconds`
                ),


                db.prepare(
                    `INSERT INTO claims
                    (
                        user_id,
                        reward
                    )
                    SELECT
                        ?,
                        ?
                    WHERE changes() = 1`
                ).bind(
                    userId,
                    REWARD
                ),


                db.prepare(
                    `UPDATE user_devices
                     SET last_claim_at = ?
                     WHERE device_id_hash = ?
                       AND user_id = ?`
                ).bind(
                    new Date().toISOString(),
                    deviceIdHash,
                    userId
                )
            ]);


        /* =================================================
           BALANCE UPDATE CHECK
        ================================================= */

        const balanceChanges =
            results?.[0]?.meta?.changes ?? 0;


        if (balanceChanges !== 1) {

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
                    .bind(
                        userId
                    )
                    .first();


            let remainingSeconds =
                COOLDOWN_SECONDS;


            if (lastClaim?.claimed_at) {

                const claimedAt =
                    String(
                        lastClaim.claimed_at
                    );


                const lastTime =
                    Date.parse(
                        claimedAt.includes("T")
                            ? (
                                claimedAt.endsWith("Z")
                                    ? claimedAt
                                    : `${claimedAt}Z`
                            )
                            : `${claimedAt.replace(" ", "T")}Z`
                    );


                if (
                    Number.isFinite(
                        lastTime
                    )
                ) {

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


            return jsonResponse(
                {
                    success: false,
                    error:
                        `Please wait ${hours}h ${minutes}m ${seconds}s before claiming again.`
                },
                429
            );
        }


        /* =================================================
           CLAIM INSERT CHECK
        ================================================= */

        const claimChanges =
            results?.[1]?.meta?.changes ?? 0;


        if (claimChanges !== 1) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to record your claim."
                },
                500
            );
        }


        /* =================================================
           DEVICE TIMESTAMP CHECK
        ================================================= */

        const deviceChanges =
            results?.[2]?.meta?.changes ?? 0;


        if (deviceChanges !== 1) {

            console.error(
                "DEVICE CLAIM TIMESTAMP UPDATE FAILED"
            );

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to record device claim."
                },
                500
            );
        }


        /* =================================================
           UPDATED BALANCE
        ================================================= */

        const updatedUser =
            await db
                .prepare(
                    `SELECT
                        balance
                     FROM users
                     WHERE id = ?
                     LIMIT 1`
                )
                .bind(
                    userId
                )
                .first();


        if (!updatedUser) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Unable to load updated balance."
                },
                500
            );
        }


        const balance =
            Number(
                updatedUser.balance
            );


        if (
            !Number.isFinite(balance) ||
            balance < 0
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid balance received."
                },
                500
            );
        }


        /* =================================================
           SUCCESS
        ================================================= */

        return jsonResponse({

            success: true,

            message:
                "Reward claimed successfully!",

            reward:
                REWARD,

            balance:
                balance
        });


    } catch (error) {

        console.error(
            "CLAIM ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );


        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to process claim."
            },
            500
        );
    }
}
