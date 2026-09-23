const REWARD = 0.00000001;
const COOLDOWN_SECONDS = 60 * 60;

const DEVICE_COOKIE_NAME = "mcf_device";

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

/* DEVICE TOKEN HASH */
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

/* JSON RESPONSE */
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

        /* --------------------------------
           1. READ REQUEST
        -------------------------------- */

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

        /* --------------------------------
           2. CHECK SESSION
        -------------------------------- */

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

        /* --------------------------------
           3. CHECK DEVICE
        -------------------------------- */

        const deviceToken = getCookie(
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
            await hashDeviceToken(deviceToken);

        const device = await db
            .prepare(
                `SELECT
                    id,
                    user_id,
                    last_claim_at
                 FROM user_devices
                 WHERE device_id_hash = ?
                 LIMIT 1`
            )
            .bind(deviceIdHash)
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

        /*
         * The device must already be bound to an account.
         *
         * We intentionally do not block login switching here.
         * Device-level claim protection is enforced at claim time.
         */
        const deviceLastClaimAt =
            device.last_claim_at
                ? new Date(
                    device.last_claim_at
                ).getTime()
                : 0;

        if (
            deviceLastClaimAt > 0 &&
            Number.isFinite(deviceLastClaimAt)
        ) {
            const nowMs = Date.now();

            const elapsed =
                Math.floor(
                    (nowMs - deviceLastClaimAt) / 1000
                );

            const remainingSeconds =
                Math.max(
                    0,
                    COOLDOWN_SECONDS - elapsed
                );

            if (remainingSeconds > 0) {
                const hours = Math.floor(
                    remainingSeconds / 3600
                );

                const minutes = Math.floor(
                    (remainingSeconds % 3600) / 60
                );

                const seconds =
                    remainingSeconds % 60;

                return jsonResponse(
                    {
                        success: false,
                        error:
                            `Please wait ${hours}h ${minutes}m ${seconds}s before claiming again on this device.`
                    },
                    429
                );
            }
        }

        /* --------------------------------
           4. VERIFY TURNSTILE
        -------------------------------- */

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

        const verifyResponse = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: new URLSearchParams({
                    secret: turnstileSecret,
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

        /* --------------------------------
           5. ATOMIC CLAIM + BALANCE UPDATE
        -------------------------------- */

        const results = await db.batch([
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
                   )
                   AND EXISTS (
                       SELECT 1
                       FROM user_devices
                       WHERE device_id_hash = ?
                         AND (
                             last_claim_at IS NULL
                             OR last_claim_at <=
                                 datetime('now', ?)
                         )
                   )`
            ).bind(
                REWARD,
                userId,
                userId,
                `-${COOLDOWN_SECONDS} seconds`,
                deviceIdHash,
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

        /* --------------------------------
           6. CHECK BALANCE UPDATE
        -------------------------------- */

        const balanceChanges =
            results?.[0]?.meta?.changes ?? 0;

        if (balanceChanges !== 1) {

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

            const deviceStatus = await db
                .prepare(
                    `SELECT
                        last_claim_at
                     FROM user_devices
                     WHERE device_id_hash = ?
                     LIMIT 1`
                )
                .bind(deviceIdHash)
                .first();

            let remainingSeconds =
                COOLDOWN_SECONDS;

            /*
             * First check device-level cooldown.
             */
            if (deviceStatus?.last_claim_at) {

                const lastDeviceTime =
                    new Date(
                        deviceStatus.last_claim_at
                    ).getTime();

                if (Number.isFinite(lastDeviceTime)) {

                    const elapsed =
                        Math.floor(
                            (
                                Date.now() -
                                lastDeviceTime
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

            /*
             * If device cooldown has expired,
             * check the user's own claim cooldown.
             */
            if (
                remainingSeconds <= 0 &&
                lastClaim?.claimed_at
            ) {

                const lastTime =
                    new Date(
                        lastClaim.claimed_at
                    ).getTime();

                if (Number.isFinite(lastTime)) {

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

            const hours = Math.floor(
                remainingSeconds / 3600
            );

            const minutes = Math.floor(
                (remainingSeconds % 3600) / 60
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

        /* --------------------------------
           7. CHECK CLAIM INSERT
        -------------------------------- */

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

        /* --------------------------------
           8. CHECK DEVICE TIMESTAMP UPDATE
        -------------------------------- */

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

        /* --------------------------------
           9. LOAD UPDATED BALANCE
        -------------------------------- */

        const updatedUser = await db
            .prepare(
                `SELECT
                    balance
                 FROM users
                 WHERE id = ?
                 LIMIT 1`
            )
            .bind(userId)
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
            Number(updatedUser.balance);

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

        /* --------------------------------
           10. SUCCESS
        -------------------------------- */

        return jsonResponse({
            success: true,
            message:
                "Reward claimed successfully!",
            reward: REWARD,
            balance: balance
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
