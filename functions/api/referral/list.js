/* =====================================================
   REFERRAL LIST
   Shows referred users to the logged-in referrer
===================================================== */


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
   MASK EMAIL
===================================================== */

function maskEmail(email) {

    if (
        typeof email !== "string" ||
        !email.includes("@")
    ) {
        return "User";
    }

    const [local, domain] =
        email.split("@");

    if (!local || !domain) {
        return "User";
    }

    if (local.length <= 2) {

        return (
            local.charAt(0) +
            "***@" +
            domain
        );
    }

    return (
        local.charAt(0) +
        "***" +
        local.charAt(local.length - 1) +
        "@" +
        domain
    );
}


/* =====================================================
   REFERRAL LIST
===================================================== */

export async function onRequestGet(context) {

    try {

        const db =
            context.env.DB.withSession(
                "first-primary"
            );


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
           GET REFERRALS
        ================================================= */

        const result =
            await db
                .prepare(
                    `SELECT
                        referrals.id AS referral_id,
                        referrals.created_at AS joined_at,
                        users.id AS user_id,
                        users.email,

                        COUNT(claims.id)
                            AS claim_count,

                        COALESCE(
                            (
                                SELECT
                                    SUM(
                                        referral_rewards.reward_sats
                                    )
                                FROM referral_rewards
                                WHERE
                                    referral_rewards.referral_id =
                                        referrals.id
                            ),
                            0
                        ) AS reward_sats

                     FROM referrals

                     INNER JOIN users
                        ON users.id =
                           referrals.referred_user_id

                     LEFT JOIN claims
                        ON claims.user_id =
                           referrals.referred_user_id

                     WHERE
                        referrals.referrer_user_id = ?

                     GROUP BY
                        referrals.id,
                        referrals.created_at,
                        users.id,
                        users.email

                     ORDER BY
                        referrals.created_at DESC`
                )
                .bind(
                    userId
                )
                .all();


        const rows =
            result?.results ?? [];


        /* =================================================
           FORMAT RESPONSE
        ================================================= */

        const referrals =
            rows.map(row => ({

                userId:
                    Number(row.user_id),

                name:
                    maskEmail(row.email),

                claimCount:
                    Number(row.claim_count ?? 0),

                rewardSats:
                    Number(row.reward_sats ?? 0),

                joinedAt:
                    row.joined_at

            }));


        const totalReferrals =
            referrals.length;


        const totalRewardSats =
            referrals.reduce(
                (total, referral) =>
                    total +
                    referral.rewardSats,
                0
            );


        return jsonResponse({

            success: true,

            referrals,

            totalReferrals,

            totalRewardSats

        });


    } catch (error) {

        console.error(
            "REFERRAL LIST ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );


        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to load referral details."
            },
            500
        );
    }
            }
