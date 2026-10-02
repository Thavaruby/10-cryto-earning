/* =====================================================
   REFERRAL MILESTONE REWARD
===================================================== */

const MILESTONES = [
    {
        claims: 1,
        rewardSats: 5
    },
    {
        claims: 5,
        rewardSats: 10
    },
    {
        claims: 10,
        rewardSats: 15
    },
    {
        claims: 20,
        rewardSats: 20
    },
    {
        claims: 50,
        rewardSats: 30
    }
];


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
   REFERRAL REWARD
===================================================== */

export async function onRequestPost(context) {

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
           FIND REFERRAL
        ================================================= */

        const referral =
            await db
                .prepare(
                    `SELECT
                        id,
                        referrer_user_id
                     FROM referrals
                     WHERE referred_user_id = ?
                     LIMIT 1`
                )
                .bind(
                    userId
                )
                .first();


        /*
         * This user was not referred.
         * Nothing to reward.
         */

        if (!referral) {

            return jsonResponse({
                success: true,
                awardedSats: 0
            });
        }


        const referralId =
            Number(
                referral.id
            );


        const referrerUserId =
            Number(
                referral.referrer_user_id
            );


        if (
            !Number.isInteger(referralId) ||
            referralId <= 0 ||
            !Number.isInteger(referrerUserId) ||
            referrerUserId <= 0 ||
            referrerUserId === userId
        ) {

            return jsonResponse(
                {
                    success: false,
                    error:
                        "Invalid referral record."
                },
                500
            );
        }


        /* =================================================
           COUNT SUCCESSFUL CLAIMS
        ================================================= */

        const claimResult =
            await db
                .prepare(
                    `SELECT
                        COUNT(*) AS claim_count
                     FROM claims
                     WHERE user_id = ?`
                )
                .bind(
                    userId
                )
                .first();


        const claimCount =
            Number(
                claimResult?.claim_count ?? 0
            );


        if (
            !Number.isInteger(claimCount) ||
            claimCount <= 0
        ) {

            return jsonResponse({
                success: true,
                awardedSats: 0
            });
        }


        /* =================================================
           FIND REACHED MILESTONES
        ================================================= */

        const reachedMilestones =
            MILESTONES.filter(
                milestone =>
                    claimCount >=
                    milestone.claims
            );


        if (
            reachedMilestones.length === 0
        ) {

            return jsonResponse({
                success: true,
                awardedSats: 0
            });
        }


        /* =================================================
           INSERT MISSING REWARDS
           
           UNIQUE(referral_id, milestone_claims)
           prevents duplicate rewards.

           The database trigger
           "referral_reward_credit"
           automatically adds the reward
           to the referrer's main balance.
        ================================================= */

        const statements =
            reachedMilestones.map(
                milestone =>

                    db.prepare(
                        `INSERT OR IGNORE INTO referral_rewards
                        (
                            referral_id,
                            milestone_claims,
                            reward_sats
                        )
                        VALUES (?, ?, ?)`
                    ).bind(
                        referralId,
                        milestone.claims,
                        milestone.rewardSats
                    )
            );


        const results =
            await db.batch(
                statements
            );


        /* =================================================
           CALCULATE NEWLY AWARDED SATS
        ================================================= */

        let awardedSats = 0;


        for (
            let i = 0;
            i < reachedMilestones.length;
            i++
        ) {

            const changes =
                results?.[i]?.meta?.changes ?? 0;


            if (changes === 1) {

                awardedSats +=
                    reachedMilestones[i]
                        .rewardSats;
            }
        }


        /* =================================================
           SUCCESS
        ================================================= */

        return jsonResponse({

            success: true,

            awardedSats:

                awardedSats,

            claimCount:

                claimCount
        });


    } catch (error) {

        console.error(
            "REFERRAL REWARD ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );


        return jsonResponse(
            {
                success: false,
                error:
                    "Unable to process referral reward."
            },
            500
        );
    }
}
