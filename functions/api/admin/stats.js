// ========================================
// ADMIN STATISTICS
// GET /api/admin/stats
// ========================================

export async function onRequestGet(context) {
  const { request, env } = context;

  try {

    // ========================================
    // ADMIN AUTHENTICATION
    // ========================================

    const cookieHeader = request.headers.get("Cookie") || "";

    const sessionMatch = cookieHeader.match(
      /(?:^|;\s*)session=([^;]+)/
    );

    if (!sessionMatch) {
      return Response.json(
        {
          success: false,
          error: "Unauthorized"
        },
        { status: 401 }
      );
    }

    const sessionToken = sessionMatch[1];

    // ========================================
    // HASH SESSION TOKEN
    // ========================================

    const tokenHashBuffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(sessionToken)
    );

    const tokenHash = Array.from(
      new Uint8Array(tokenHashBuffer)
    )
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    // ========================================
    // CHECK SESSION
    // ========================================

    const session = await env.DB.prepare(`
      SELECT user_id
      FROM sessions
      WHERE token_hash = ?
        AND expires_at > CURRENT_TIMESTAMP
      LIMIT 1
    `)
      .bind(tokenHash)
      .first();

    if (!session) {
      return Response.json(
        {
          success: false,
          error: "Unauthorized"
        },
        { status: 401 }
      );
    }

    // ========================================
    // CHECK ADMIN
    // ========================================

    const admin = await env.DB.prepare(`
      SELECT user_id
      FROM admins
      WHERE user_id = ?
      LIMIT 1
    `)
      .bind(session.user_id)
      .first();

    if (!admin) {
      return Response.json(
        {
          success: false,
          error: "Forbidden"
        },
        { status: 403 }
      );
    }

    // ========================================
    // TOTAL USERS
    // ========================================

    const users = await env.DB.prepare(`
      SELECT COUNT(*) AS total_users
      FROM users
    `).first();

    // ========================================
    // CLAIM STATISTICS
    // ========================================

    const claims = await env.DB.prepare(`
      SELECT
        COUNT(*) AS total_claims,
        COALESCE(SUM(reward), 0) AS total_claimed
      FROM claims
    `).first();

    // ========================================
    // WITHDRAWAL STATISTICS
    // BTC ONLY
    // ========================================

    const withdrawals = await env.DB.prepare(`
      SELECT

        COUNT(*) AS total_withdrawals,

        COALESCE(
          SUM(
            CASE
              WHEN status = 'approved'
              THEN amount
              ELSE 0
            END
          ),
          0
        ) AS total_withdrawn,

        COALESCE(
          SUM(
            CASE
              WHEN status = 'pending'
              THEN amount
              ELSE 0
            END
          ),
          0
        ) AS pending_amount,

        SUM(
          CASE
            WHEN status = 'pending'
            THEN 1
            ELSE 0
          END
        ) AS pending_count,

        SUM(
          CASE
            WHEN status = 'approved'
            THEN 1
            ELSE 0
          END
        ) AS approved_count,

        SUM(
          CASE
            WHEN status = 'rejected'
            THEN 1
            ELSE 0
          END
        ) AS rejected_count

      FROM withdrawals

      WHERE currency = 'BTC'
    `).first();

    // ========================================
    // TODAY'S CLAIMS
    // ========================================

    const todayClaims = await env.DB.prepare(`
      SELECT
        COUNT(*) AS count,
        COALESCE(SUM(reward), 0) AS amount
      FROM claims
      WHERE date(claimed_at) = date('now')
    `).first();

    // ========================================
    // TODAY'S WITHDRAWALS
    // ========================================

    const todayWithdrawals = await env.DB.prepare(`
      SELECT
        COUNT(*) AS count,
        COALESCE(SUM(amount), 0) AS amount
      FROM withdrawals
      WHERE currency = 'BTC'
        AND date(created_at) = date('now')
    `).first();

    // ========================================
    // FINAL RESPONSE
    // ========================================

    return Response.json({

      success: true,

      users: {
        total: Number(
          users?.total_users || 0
        )
      },

      claims: {
        totalClaims: Number(
          claims?.total_claims || 0
        ),

        totalClaimed: Number(
          claims?.total_claimed || 0
        )
      },

      withdrawals: {

        total: Number(
          withdrawals?.total_withdrawals || 0
        ),

        totalWithdrawn: Number(
          withdrawals?.total_withdrawn || 0
        ),

        pending: Number(
          withdrawals?.pending_count || 0
        ),

        pendingAmount: Number(
          withdrawals?.pending_amount || 0
        ),

        approved: Number(
          withdrawals?.approved_count || 0
        ),

        rejected: Number(
          withdrawals?.rejected_count || 0
        )
      },

      today: {

        claims: Number(
          todayClaims?.count || 0
        ),

        claimedAmount: Number(
          todayClaims?.amount || 0
        ),

        withdrawals: Number(
          todayWithdrawals?.count || 0
        ),

        withdrawalAmount: Number(
          todayWithdrawals?.amount || 0
        )
      }

    });

  } catch (error) {

    console.error(
      "ADMIN STATS ERROR:",
      error
    );

    return Response.json(
      {
        success: false,
        error: error?.message || String(error)
      },
      { status: 500 }
    );
  }
}
