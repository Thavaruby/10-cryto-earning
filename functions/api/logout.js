async function hashSessionToken(token) {
    const data = new TextEncoder().encode(token);

    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        data
    );

    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function getCookie(request, name) {
    const cookieHeader = request.headers.get("Cookie");

    if (!cookieHeader) {
        return null;
    }

    const cookies = cookieHeader.split(";");

    for (const cookie of cookies) {
        const [key, ...valueParts] = cookie.trim().split("=");

        if (key === name) {
            return decodeURIComponent(valueParts.join("="));
        }
    }

    return null;
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
    return new Response(
        JSON.stringify(data),
        {
            status,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                ...extraHeaders
            }
        }
    );
}

export async function onRequestPost(context) {
    try {
        const { request, env } = context;

        const db = env.DB.withSession("first-primary");

        const sessionToken = getCookie(
            request,
            "session"
        );

        if (sessionToken) {
            const tokenHash =
                await hashSessionToken(sessionToken);

            await db.prepare(`
                DELETE FROM sessions
                WHERE token_hash = ?
            `)
                .bind(tokenHash)
                .run();
        }

        return jsonResponse(
            {
                success: true
            },
            200,
            {
                "Set-Cookie":
                    "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
            }
        );

    } catch (error) {
        console.error(
            "LOGOUT ERROR:",
            error instanceof Error
                ? error.message
                : "Unknown error"
        );

        return jsonResponse(
            {
                success: false,
                error: "Internal server error"
            },
            500
        );
    }
}
