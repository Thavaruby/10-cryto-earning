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

export async function onRequestPost(context) {
    try {
        const { request, env } = context;

        const sessionToken = getCookie(
            request,
            "session"
        );

        if (sessionToken) {
            const tokenHash =
                await hashSessionToken(sessionToken);

            await env.DB.prepare(`
                DELETE FROM sessions
                WHERE token_hash = ?
            `)
                .bind(tokenHash)
                .run();
        }

        return new Response(
            JSON.stringify({
                success: true
            }),
            {
                status: 200,
                headers: {
                    "Content-Type": "application/json",
                    "Set-Cookie":
                        "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
                }
            }
        );

    } catch (error) {
        console.error("Logout error:", error);

        return new Response(
            JSON.stringify({
                success: false,
                error: "Internal server error"
            }),
            {
                status: 500,
                headers: {
                    "Content-Type": "application/json"
                }
            }
        );
    }
}
