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

export async function onRequestPost(context) {

    try {

        const sessionToken =
            getCookie(context.request, "session");

        if (sessionToken) {

            const tokenHash =
                await hashSessionToken(sessionToken);

            await context.env.DB
                .prepare(
                    "DELETE FROM sessions WHERE token_hash = ?"
                )
                .bind(tokenHash)
                .run();
        }

        return new Response(
            JSON.stringify({
                success: true,
                message: "Logged out successfully"
            }),
            {
                headers: {
                    "Content-Type":
                        "application/json",

                    "Set-Cookie":
                        "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
                }
            }
        );

    } catch (error) {

        return Response.json(
            {
                success: false,
                error: error.message
            },
            { status: 500 }
        );
    }
}
