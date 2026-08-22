export async function onRequestPost(context) {
    try {
        const data = await context.request.json();

        const email = String(data.email || "").trim().toLowerCase();

        if (!email) {
            return Response.json(
                {
                    success: false,
                    error: "Email is required"
                },
                { status: 400 }
            );
        }

        const existingUser = await context.env.DB
            .prepare("SELECT id, email FROM users WHERE email = ?")
            .bind(email)
            .first();

        if (existingUser) {
            return Response.json(
                {
                    success: false,
                    error: "Email already registered"
                },
                { status: 409 }
            );
        }

        const result = await context.env.DB
            .prepare(
                "INSERT INTO users (email, balance) VALUES (?, 0)"
            )
            .bind(email)
            .run();

        return Response.json({
            success: true,
            message: "Account created successfully!",
            user_id: result.meta.last_row_id
        });

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
