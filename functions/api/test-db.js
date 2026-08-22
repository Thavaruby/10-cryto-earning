export async function onRequestGet(context) {
    try {
        const result = await context.env.DB
            .prepare("SELECT COUNT(*) AS total FROM users")
            .first();

        return Response.json({
            success: true,
            message: "Database connection successful!",
            users: result.total
        });

    } catch (error) {

        return Response.json({
            success: false,
            error: error.message
        }, { status: 500 });
    }
}
