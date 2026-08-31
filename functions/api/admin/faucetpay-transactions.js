export async function onRequestGet(context) {
    try {

        const apiKey =
            context.env.FAUCETPAY_API_KEY;

        if (!apiKey) {
            return Response.json(
                {
                    success: false,
                    error: "FaucetPay API key is missing"
                },
                { status: 500 }
            );
        }

        const response = await fetch(
            "https://faucetpay.io/api/v2/transactions",
            {
                method: "POST",

                headers: {
                    "Authorization":
                        `Bearer ${apiKey}`,

                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    coin: "BTC",
                    page: 1
                })
            }
        );

        const result =
            await response.json();

        console.log(
            "FAUCETPAY TRANSACTIONS STATUS:",
            response.status
        );

        console.log(
            "FAUCETPAY TRANSACTIONS RESPONSE:",
            JSON.stringify(result)
        );

        return Response.json({
            success: true,
            http_status: response.status,
            faucetpay: result
        });

    } catch (error) {

        console.error(
            "FaucetPay transactions error:",
            error
        );

        return Response.json(
            {
                success: false,
                error: error.message
            },
            { status: 500 }
        );
    }
}
