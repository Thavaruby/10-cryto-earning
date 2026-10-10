
const ASSETS = [
  "BTC", "ETH", "LTC", "DOGE", "BNB",
  "SOL", "TRX", "TON", "BCH", "XRP",
  "ADA", "AVAX", "DOT", "LINK", "POL"
];

export async function onRequest({ request }) {
  if (request.method !== "GET") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405, headers: { Allow: "GET" } }
    );
  }

  try {
    const response = await fetch(
      "https://api-gcp.binance.com/api/v3/ticker/price",
      {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10000)
      }
    );

    if (!response.ok) {
      return Response.json(
        { error: "Crypto provider unavailable", upstreamStatus: response.status },
        { status: 502 }
      );
    }

    const data = await response.json();

    if (!Array.isArray(data)) {
      return Response.json(
        { error: "Invalid provider response" },
        { status: 502 }
      );
    }

    const available = new Map();

    for (const item of data) {
      if (!item.symbol?.endsWith("USDT")) continue;

      const asset = item.symbol.slice(0, -4);
      const price = Number(item.price);

      if (
        ASSETS.includes(asset) &&
        Number.isFinite(price) &&
        price > 0
      ) {
        available.set(asset, price);
      }
    }

    const rates = Object.fromEntries(
      ASSETS.filter(asset => available.has(asset))
        .map(asset => [asset, available.get(asset)])
    );

    if (Object.keys(rates).length === 0) {
      return Response.json(
        { error: "No supported crypto pairs available" },
        { status: 502 }
      );
    }

    return Response.json(
      {
        base: "USDT",
        rates,
        source: "Binance public market data",
        fetchedAt: new Date().toISOString()
      },
      {
        headers: {
          "Cache-Control": "public, max-age=30",
          "X-Content-Type-Options": "nosniff"
        }
      }
    );
  } catch {
    return Response.json(
      { error: "Could not connect to crypto provider" },
      { status: 502 }
    );
  }
}
