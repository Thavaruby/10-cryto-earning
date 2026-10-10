
const ASSETS = [
  "BTC", "ETH", "LTC", "DOGE", "BNB",
  "SOL", "TRX", "TON", "BCH", "XRP",
  "ADA", "AVAX", "DOT", "LINK", "POL"
];

const BASE_URL = "https://data-api.binance.vision/api/v3/ticker/price";

export async function onRequest(context) {
  const { request } = context;

  if (request.method !== "GET") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405, headers: { Allow: "GET" } }
    );
  }

  const symbols = ASSETS.map(asset => `${asset}USDT`);

  try {
    const url = new URL(BASE_URL);
    url.searchParams.set("symbols", JSON.stringify(symbols));

    const response = await fetch(url.toString(), {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
      cf: { cacheTtl: 30, cacheEverything: true }
    });

    if (!response.ok) {
      return Response.json(
        { error: "Crypto rate provider unavailable" },
        { status: 502 }
      );
    }

    const data = await response.json();

    if (!Array.isArray(data)) {
      return Response.json(
        { error: "Invalid crypto rate response" },
        { status: 502 }
      );
    }

    const rates = {};

    for (const item of data) {
      const asset = item.symbol.replace(/USDT$/, "");
      const price = Number(item.price);

      if (
        ASSETS.includes(asset) &&
        Number.isFinite(price) &&
        price > 0
      ) {
        rates[asset] = price;
      }
    }

    if (!rates.BTC || !rates.ETH) {
      return Response.json(
        { error: "Required crypto rates unavailable" },
        { status: 502 }
      );
    }

    return Response.json(
      {
        base: "USDT",
        quote: "USDT",
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
      { error: "Could not retrieve crypto rates. Please retry." },
      { status: 502 }
    );
  }
}
