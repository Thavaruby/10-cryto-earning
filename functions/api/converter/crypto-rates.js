
const API_BASE = "https://api-gcp.binance.com/api/v3";

const FIAT_ASSETS = new Set([
  "USD", "EUR", "GBP", "TRY", "BRL", "AUD", "CAD",
  "CHF", "PLN", "UAH", "RUB", "ZAR", "NGN", "ARS",
  "COP", "MXN", "IDR", "INR", "JPY", "KRW", "VND",
  "PHP", "THB", "SGD", "AED", "DKK", "NOK", "SEK",
  "NZD", "CZK", "RON", "HUF", "KZT", "TWD", "MAD",
  "EGP", "ILS", "PKR", "LKR", "CLP", "PEN", "BOB"
]);

export async function onRequest({ request }) {
  if (request.method !== "GET") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405, headers: { Allow: "GET" } }
    );
  }

  const cacheKey = new Request(
    new URL("/api/crypto-rates", request.url).toString()
  );

  try {
    const cached = await caches.default.match(cacheKey);
    if (cached) return cached;
  } catch {
    // Continue if edge cache is unavailable.
  }

  try {
    const [exchangeResponse, tickerResponse] = await Promise.all([
      fetch(`${API_BASE}/exchangeInfo`, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10000)
      }),
      fetch(`${API_BASE}/ticker/price`, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10000)
      })
    ]);

    if (!exchangeResponse.ok || !tickerResponse.ok) {
      return Response.json(
        {
          error: "Binance market data unavailable",
          exchangeStatus: exchangeResponse.status,
          tickerStatus: tickerResponse.status
        },
        { status: 502 }
      );
    }

    const [exchangeData, tickerData] = await Promise.all([
      exchangeResponse.json(),
      tickerResponse.json()
    ]);

    if (
      !Array.isArray(exchangeData.symbols) ||
      !Array.isArray(tickerData)
    ) {
      return Response.json(
        { error: "Invalid Binance response" },
        { status: 502 }
      );
    }

    const prices = new Map();

    for (const item of tickerData) {
      const price = Number(item.price);

      if (item.symbol && Number.isFinite(price) && price > 0) {
        prices.set(item.symbol, price);
      }
    }

    const graph = new Map();

    function addEdge(from, to, rate) {
      if (!Number.isFinite(rate) || rate <= 0) return;

      if (!graph.has(from)) graph.set(from, []);
      graph.get(from).push({ asset: to, rate });
    }

    for (const pair of exchangeData.symbols) {
      if (
        pair.status !== "TRADING" ||
        pair.isSpotTradingAllowed !== true ||
        FIAT_ASSETS.has(pair.baseAsset) ||
        FIAT_ASSETS.has(pair.quoteAsset)
      ) {
        continue;
      }

      const price = prices.get(pair.symbol);
      if (!price) continue;

      addEdge(pair.baseAsset, pair.quoteAsset, price);
      addEdge(pair.quoteAsset, pair.baseAsset, 1 / price);
    }

    // Calculate how many units of each asset equal 1 USDT.
    // Direct USDT pairs are discovered first; other assets can
    // be reached through available trading pairs.
    const unitsPerUSDT = new Map([["USDT", 1]]);
    const queue = ["USDT"];
    let index = 0;

    while (index < queue.length) {
      const current = queue[index++];
      const currentAmount = unitsPerUSDT.get(current);

      for (const edge of graph.get(current) || []) {
        if (unitsPerUSDT.has(edge.asset)) continue;

        const amount = currentAmount * edge.rate;

        if (!Number.isFinite(amount) || amount <= 0) continue;

        unitsPerUSDT.set(edge.asset, amount);
        queue.push(edge.asset);
      }
    }

    const rates = {};

    for (const [asset, units] of unitsPerUSDT) {
      if (asset === "USDT" || FIAT_ASSETS.has(asset)) continue;

      const priceInUSDT = 1 / units;

      if (Number.isFinite(priceInUSDT) && priceInUSDT > 0) {
        rates[asset] = Number(priceInUSDT.toPrecision(12));
      }
    }

    rates.USDT = 1;

    const response = Response.json(
      {
        base: "USDT",
        rates,
        count: Object.keys(rates).length,
        source: "Binance public Spot market data",
        fetchedAt: new Date().toISOString()
      },
      {
        headers: {
          "Cache-Control": "public, max-age=60, s-maxage=300",
          "X-Content-Type-Options": "nosniff"
        }
      }
    );

    try {
      await caches.default.put(cacheKey, response.clone());
    } catch {
      // Return live data even if caching fails.
    }

    return response;
  } catch {
    return Response.json(
      { error: "Could not retrieve Binance market data" },
      { status: 502 }
    );
  }
}
