// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";
import { OpenAI } from "openai";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true })); // per form/test

// ===== ENV =====
const APP_BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, ""); // es: https://shopify-ai-chat.onrender.com
const SHOP_DOMAIN = process.env.SHOP_DOMAIN || ""; // default shop (facoltativo)
const SF_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN || "";
const ADMIN_TOKEN_FALLBACK = process.env.SHOPIFY_ADMIN_TOKEN || ""; // fallback se non usi OAuth
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || "";
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || "";
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || "read_products,read_orders,read_app_proxy,write_app_proxy";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini"; // modello economico

if (!OPENAI_API_KEY) {
  console.warn("[WARN] OPENAI_API_KEY mancante. /chat-proxy risponderà con errore.");
}
if (!SF_TOKEN) {
  console.warn("[WARN] SHOPIFY_STOREFRONT_TOKEN mancante. I tools prodotti non funzioneranno.");
}

const client = new OpenAI({ apiKey: OPENAI_API_KEY });

// In memoria: token Admin per shop (prototipo; in produzione usa DB/secret manager)
const TOKENS = new Map(); // Map<shopDomain, admin_access_token>

// ===== Utils =====

// (FACOLTATIVO) Verifica firma App Proxy (qui bypassata per prototipo)
function verifyProxySignature(/* query */) { return true; }

// Verifica shop *.myshopify.com
function isValidShop(shop) { return typeof shop === "string" && /\.myshopify\.com$/.test(shop); }

// Blocca link esterni, consente relativi e dominio dello shop
function sanitizeLinks(text, shopDomain) {
  if (!text) return text;
  const allowedHost = (shopDomain || "").replace(/^https?:\/\//, "");
  return String(text)
    // markdown [label](url)
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi, (m, label, url) => {
      return url.includes(allowedHost) ? m : `${label} ([link rimosso])`;
    })
    // url in chiaro
    .replace(/https?:\/\/[^\s)]+/gi, (m) => (m.includes(allowedHost) ? m : "[link rimosso]"));
}

// ===== OAuth (Partner App) =====

// Costruisce URL autorizzazione
function buildInstallUrl({ shop, state }) {
  const params = new URLSearchParams({
    client_id: SHOPIFY_CLIENT_ID,
    scope: SHOPIFY_SCOPES,
    redirect_uri: `${APP_BASE_URL}/auth/callback`,
    state
  });
  return `https://${shop}/admin/oauth/authorize?${params.toString()}`;
}

// Verifica HMAC callback
function verifyHmacQuery(queryObj, secret) {
  const q = { ...queryObj };
  const hmac = q.hmac;
  if (!hmac) return false;
  delete q.hmac;
  delete q.signature;
  const message = Object.keys(q)
    .sort()
    .map(k => `${k}=${Array.isArray(q[k]) ? q[k].join(",") : q[k]}`)
    .join("&");
  const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(hmac, "utf8"));
  } catch {
    return false;
  }
}

// Avvio installazione: /auth/start?shop=tuo-shop.myshopify.com
app.get("/auth/start", (req, res) => {
  const shop = String(req.query.shop || "").toLowerCase();
  if (!isValidShop(shop)) return res.status(400).send("Parametro 'shop' mancante o non valido");
  const state = crypto.randomBytes(16).toString("hex"); // in produzione: salva/verifica state
  res.redirect(buildInstallUrl({ shop, state }));
});

// Callback dopo consenso
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code } = req.query;
    if (!isValidShop(shop)) return res.status(400).send("Shop non valido");
    if (!verifyHmacQuery(req.query, SHOPIFY_CLIENT_SECRET)) {
      return res.status(400).send("HMAC non valido");
    }
    const r = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code
      })
    });
    const json = await r.json(); // { access_token, scope }
    if (!json.access_token) throw new Error("Nessun access_token nella risposta OAuth");
    TOKENS.set(shop, json.access_token);
    console.log(`[OAuth] Install OK for ${shop} — token: ${json.access_token.slice(0,6)}...`);
    res.send("Installazione completata ✅ Puoi chiudere questa pagina e usare l'App Proxy / le API.");
  } catch (e) {
    console.error("[OAuth] Error:", e);
    res.status(500).send("OAuth error: " + e.message);
  }
});

// ===== Shopify helpers (Storefront & Admin) =====

// Storefront API base caller
async function storefrontGraphQL({ shopDomain, query, variables }) {
  const domain = shopDomain || SHOP_DOMAIN;
  const url = `https://${domain}/api/2024-07/graphql.json`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Storefront-Access-Token": SF_TOKEN
    },
    body: JSON.stringify({ query, variables })
  });
  const json = await r.json();
  if (json.errors || json.data?.__typename === "GraphQLError") {
    console.error("[Storefront errors]", JSON.stringify(json));
  }
  return json.data;
}

// 1) Prodotto per handle
async function storefrontGetProductByHandle(handle, shopDomain = SHOP_DOMAIN) {
  const q = `
    query($handle: String!) {
      product(handle: $handle) {
        title handle descriptionHtml
        variants(first:1){ edges{ node{ id price{ amount currencyCode } availableForSale } } }
      }
    }`;
  const data = await storefrontGraphQL({ shopDomain, query: q, variables: { handle } });
  return data?.product || null;
}

// 2) Prodotto più economico
async function storefrontGetCheapestProduct(shopDomain = SHOP_DOMAIN) {
  // Ordinamento per prezzo ascendente (PRICE), prendiamo il primo prodotto disponibile
  const q = `
    query {
      products(first: 20, sortKey: PRICE, reverse: false) {
        edges {
          node {
            title handle descriptionHtml
            priceRange { minVariantPrice { amount currencyCode } }
            availableForSale
          }
        }
      }
    }`;
  const data = await storefrontGraphQL({ shopDomain, query: q });
  const list = data?.products?.edges?.map(e => e.node) || [];
  const firstAvailable = list.find(p => p.availableForSale) || list[0] || null;
  return firstAvailable;
}

// 3) Ricerca prodotti (per titolo/descrizione/tag) con ordinamento per prezzo opzionale
async function storefrontSearchProducts({ shopDomain = SHOP_DOMAIN, queryText = "", limit = 5, sort = "RELEVANCE" }) {
  // sort: RELEVANCE | PRICE_ASC | PRICE_DESC
  let sortKey = "RELEVANCE"; let reverse = false;
  if (sort === "PRICE_ASC") { sortKey = "PRICE"; reverse = false; }
  if (sort === "PRICE_DESC") { sortKey = "PRICE"; reverse = true; }

  const q = `
    query($q: String!, $n: Int!, $reverse: Boolean!, $sortKey: ProductSortKeys!) {
      products(first: $n, query: $q, reverse: $reverse, sortKey: $sortKey) {
        edges {
          node {
            title handle descriptionHtml
            priceRange { minVariantPrice { amount currencyCode } }
            availableForSale
          }
        }
      }
    }`;
  const data = await storefrontGraphQL({
    shopDomain,
    query: q,
    variables: { q: queryText, n: Math.max(1, Math.min(20, limit)), reverse, sortKey }
  });
  const list = data?.products?.edges?.map(e => e.node) || [];
  return list;
}

// Admin API (stato ordine) — prende token da TOKENS[shop] o fallback ENV
async function adminGetOrderStatus(email, orderNumber, shopDomain = SHOP_DOMAIN) {
  const adminToken = TOKENS.get(shopDomain) || ADMIN_TOKEN_FALLBACK;
  if (!adminToken) throw new Error("Admin token mancante: completa l'installazione OAuth");

  const url = `https://${shopDomain}/admin/api/2024-07/graphql.json`;
  const q = `
    query($q:String!) {
      orders(first:1, query:$q) {
        edges { node { id name displayFinancialStatus displayFulfillmentStatus email } }
      }
    }`;
  const queryString = `name:${orderNumber} email:${email}`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": adminToken
    },
    body: JSON.stringify({ query: q, variables: { q: queryString } })
  });
  const json = await r.json();
  return json.data?.orders?.edges?.[0]?.node || null;
}

// ===== OpenAI chat con tools =====
async function chatWithTools(messages, { shopDomain } = {}) {
  if (!OPENAI_API_KEY) {
    return "Configurazione mancante: OPENAI_API_KEY non impostata.";
  }

  const tools = [
    {
      type: "function",
      name: "getProductByHandle",
      description: "Dettagli prodotto dal negozio Shopify (titolo, descrizione, prezzo) per handle.",
      parameters: {
        type: "object",
        properties: { handle: { type: "string", description: "Handle del prodotto (slug)" } },
        required: ["handle"]
      }
    },
    {
      type: "function",
      name: "getCheapestProduct",
      description: "Restituisce il prodotto più economico disponibile, con titolo, descrizione e prezzo.",
      parameters: { type: "object", properties: {} }
    },
    {
      type: "function",
      name: "searchProducts",
      description: "Cerca prodotti per parola chiave (titolo/descrizione/tag) e restituisce titolo, descrizione e prezzo.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Query di ricerca (es. 'albero natale')" },
          limit: { type: "number", description: "Quanti risultati (1-20)", default: 5 },
          sort:  { type: "string", enum: ["RELEVANCE", "PRICE_ASC", "PRICE_DESC"], default: "RELEVANCE" }
        },
        required: ["query"]
      }
    },
    {
      type: "function",
      name: "getOrderStatus",
      description: "Stato ordine dato email e numero",
      parameters: {
        type: "object",
        properties: {
          email: { type: "string" },
          orderNumber: { type: "string" }
        },
        required: ["email", "orderNumber"]
      }
    }
  ];

  let resp;
  try {
    resp = await client.responses.create({
      model: OPENAI_MODEL,
      input: messages,
      tools
    });
  } catch (e) {
    console.error("[OpenAI] create error:", e);
    return "⚠️ Errore AI: " + e.message;
  }

  // Gestione tool calls
  while (true) {
    const toolCalls = resp?.output?.filter(o => o.type === "tool_call") || [];
    if (!toolCalls.length) break;

    const toolResults = [];
    for (const call of toolCalls) {
      try {
        const { name, arguments: args } = call;

        if (name === "getProductByHandle") {
          const data = await storefrontGetProductByHandle(args.handle, shopDomain);
          toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }

        if (name === "getCheapestProduct") {
          const data = await storefrontGetCheapestProduct(shopDomain);
          toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }

        if (name === "searchProducts") {
          const data = await storefrontSearchProducts({
            shopDomain,
            queryText: args.query,
            limit: args.limit || 5,
            sort: args.sort || "RELEVANCE"
          });
          toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }

        if (name === "getOrderStatus") {
          const data = await adminGetOrderStatus(args.email, args.orderNumber, shopDomain);
          toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }
      } catch (e) {
        toolResults.push({ tool_call_id: call.id, output: JSON.stringify({ error: e.message }) });
      }
    }

    try {
      resp = await client.responses.create({
        model: OPENAI_MODEL,
        input: [
          ...messages,
          ...toolResults.map(tr => ({ role: "tool", tool_call_id: tr.tool_call_id, content: tr.output }))
        ],
        tools
      });
    } catch (e) {
      console.error("[OpenAI] follow-up error:", e);
      return "⚠️ Errore AI: " + e.message;
    }
  }

  return resp?.output_text || "…";
}

// ===== Rotte =====

// App Proxy (widget) — supporta GET ?message=... e POST {message}
app.all("/chat-proxy", async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  try {
    // Verifica firma (bypass in prototipo)
    if (!verifyProxySignature(req.query)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const isGet = req.method === "GET";
    const rawMsg = isGet ? (req.query.message ?? "") : (req.body.message ?? "");

    // GET senza message -> hint
    if (isGet && !rawMsg) {
      return res.json({ ok: true, hint: "Questa rotta accetta GET ?message=... o POST (JSON/urlencoded) { message }" });
    }

    const userMsg = String(rawMsg || "");
    const shopFromProxy = String(req.query.shop || SHOP_DOMAIN).toLowerCase();

    console.log(">>> /chat-proxy:", req.method, "shop:", shopFromProxy, "msg:", userMsg);

    const messages = [
      { role: "system", content:
        "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. " +
        "NON inserire MAI link esterni. Se serve un link, usa solo URL interni del negozio (es. /products/handle, /policies). " +
        "Quando citi un prodotto, includi titolo e una breve descrizione. " +
        "Se non sei sicuro di una risposta, chiedi chiarimenti o invita a contattare l'assistenza." },
      { role: "user", content: userMsg }
    ];

    const answer = await chatWithTools(messages, { shopDomain: shopFromProxy }).catch(e => {
      console.error("Errore chatWithTools:", e);
      return "⚠️ Errore AI: " + e.message;
    });

    const safeAnswer = sanitizeLinks(answer, `https://${shopFromProxy}`);
    res.json({ answer: safeAnswer });
  } catch (e) {
    console.error("Errore chat-proxy:", e);
    res.status(500).json({ error: e.message });
  }
});

// Streaming SSE (opzionale; spesso App Proxy bufferizza: usalo diretto sul dominio Render)
app.get("/chat-proxy-stream", async (req, res) => {
  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  const user = req.query.q || "Ciao!";
  const messages = [
    { role: "system", content: "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. Non usare mai link esterni." },
    { role: "user", content: String(user) }
  ];

  try {
    const stream = await client.responses.stream({ model: OPENAI_MODEL, input: messages });
    stream.on("message", (msg) => res.write(`data:${JSON.stringify(msg)}\n\n`));
    stream.on("end", () => res.end());
    stream.on("error", (e) => { res.write(`event: error\ndata:${JSON.stringify({ error: e.message })}\n\n`); res.end(); });
  } catch (e) {
    res.write(`event: error\ndata:${JSON.stringify({ error: e.message })}\n\n`);
    res.end();
  }
});

// Health & test
app.get("/", (req, res) => res.send("AI Chat up ✅"));
app.get("/test", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`
    <form action="/chat-proxy" method="GET" style="max-width:480px;margin:40px auto;font-family:sans-serif">
      <h3>Test AI Chat</h3>
      <p>Scrivi un messaggio e invia:</p>
      <textarea name="message" style="width:100%;height:120px"></textarea>
      <br><br>
      <button type="submit">Invia (GET)</button>
      <p style="margin-top:16px;color:#666">Puoi anche provare POST /chat-proxy con body { message }.</p>
    </form>
  `);
});

// Avvio
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AI Chat server ascolta su :${PORT}`));
