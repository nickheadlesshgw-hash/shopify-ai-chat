// server.js (ADMIN-ONLY)
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";
import { OpenAI } from "openai";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ===== ENV =====
const APP_BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, "");
const SHOP_DOMAIN = process.env.SHOP_DOMAIN || ""; // es: buzzhivestore.myshopify.com
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";

// OAuth
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || "";
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || "";
const SHOPIFY_SCOPES =
  process.env.SHOPIFY_SCOPES ||
  "read_products,read_orders,read_app_proxy,write_app_proxy";

// Fallback se vuoi testare senza OAuth (sconsigliato in prod)
const ADMIN_TOKEN_FALLBACK = process.env.SHOPIFY_ADMIN_TOKEN || "";

if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY mancante.");
const client = new OpenAI({ apiKey: OPENAI_API_KEY });

// In memoria: token Admin per shop (prototipo)
const TOKENS = new Map(); // Map<shopDomain, admin_access_token>

// ===== Utils =====
function verifyProxySignature(/* query */) { return true; } // abilita check HMAC in prod
function isValidShop(shop) { return typeof shop === "string" && /\.myshopify\.com$/.test(shop); }
function sanitizeLinks(text, shopDomain) {
  if (!text) return text;
  const allowedHost = (shopDomain || "").replace(/^https?:\/\//, "");
  return String(text)
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi, (m, label, url) =>
      url.includes(allowedHost) ? m : `${label} ([link rimosso])`)
    .replace(/https?:\/\/[^\s)]+/gi, m => (m.includes(allowedHost) ? m : "[link rimosso]"));
}

// ===== OAuth =====
function buildInstallUrl({ shop, state }) {
  const params = new URLSearchParams({
    client_id: SHOPIFY_CLIENT_ID,
    scope: SHOPIFY_SCOPES,
    redirect_uri: `${APP_BASE_URL}/auth/callback`,
    state
  });
  return `https://${shop}/admin/oauth/authorize?${params.toString()}`;
}
function verifyHmacQuery(queryObj, secret) {
  const q = { ...queryObj };
  const hmac = q.hmac;
  if (!hmac) return false;
  delete q.hmac; delete q.signature;
  const message = Object.keys(q).sort().map(k => `${k}=${Array.isArray(q[k]) ? q[k].join(",") : q[k]}`).join("&");
  const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(hmac, "utf8")); }
  catch { return false; }
}
app.get("/auth/start", (req, res) => {
  const shop = String(req.query.shop || "").toLowerCase();
  if (!isValidShop(shop)) return res.status(400).send("Parametro 'shop' non valido");
  const state = crypto.randomBytes(16).toString("hex"); // salva/verifica in prod
  res.redirect(buildInstallUrl({ shop, state }));
});
app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code } = req.query;
    if (!isValidShop(shop)) return res.status(400).send("Shop non valido");
    if (!verifyHmacQuery(req.query, SHOPIFY_CLIENT_SECRET)) return res.status(400).send("HMAC non valido");
    const r = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: SHOPIFY_CLIENT_ID, client_secret: SHOPIFY_CLIENT_SECRET, code })
    });
    const json = await r.json();
    if (!json.access_token) throw new Error("Nessun access_token");
    TOKENS.set(shop, json.access_token);
    console.log(`[OAuth] Install OK for ${shop} — token: ${json.access_token.slice(0,6)}...`);
    res.send("Installazione completata ✅ Puoi chiudere questa pagina.");
  } catch (e) {
    console.error("[OAuth] Error:", e);
    res.status(500).send("OAuth error: " + e.message);
  }
});

// ===== Admin API helpers =====
async function adminGraphQL({ shopDomain, query, variables }) {
  const domain = shopDomain || SHOP_DOMAIN;
  const adminToken = TOKENS.get(domain) || ADMIN_TOKEN_FALLBACK;
  if (!adminToken) throw new Error("Admin token mancante: esegui OAuth /auth/start?shop=SHOP");
  const url = `https://${domain}/admin/api/2024-07/graphql.json`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": adminToken },
    body: JSON.stringify({ query, variables })
  });
  const json = await r.json();
  if (json.errors) { console.error("[Admin errors]", JSON.stringify(json.errors)); throw new Error("Errore Admin API"); }
  return json.data;
}

// — getProductByHandle (titolo/descrizione/prezzo) —
async function adminGetProductByHandle(handle, shopDomain = SHOP_DOMAIN) {
  const q = `
    query($q:String!) {
      products(first:1, query:$q) {
        edges {
          node {
            id title handle bodyHtml
            priceRangeV2 { minVariantPrice { amount currencyCode } }
            status
          }
        }
      }
    }`;
  const data = await adminGraphQL({ shopDomain, query: q, variables: { q: `handle:${handle}` } });
  return data?.products?.edges?.[0]?.node || null;
}

// — getCheapestProduct (prodotto attivo con prezzo minore) —
async function adminGetCheapestProduct(shopDomain = SHOP_DOMAIN) {
  const q = `
    query {
      products(first:100, query:"status:active") {
        edges {
          node {
            id title handle bodyHtml
            priceRangeV2 { minVariantPrice { amount currencyCode } }
          }
        }
      }
    }`;
  const data = await adminGraphQL({ shopDomain, query: q });
  const list = (data?.products?.edges || []).map(e => e.node);
  let cheapest = null, min = Infinity, curr = "EUR";
  for (const p of list) {
    const amt = parseFloat(p?.priceRangeV2?.minVariantPrice?.amount || "NaN");
    const code = p?.priceRangeV2?.minVariantPrice?.currencyCode || "EUR";
    if (!isNaN(amt) && amt < min) { min = amt; curr = code; cheapest = { ...p, _min: amt, _ccy: code }; }
  }
  return cheapest ? { ...cheapest, minPrice: { amount: String(min), currencyCode: curr } } : null;
}

// — searchProducts (testo + sort prezzo opzionale) —
async function adminSearchProducts({ shopDomain = SHOP_DOMAIN, queryText = "", limit = 5, sort = "RELEVANCE" }) {
  const q = `
    query($q:String!, $n:Int!) {
      products(first:$n, query:$q) {
        edges {
          node {
            id title handle bodyHtml
            priceRangeV2 { minVariantPrice { amount currencyCode } }
          }
        }
      }
    }`;
  const data = await adminGraphQL({ shopDomain, query: q, variables: { q: queryText, n: Math.max(1, Math.min(20, limit)) } });
  let list = (data?.products?.edges || []).map(e => {
    const n = e.node;
    return { ...n, minPrice: n.priceRangeV2?.minVariantPrice || null };
  });
  if (sort === "PRICE_ASC") list.sort((a,b)=> parseFloat(a?.minPrice?.amount||"Infinity")-parseFloat(b?.minPrice?.amount||"Infinity"));
  if (sort === "PRICE_DESC") list.sort((a,b)=> parseFloat(b?.minPrice?.amount||"-Infinity")-parseFloat(a?.minPrice?.amount||"-Infinity"));
  return list;
}

// — ordine (email + numero) —
async function adminGetOrderStatus(email, orderNumber, shopDomain = SHOP_DOMAIN) {
  const q = `
    query($q:String!) {
      orders(first:1, query:$q) {
        edges { node { id name displayFinancialStatus displayFulfillmentStatus email } }
      }
    }`;
  const data = await adminGraphQL({ shopDomain, query: q, variables: { q: `name:${orderNumber} email:${email}` } });
  return data?.orders?.edges?.[0]?.node || null;
}

// ===== OpenAI + tools =====
async function chatWithTools(messages, { shopDomain } = {}) {
  if (!OPENAI_API_KEY) return "Configurazione mancante: OPENAI_API_KEY non impostata.";

  const tools = [
    {
      type: "function",
      name: "getProductByHandle",
      description: "Dettagli prodotto (titolo, descrizione, prezzo) per handle.",
      parameters: { type: "object", properties: { handle: { type: "string" } }, required: ["handle"] }
    },
    {
      type: "function",
      name: "getCheapestProduct",
      description: "Prodotto attivo più economico (titolo, descrizione, prezzo).",
      parameters: { type: "object", properties: {} }
    },
    {
      type: "function",
      name: "searchProducts",
      description: "Cerca prodotti per parole chiave (titolo/descrizione/tag) e ritorna titolo/descrizione/prezzo.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string" },
          limit: { type: "number", default: 5 },
          sort:  { type: "string", enum: ["RELEVANCE","PRICE_ASC","PRICE_DESC"], default: "RELEVANCE" }
        },
        required: ["query"]
      }
    },
    {
      type: "function",
      name: "getOrderStatus",
      description: "Stato ordine dato email e numero.",
      parameters: {
        type: "object",
        properties: { email: { type: "string" }, orderNumber: { type: "string" } },
        required: ["email","orderNumber"]
      }
    }
  ];

  let resp;
  try {
    resp = await client.responses.create({ model: OPENAI_MODEL, input: messages, tools });
  } catch (e) {
    console.error("[OpenAI] create error:", e);
    return "⚠️ Errore AI: " + e.message;
  }

  while (true) {
    const toolCalls = resp?.output?.filter(o => o.type === "tool_call") || [];
    if (!toolCalls.length) break;

    const toolResults = [];
    for (const call of toolCalls) {
      try {
        const { name, arguments: args } = call;

        if (name === "getProductByHandle") {
          const data = await adminGetProductByHandle(args.handle, shopDomain);
          toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }
        if (name === "getCheapestProduct") {
          const data = await adminGetCheapestProduct(shopDomain);
          toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }
        if (name === "searchProducts") {
          const data = await adminSearchProducts({
            shopDomain, queryText: args.query, limit: args.limit || 5, sort: args.sort || "RELEVANCE"
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

// ===== App Proxy =====
app.all("/chat-proxy", async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  try {
    if (!verifyProxySignature(req.query)) return res.status(401).json({ error: "Invalid signature" });

    const isGet = req.method === "GET";
    const rawMsg = isGet ? (req.query.message ?? "") : (req.body.message ?? "");
    if (isGet && !rawMsg) {
      return res.json({ ok: true, hint: "GET ?message=... o POST { message }" });
    }

    const userMsg = String(rawMsg || "");
    const shopFromProxy = String(req.query.shop || SHOP_DOMAIN).toLowerCase();

    console.log(">>> /chat-proxy:", req.method, "shop:", shopFromProxy, "msg:", userMsg);

    const messages = [
      { role: "system", content:
        "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. " +
        "NON inserire MAI link esterni. Se serve un link, usa solo URL interni del negozio (es. /products/handle, /policies). " +
        "Quando suggerisci prodotti, includi titolo, breve descrizione e prezzo; se possibile fornisci anche il percorso interno /products/<handle>." },
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

// ===== Misc =====
app.get("/", (req, res) => res.send("AI Chat up ✅"));
app.get("/test", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`
    <form action="/chat-proxy" method="GET" style="max-width:480px;margin:40px auto;font-family:sans-serif">
      <h3>Test AI Chat</h3>
      <textarea name="message" style="width:100%;height:120px"></textarea><br><br>
      <button type="submit">Invia (GET)</button>
      <p style="margin-top:12px;color:#666">Oppure POST /chat-proxy con body { message }.</p>
    </form>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AI Chat server ascolta su :${PORT}`));
