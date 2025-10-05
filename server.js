// server.js — Shopify AI Chat (Admin-only, OAuth, App Proxy, Tools + Intent Fallback)
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";
import { OpenAI } from "openai";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

/* ========== ENV ========== */
const APP_BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, ""); // es: https://shopify-ai-chat.onrender.com
const SHOP_DOMAIN = process.env.SHOP_DOMAIN || ""; // es: wm126i-0y.myshopify.com

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini"; // economico e veloce

// OAuth
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || "";
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || "";
const SHOPIFY_SCOPES =
  process.env.SHOPIFY_SCOPES ||
  "read_products,read_orders,read_app_proxy,write_app_proxy";

// opzionale: fallback token admin per test senza OAuth
const ADMIN_TOKEN_FALLBACK = process.env.SHOPIFY_ADMIN_TOKEN || "";

/* ========== OpenAI ========== */
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY mancante");
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

/* ========== Token storage (prototipo in RAM) ========== */
const TOKENS = new Map(); // Map<shopDomain, admin_access_token>

/* ========== Utils ========== */
function isValidShop(shop) {
  return typeof shop === "string" && /\.myshopify\.com$/.test(shop);
}
function verifyProxySignature(/*query*/) { return true; } // abilita HMAC in prod

function sanitizeLinks(text, shopDomain) {
  if (!text) return text;
  const allowedHost = (shopDomain || "").replace(/^https?:\/\//, "");
  return String(text)
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi, (m, label, url) =>
      url.includes(allowedHost) ? m : `${label} ([link rimosso])`)
    .replace(/https?:\/\/[^\s)]+/gi, m => (m.includes(allowedHost) ? m : "[link rimosso]"));
}

/* ========== OAuth flow ========== */
function buildInstallUrl({ shop, state }) {
  const qs = new URLSearchParams({
    client_id: SHOPIFY_CLIENT_ID,
    scope: SHOPIFY_SCOPES,
    redirect_uri: `${APP_BASE_URL}/auth/callback`,
    state
  });
  return `https://${shop}/admin/oauth/authorize?${qs.toString()}`;
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
  const state = crypto.randomBytes(16).toString("hex"); // in prod salva e verifica
  res.redirect(buildInstallUrl({ shop, state }));
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code } = req.query;
    if (!isValidShop(shop)) return res.status(400).send("Shop non valido");
    if (!verifyHmacQuery(req.query, SHOPIFY_CLIENT_SECRET)) return res.status(400).send("HMAC non valido");

    const r = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST", headers: { "Content-Type":"application/json" },
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

/* ========== Admin API helpers (GraphQL e REST) ========== */
function getAdminToken(domain) {
  return TOKENS.get(domain) || ADMIN_TOKEN_FALLBACK;
}

async function adminGraphQL({ shopDomain, query, variables }) {
  const domain = shopDomain || SHOP_DOMAIN;
  const adminToken = getAdminToken(domain);
  if (!adminToken) throw new Error("Admin token mancante: esegui OAuth /auth/start?shop=SHOP");
  const url = `https://${domain}/admin/api/2024-07/graphql.json`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type":"application/json", "X-Shopify-Access-Token": adminToken },
    body: JSON.stringify({ query, variables })
  });
  const json = await r.json();
  if (json.errors) {
    console.error("[Admin GraphQL errors]", JSON.stringify(json.errors));
    throw new Error("Errore Admin API");
  }
  return json.data;
}

// — Product by handle (GraphQL) —
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
  const data = await adminGraphQL({ shopDomain, query: q, variables:{ q:`handle:${handle}` } });
  const node = data?.products?.edges?.[0]?.node || null;
  if (!node) return null;
  return {
    title: node.title,
    handle: node.handle,
    price: node.priceRangeV2?.minVariantPrice?.amount || null,
    currency: node.priceRangeV2?.minVariantPrice?.currencyCode || null,
    description: (node.bodyHtml || "").replace(/<[^>]+>/g, "")
  };
}

// — Cheapest product (REST: products + variants) —
async function adminGetCheapestProduct(shopDomain = SHOP_DOMAIN) {
  const domain = shopDomain || SHOP_DOMAIN;
  const adminToken = getAdminToken(domain);
  if (!adminToken) throw new Error("Admin token mancante: esegui OAuth /auth/start?shop=SHOP");

  // prendiamo 250 prodotti max per sicurezza
  const url = `https://${domain}/admin/api/2024-07/products.json?status=active&limit=250`;
  const r = await fetch(url, { headers: { "X-Shopify-Access-Token": adminToken } });
  const json = await r.json();

  const products = Array.isArray(json.products) ? json.products : [];
  let best = null;
  for (const p of products) {
    for (const v of (p.variants || [])) {
      const pr = parseFloat(v.price);
      if (isNaN(pr)) continue;
      if (!best || pr < best.price) {
        best = {
          title: p.title,
          handle: p.handle,
          price: pr,
          currency: p?.variants?.[0]?.presentment_prices?.[0]?.price?.currency || "EUR",
          description: (p.body_html || "").replace(/<[^>]+>/g, "").slice(0, 220),
        };
      }
    }
  }
  return best;
}

// — Search products (GraphQL full-text + sort in JS) —
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
  const data = await adminGraphQL({ shopDomain, query: q, variables: { q: queryText, n: Math.max(1, Math.min(50, limit)) }});
  let list = (data?.products?.edges || []).map(e => {
    const n = e.node;
    return {
      title: n.title,
      handle: n.handle,
      price: parseFloat(n.priceRangeV2?.minVariantPrice?.amount || "NaN"),
      currency: n.priceRangeV2?.minVariantPrice?.currencyCode || "EUR",
      description: (n.bodyHtml || "").replace(/<[^>]+>/g, "").slice(0, 200)
    };
  });
  if (sort === "PRICE_ASC")   list = list.filter(p=>!isNaN(p.price)).sort((a,b)=>a.price-b.price);
  if (sort === "PRICE_DESC")  list = list.filter(p=>!isNaN(p.price)).sort((a,b)=>b.price-a.price);
  return list;
}

/* ========== OpenAI Tools + Fallback Intent ========== */
async function chatWithTools(messages, { shopDomain }) {
  // 1) Router a parole chiave (garantisce risposta anche se il modello non invoca tools)
  const userText = (messages.find(m => m.role === "user")?.content || "").toLowerCase();

  // pattern per “prodotto più economico”
  const cheapestIntent = /(prodotto|articolo).*(pi[uù] economico|meno costoso|piu economico|piu' economico|che costa meno)|pi[uù] economico/;
  if (cheapestIntent.test(userText)) {
    try {
      const p = await adminGetCheapestProduct(shopDomain);
      if (!p) return "Non ho trovato prodotti attivi con un prezzo valido.";
      return `Il prodotto più economico è **${p.title}** a ${p.price} ${p.currency}. Puoi vederlo qui: /products/${p.handle}.` ;
    } catch (e) {
      console.error("[Cheapest fallback] Error:", e);
      // continua con LLM
    }
  }

  // 2) LLM con tools (per tutte le altre richieste)
  const tools = [
    {
      type: "function",
      name: "getProductByHandle",
      description: "Dettagli prodotto (titolo, descrizione, prezzo) dato l'handle.",
      parameters: { type:"object", properties:{ handle:{ type:"string" } }, required:["handle"] }
    },
    {
      type: "function",
      name: "getCheapestProduct",
      description: "Restituisce il prodotto attivo meno costoso del negozio.",
      parameters: { type:"object", properties: {} }
    },
    {
      type: "function",
      name: "searchProducts",
      description: "Cerca prodotti per testo e ritorna liste (titolo, prezzo, handle).",
      parameters: {
        type:"object",
        properties:{
          query:{ type:"string" },
          limit:{ type:"number", default:5 },
          sort:{ type:"string", enum:["RELEVANCE","PRICE_ASC","PRICE_DESC"], default:"RELEVANCE" }
        },
        required:["query"]
      }
    }
  ];

  let resp;
  try {
    resp = await openai.responses.create({ model: OPENAI_MODEL, input: messages, tools });
  } catch (e) {
    console.error("[OpenAI] create error:", e);
    return "⚠️ Errore AI: " + e.message;
  }

  while (true) {
    const toolCalls = resp?.output?.filter(o => o.type === "tool_call") || [];
    if (!toolCalls.length) break;

    const toolResults = [];
    for (const call of toolCalls) {
      const { name, arguments: args } = call;
      try {
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
            shopDomain,
            queryText: args.query,
            limit: args.limit || 5,
            sort: args.sort || "RELEVANCE"
          });
          toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }
      } catch (e) {
        toolResults.push({ tool_call_id: call.id, output: JSON.stringify({ error: e.message }) });
      }
    }

    try {
      resp = await openai.responses.create({
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

/* ========== App Proxy (widget) ========== */
app.all("/chat-proxy", async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  try {
    if (!verifyProxySignature(req.query)) return res.status(401).json({ error:"Invalid signature" });

    const isGet = req.method === "GET";
    const rawMsg = isGet ? (req.query.message ?? "") : (req.body.message ?? "");
    if (isGet && !rawMsg) return res.json({ ok:true, hint:"GET ?message=... o POST { message }" });

    const userMsg = String(rawMsg || "");
    const shopFromProxy = String(req.query.shop || SHOP_DOMAIN).toLowerCase();

    console.log(">>> /chat-proxy:", req.method, "shop:", shopFromProxy, "msg:", userMsg);

    const messages = [
      { role:"system", content:
        "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. " +
        "NON inserire MAI link esterni. Se serve un link, usa solo URL interni del negozio (es. /products/handle, /policies). " +
        "Quando suggerisci prodotti, includi titolo, breve descrizione e prezzo e, se possibile, il percorso /products/<handle>."
      },
      { role:"user", content: userMsg }
    ];

    const answer = await chatWithTools(messages, { shopDomain: shopFromProxy })
      .catch(e => { console.error("chatWithTools error:", e); return "⚠️ Errore AI: " + e.message; });

    const safeAnswer = sanitizeLinks(answer, `https://${shopFromProxy}`);
    res.json({ answer: safeAnswer });
  } catch (e) {
    console.error("Errore /chat-proxy:", e);
    res.status(500).json({ error: e.message });
  }
});

/* ========== Debug endpoints ========== */
app.get("/debug/cheapest", async (req, res) => {
  try {
    const shop = String(req.query.shop || SHOP_DOMAIN).toLowerCase();
    const p = await adminGetCheapestProduct(shop);
    if (!p) return res.status(404).json({ ok:false, msg:"Nessun prodotto attivo con prezzo trovato." });
    res.json({
      ok:true,
      title: p.title,
      handle: p.handle,
      price: `${p.price} ${p.currency || ""}`.trim(),
      preview: `/products/${p.handle}`,
      description: p.description
    });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});

app.get("/debug/search", async (req, res) => {
  try {
    const shop = String(req.query.shop || SHOP_DOMAIN).toLowerCase();
    const q = String(req.query.q || "");
    const limit = Number(req.query.limit || 5);
    const sort = String(req.query.sort || "RELEVANCE");
    const list = await adminSearchProducts({ shopDomain: shop, queryText: q, limit, sort });
    res.json({
      ok:true,
      count:list.length,
      items: list.map(p => ({
        title:p.title, handle:p.handle,
        price: isNaN(p.price) ? null : `${p.price} ${p.currency || ""}`.trim(),
        preview:`/products/${p.handle}`,
        description:p.description
      }))
    });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});

/* ========== Misc ========== */
app.get("/", (req, res) => res.send("AI Chat up ✅"));
app.get("/test", (req, res) => {
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`
    <form action="/chat-proxy" method="GET" style="max-width:520px;margin:40px auto;font-family:sans-serif">
      <h3>Test AI Chat</h3>
      <textarea name="message" style="width:100%;height:120px"></textarea><br><br>
      <button type="submit">Invia (GET)</button>
      <p style="margin-top:12px;color:#666">Oppure POST /chat-proxy con body { message }.</p>
    </form>
  `);
});

/* ========== Start ========== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AI Chat server ascolta su :${PORT}`));
