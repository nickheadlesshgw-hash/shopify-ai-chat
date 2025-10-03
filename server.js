// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";
import { OpenAI } from "openai";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true })); // per la form /test

// ===== ENV =====
const APP_BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, ""); // es: https://shopify-ai-chat.onrender.com
const SHOP_DOMAIN = process.env.SHOP_DOMAIN || ""; // opzionale default es: myshop.myshopify.com
const SF_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN || "";
const ADMIN_TOKEN_FALLBACK = process.env.SHOPIFY_ADMIN_TOKEN || ""; // fallback solo se non usi OAuth
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SHOPIFY_APP_SECRET = process.env.SHOPIFY_APP_SECRET || ""; // (non usato nel prototipo App Proxy)
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || "";
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || "";
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || "read_products,read_orders,read_app_proxy,write_app_proxy";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini"; // modello economico di default

const client = new OpenAI({ apiKey: OPENAI_API_KEY });

// In memoria: token Admin per shop (per prototipo; in produzione usa DB/secret manager)
const TOKENS = new Map(); // Map<shopDomain, admin_access_token>

// ===== Utils =====

// (FACOLTATIVO) Verifica firma App Proxy (qui bypass: true per prototipo)
function verifyProxySignature(/* query */) { return true; }

// Verifica shop *.myshopify.com
function isValidShop(shop) { return typeof shop === "string" && /\.myshopify\.com$/.test(shop); }

// Sanitize: blocca link esterni, consente relativi e dominio dello shop
function sanitizeLinks(text, shopDomain) {
  if (!text) return text;
  const allowedHost = (shopDomain || "").replace(/^https?:\/\//, "");
  return String(text)
    // 1) markdown [label](url)
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi, (m, label, url) => {
      return url.includes(allowedHost) ? m : `${label} ([link rimosso])`;
    })
    // 2) url naked
    .replace(/https?:\/\/[^\s)]+/gi, (m) => (m.includes(allowedHost) ? m : "[link rimosso]"));
}

// ===== OAuth (Partner App) =====

// Costruisce URL di autorizzazione
function buildInstallUrl({ shop, state }) {
  const params = new URLSearchParams({
    client_id: SHOPIFY_CLIENT_ID,
    scope: SHOPIFY_SCOPES,
    redirect_uri: `${APP_BASE_URL}/auth/callback`,
    state
  });
  return `https://${shop}/admin/oauth/authorize?${params.toString()}`;
}

// Verifica HMAC della query (callback OAuth)
function verifyHmacQuery(queryObj, secret) {
  const q = { ...queryObj };
  const hmac = q.hmac;
  if (!hmac) return false;
  delete q.hmac;
  delete q.signature; // vecchio parametro
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
  const state = crypto.randomBytes(16).toString("hex"); // per demo; in prod salva/verifica
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

// ===== Shopify helpers =====

// Storefront API (prodotto per handle) — usa shop specifico se passato, altrimenti default
async function storefrontGetProductByHandle(handle, shopDomain = SHOP_DOMAIN, sfToken = SF_TOKEN) {
  const url = `https://${shopDomain}/api/2024-07/graphql.json`;
  const q = `
    query($handle: String!) {
      product(handle: $handle) {
        title handle availableForSale
        variants(first:1){
          edges{ node{ id price{ amount currencyCode } availableForSale } }
        }
      }
    }`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Storefront-Access-Token": sfToken
    },
    body: JSON.stringify({ query: q, variables: { handle } })
  });
  const json = await r.json();
  return json.data?.product || null;
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
  const tools = [
    {
      type: "function",
      name: "getProductByHandle",
      description: "Dettagli prodotto dal negozio Shopify",
      parameters: {
        type: "object",
        properties: { handle: { type: "string" } },
        required: ["handle"]
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

  let resp = await client.responses.create({
    model: OPENAI_MODEL,
    input: messages,
    tools
  });

  // Gestione tool calls
  while (true) {
    const toolCalls = resp?.output?.filter(o => o.type === "tool_call") || [];
    if (!toolCalls.length) break;

    const toolResults = [];
    for (const call of toolCalls) {
      const { name, arguments: args } = call;
      if (name === "getProductByHandle") {
        const data = await storefrontGetProductByHandle(args.handle, shopDomain);
        toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
      }
      if (name === "getOrderStatus") {
        const data = await adminGetOrderStatus(args.email, args.orderNumber, shopDomain);
        toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
      }
    }

    resp = await client.responses.create({
      model: OPENAI_MODEL,
      input: [
        ...messages,
        ...toolResults.map(tr => ({ role: "tool", tool_call_id: tr.tool_call_id, content: tr.output }))
      ],
      tools
    });
  }

  return resp?.output_text || "Ok.";
}

// ---------------------
// Rotta App Proxy (widget)
// ---------------------
app.all("/chat-proxy", async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  try {
    // se arriva GET (es. aperto da browser) mostri solo un hint
    if (req.method === "GET") {
      return res.json({
        ok: true,
        hint: "Questa rotta accetta POST con JSON { message: '...' }"
      });
    }

    // verifica firma proxy (per ora permissiva)
    if (!verifyProxySignature(req.query)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    // prendi messaggio da body (POST) o query string (fallback)
    const userMsg = String(req.body.message || req.query.message || "");
    const messages = [
      { role: "system", content:
        "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. " +
        "NON inserire MAI link esterni. Se serve un link, usa solo URL interni del negozio (es. /products/handle, /policies). " +
        "Se non sei sicuro di una risposta, chiedi chiarimenti o invita a contattare l'assistenza."
      },
      { role: "user", content: userMsg }
    ];

    const answer = await chatWithTools(messages);

    // opzionale: sanitizza link
    function sanitizeLinks(text) {
      if (!text) return text;
      return text.replace(/https?:\/\/[^\s)]+/g, "[link rimosso]");
    }

    res.json({ answer: sanitizeLinks(answer) });
  } catch (e) {
    console.error("Errore chat-proxy:", e);
    res.status(500).json({ error: e.message });
  }
});

// (Opzionale) Streaming SSE — spesso l’App Proxy bufferizza; usalo diretto su Render se vuoi
app.get("/chat-proxy-stream", async (req, res) => {
  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  const user = req.query.q || "Ciao!";
  const shopFromProxy = String(req.query.shop || SHOP_DOMAIN).toLowerCase();
  const messages = [
    { role: "system", content: "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. Non usare mai link esterni." },
    { role: "user", content: String(user) }
  ];

  try {
    const stream = await client.responses.stream({
      model: OPENAI_MODEL,
      input: messages,
    });

    stream.on("message", (msg) => {
      // volendo si può anche sanificare progressivamente
      res.write(`data:${JSON.stringify(msg)}\n\n`);
    });

    stream.on("end", () => res.end());
    stream.on("error", (e) => {
      res.write(`event: error\ndata:${JSON.stringify({ error: e.message })}\n\n`);
      res.end();
    });
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
    <form action="/chat-proxy" method="POST" style="max-width:480px;margin:40px auto;font-family:sans-serif">
      <h3>Test AI Chat</h3>
      <p>Scrivi un messaggio e invia:</p>
      <textarea name="message" style="width:100%;height:120px"></textarea>
      <br><br>
      <button type="submit">Invia</button>
      <p style="margin-top:16px;color:#666">Nota: la rotta /chat-proxy è pensata per App Proxy (POST JSON). Questa form è solo per provare.</p>
    </form>
  `);
});

// Avvio
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AI Chat server ascolta su :${PORT}`));
