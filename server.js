// server.js — AI Chat per Shopify (OAuth, App Proxy, Context-aware, Ricerca, Budget)
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";
import { OpenAI } from "openai";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

/* ========= ENV ========= */
const APP_BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, ""); // es: https://shopify-ai-chat.onrender.com
const SHOP_DOMAIN = (process.env.SHOP_DOMAIN || "").toLowerCase();       // es: wm126i-0y.myshopify.com

const PUBLIC_STORE_URL = (process.env.PUBLIC_STORE_URL || "https://buzzhivestore.com")
  .replace(/\/$/, "");

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL   = process.env.OPENAI_MODEL || "gpt-4o-mini";

const SHOPIFY_CLIENT_ID     = process.env.SHOPIFY_CLIENT_ID || "";
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || "";
const SHOPIFY_SCOPES =
  process.env.SHOPIFY_SCOPES || "read_products,read_app_proxy,write_app_proxy";

// opzionale per sviluppo (sconsigliato in produzione)
const ADMIN_TOKEN_FALLBACK = process.env.SHOPIFY_ADMIN_TOKEN || "";

/* ========= OpenAI ========= */
if (!OPENAI_API_KEY) console.warn("[WARN] OPENAI_API_KEY mancante");
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

/* ========= Token storage (RAM prototipo) ========= */
const TOKENS = new Map(); // Map<shop, access_token>

/* ========= Utility ========= */
function isValidShop(shop) {
  return typeof shop === "string" && /\.myshopify\.com$/i.test(shop);
}
function productUrl(handle) {
  return `${PUBLIC_STORE_URL}/products/${handle}`;
}
function sanitizeLinks(text) {
  if (!text) return text;
  const allowedHost = PUBLIC_STORE_URL.replace(/^https?:\/\//, "");
  return String(text)
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi, (m, label, url) =>
      url.includes(allowedHost) ? m : `${label} ([link rimosso])`)
    .replace(/https?:\/\/[^\s)]+/gi, m => (m.includes(allowedHost) ? m : "[link rimosso]"));
}

function verifyProxySignature(/*query*/) { return true; } // abilita HMAC in prod

/* ========= OAuth ========= */
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
  const message = Object.keys(q)
    .sort()
    .map(k => `${k}=${Array.isArray(q[k]) ? q[k].join(",") : q[k]}`)
    .join("&");
  const digest  = crypto.createHmac("sha256", secret).update(message).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(hmac, "utf8")); }
  catch { return false; }
}

app.get("/auth/start", (req, res) => {
  const shop = String(req.query.shop || "").toLowerCase();
  if (!isValidShop(shop)) return res.status(400).send("Parametro 'shop' non valido");
  const state = crypto.randomBytes(16).toString("hex"); // (in prod salva e verifica)
  res.redirect(buildInstallUrl({ shop, state }));
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code } = req.query;
    if (!isValidShop(shop)) return res.status(400).send("Shop non valido");
    if (!verifyHmacQuery(req.query, SHOPIFY_CLIENT_SECRET)) return res.status(400).send("HMAC non valido");

    const r = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code
      })
    });
    const json = await r.json();
    if (!json.access_token) throw new Error("Nessun access_token");
    TOKENS.set(String(shop).toLowerCase(), json.access_token);
    console.log(`[OAuth] Install OK for ${shop} — token: ${json.access_token.slice(0,6)}...`);
    res.send("Installazione completata ✅ Puoi chiudere questa pagina.");
  } catch (e) {
    console.error("[OAuth] Error:", e);
    res.status(500).send("OAuth error: " + e.message);
  }
});

/* ========= Admin helpers ========= */
function getAdminToken(domain) {
  return TOKENS.get(domain) || ADMIN_TOKEN_FALLBACK;
}
async function adminGraphQL({ shopDomain, query, variables }) {
  const domain = String(shopDomain || SHOP_DOMAIN).toLowerCase();
  const token  = getAdminToken(domain);
  if (!token) throw new Error("Admin token mancante: esegui OAuth /auth/start?shop=SHOP");
  const url = `https://${domain}/admin/api/2024-07/graphql.json`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type":"application/json", "X-Shopify-Access-Token": token },
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
    currency: node.priceRangeV2?.minVariantPrice?.currencyCode || "EUR",
    description: (node.bodyHtml || "").replace(/<[^>]+>/g, "")
  };
}

// — Lista prodotti attivi (REST) con prezzo minimo —
async function adminListActiveProducts(shopDomain = SHOP_DOMAIN) {
  const domain = String(shopDomain || SHOP_DOMAIN).toLowerCase();
  const token  = getAdminToken(domain);
  if (!token) throw new Error("Admin token mancante: esegui OAuth /auth/start?shop=SHOP");

  const url = `https://${domain}/admin/api/2024-07/products.json?status=active&limit=250`;
  const r = await fetch(url, { headers: { "X-Shopify-Access-Token": token } });
  const json = await r.json();
  const items = Array.isArray(json.products) ? json.products : [];

  return items.map(p => {
    const minVariant = (p.variants || []).reduce((min, v) => {
      const pr = parseFloat(v.price);
      if (isNaN(pr)) return min;
      return (min === null || pr < min) ? pr : min;
    }, null);

    return {
      title: p.title,
      handle: p.handle,
      price: typeof minVariant === "number" ? minVariant : null,
      currency: "EUR",
      description: (p.body_html || "").replace(/<[^>]+>/g, "").slice(0, 220),
      tags: p.tags || ""
    };
  }).filter(p => typeof p.price === "number");
}

// — Prodotto più economico —
async function adminGetCheapestProduct(shopDomain = SHOP_DOMAIN) {
  const list = await adminListActiveProducts(shopDomain);
  if (!list.length) return null;
  return list.reduce((min, p) => (p.price < min.price ? p : min), list[0]);
}

/* ========= Ricerca & Raccomandazioni ========= */
const STOPWORDS = new Set([
  "ciao","salve","buongiorno","buonasera","hey","hi","hola",
  "ok","okay","grazie","thanks","thank","per","favore","please",
  "aiuto","help","info","informazioni","il","la","lo","un","una","di","del","dei","delle","per","da","su","con","e","ed","o"
]);
function isSmallTalk(t) {
  return /\b(ciao|salve|buongiorno|buonasera|hey|hi|hola|ok|grazie|thanks)\b/i.test(t);
}
function normalizeWords(t) {
  return String(t || "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, " ")
    .split(/\s+/)
    .filter(Boolean);
}
function extractSearchableTerms(t) {
  return normalizeWords(t).filter(w => !STOPWORDS.has(w) && w.length >= 3);
}
function buildQueryText(t) {
  const cleaned = String(t || "").replace(/(?:avete|vendete|offrite|cerca|cercami|trova|mostra|cerco)\b/gi, "");
  const terms = extractSearchableTerms(cleaned);
  return terms.join(" ").trim();
}
function keywordScore(text, keywords) {
  const t = (text || "").toLowerCase();
  const arr = Array.isArray(keywords) ? keywords : String(keywords || "").split(/\s+/);
  let score = 0;
  for (const k of arr) {
    if (!k) continue;
    const m = t.split(String(k).toLowerCase()).length - 1;
    score += m > 0 ? m : 0;
  }
  return score;
}
async function findByKeywords({ shopDomain, queryText, limit = 5, sort = "RELEVANCE" }) {
  const kw = String(queryText || "").trim();
  if (!kw) return [];
  const items = await adminListActiveProducts(shopDomain);
  let list = items.map(p => ({
    ...p,
    _score: keywordScore(`${p.title} ${p.description} ${p.tags}`, kw.split(/\s+/))
  }));
  if (sort === "RELEVANCE")  list = list.sort((a,b) => b._score - a._score);
  if (sort === "PRICE_ASC")  list = list.sort((a,b) => a.price - b.price);
  if (sort === "PRICE_DESC") list = list.sort((a,b) => b.price - a.price);
  return list.slice(0, limit);
}
async function recommendByBudgetAndInterests({ shopDomain, budget, interestsText, limit = 5 }) {
  const interests = normalizeWords(interestsText).filter(w => !STOPWORDS.has(w));
  const all = await adminListActiveProducts(shopDomain);
  const filtered = all
    .filter(p => p.price <= budget)
    .map(p => ({ ...p, _score: keywordScore(`${p.title} ${p.description} ${p.tags}`, interests) }))
    .sort((a,b) => (b._score !== a._score) ? (b._score - a._score) : (a.price - b.price))
    .slice(0, limit);
  return filtered;
}

/* ========= Chat (intent + tools) ========= */
async function chatWithTools(messages, { shopDomain, context = {} } = {}) {
  const userText = (messages.find(m => m.role === "user")?.content || "");

  // 0) quick Q&A sul prodotto in pagina
  if (context?.pageType === "product" && context?.product?.handle) {
    const h = context.product.handle;
    const quick = /(prezzo|quanto costa|descrizione|informazioni|info|cos'?è|dimensioni|ingredienti|taglie|materiale)/i;
    if (quick.test(userText)) {
      const p = await adminGetProductByHandle(h, shopDomain);
      if (p) {
        return `**${p.title}** — ${p.price} ${p.currency}\n${p.description}\nLink: ${productUrl(p.handle)}`;
      }
    }
  }

  // 1) small talk → niente ricerca
  if (isSmallTalk(userText)) {
    return "Ciao! Posso aiutarti a trovare prodotti e idee regalo.\n" +
           "Esempi: \"albero di Natale\", \"tazze regalo\", \"regalo per lui 50€\".";
  }

  // 2) prodotto più economico
  const cheapIntent = /(prodotto|articolo).*(pi[uù] economico|meno costoso|che costa meno)|pi[uù] economico/i;
  if (cheapIntent.test(userText)) {
    const p = await adminGetCheapestProduct(shopDomain);
    if (p) return `Il prodotto più economico è **${p.title}** a ${p.price} EUR. Link: ${productUrl(p.handle)}`;
  }

  // 3) idea regalo + budget/interessi
  const giftIntent = /(regalo|idea|consiglio).*(fidanzat[oa]?|amico|amica|papà|mamma|collega|lei|lui|bambin[oa])/i;
  const money = userText.match(/(\d+[,.]?\d*)\s?€|\beuro\b\s?(\d+[,.]?\d*)/i);
  if (giftIntent.test(userText) && money) {
    const num = Number((money[1] || money[2]).replace(",", "."));
    const recs = await recommendByBudgetAndInterests({
      shopDomain, budget: num, interestsText: userText, limit: 5
    });
    if (recs.length) {
      return (
        `Ecco alcune idee entro **${num} €**:\n\n` +
        recs.map(p => `• **${p.title}** — ${p.price} EUR\n  ${productUrl(p.handle)}`).join("\n")
      );
    }
    return `Non ho trovato articoli entro ${num} €. Vuoi aumentare il budget o darmi altri interessi?`;
  }

  // 4) ricerca prodotti (solo se ci sono termini cercabili)
  const searchIntent = /(cerc|avete|vendete|offrite|trova|mostra|cerco)/i;
  const queryText = buildQueryText(userText);
  const hasTerms  = extractSearchableTerms(queryText).length > 0;

  if ((searchIntent.test(userText) || hasTerms) && hasTerms) {
    const list = await findByKeywords({ shopDomain, queryText, limit: 5, sort: "RELEVANCE" });
    if (list.length) {
      return (
        `Ho trovato questi risultati per **${queryText}**:\n\n` +
        list.map(p => `• **${p.title}** — ${p.price} EUR\n  ${productUrl(p.handle)}`).join("\n")
      );
    }
    return `Non ho trovato prodotti per **${queryText}**. Vuoi darmi un dettaglio in più?`;
  }

  // 5) fallback: LLM + tools per casi complessi
  const tools = [
    {
      type: "function",
      name: "getProductByHandle",
      description: "Dettagli prodotto per handle",
      parameters: { type:"object", properties:{ handle:{ type:"string" } }, required:["handle"] }
    },
    {
      type: "function",
      name: "searchProducts",
      description: "Cerca prodotti per parole chiave",
      parameters: { type:"object", properties:{ query:{ type:"string" }, limit:{ type:"number", default:5 } }, required:["query"] }
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
    const calls = resp?.output?.filter(o => o.type === "tool_call") || [];
    if (!calls.length) break;

    const outs = [];
    for (const call of calls) {
      const { name, arguments: args } = call;
      try {
        if (name === "getProductByHandle") {
          const data = await adminGetProductByHandle(args.handle, shopDomain);
          outs.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }
        if (name === "searchProducts") {
          const data = await findByKeywords({ shopDomain, queryText: args.query, limit: args.limit || 5 });
          outs.push({ tool_call_id: call.id, output: JSON.stringify(data) });
        }
      } catch (e) {
        outs.push({ tool_call_id: call.id, output: JSON.stringify({ error: e.message }) });
      }
    }

    try {
      resp = await openai.responses.create({
        model: OPENAI_MODEL,
        input: [
          ...messages,
          ...outs.map(o => ({ role: "tool", tool_call_id: o.tool_call_id, content: o.output }))
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

/* ========= App Proxy ========= */
app.all("/chat-proxy", async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  try {
    if (!verifyProxySignature(req.query)) return res.status(401).json({ error:"Invalid signature" });

    const isGet  = req.method === "GET";
    const rawMsg = isGet ? (req.query.message ?? "") : (req.body.message ?? "");
    const ctx    = isGet ? {} : (req.body.context || {});
    if (isGet && !rawMsg) return res.json({ ok:true, hint:"Questa rotta accetta POST { message, context }" });

    const userMsg = String(rawMsg || "");
    const shopFromProxy = String(req.query.shop || SHOP_DOMAIN).toLowerCase();

    console.log(">>> /chat-proxy:", req.method, "shop:", shopFromProxy, "msg:", userMsg);

    const messages = [
      { role:"system", content:
        "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. " +
        "NON inserire MAI link esterni. Quando devi linkare un prodotto usa SEMPRE URL assoluti del negozio. " +
        `Il dominio pubblico è: ${PUBLIC_STORE_URL}. Genera quindi link del tipo ${PUBLIC_STORE_URL}/products/<handle>. ` +
        "Quando suggerisci prodotti, includi titolo, breve descrizione e prezzo." },
      { role:"user", content: userMsg }
    ];

    const answer = await chatWithTools(messages, { shopDomain: shopFromProxy, context: ctx })
      .catch(e => { console.error("chatWithTools error:", e); return "⚠️ Errore AI: " + e.message; });

    res.json({ answer: sanitizeLinks(answer) });
  } catch (e) {
    console.error("Errore /chat-proxy:", e);
    res.status(500).json({ error: e.message });
  }
});

/* ========= Debug ========= */
app.get("/debug/cheapest", async (req, res) => {
  try {
    const shop = String(req.query.shop || SHOP_DOMAIN).toLowerCase();
    const p = await adminGetCheapestProduct(shop);
    if (!p) return res.status(404).json({ ok:false, msg:"Nessun prodotto attivo con prezzo trovato." });
    res.json({ ok:true, title: p.title, handle: p.handle, price:`${p.price} EUR`, url: productUrl(p.handle), description: p.description });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});
app.get("/debug/search", async (req, res) => {
  try {
    const shop  = String(req.query.shop || SHOP_DOMAIN).toLowerCase();
    const q     = String(req.query.q || "");
    const list  = await findByKeywords({ shopDomain: shop, queryText: q, limit: 5, sort: "RELEVANCE" });
    res.json({ ok:true, count:list.length, items: list.map(p => ({ title:p.title, handle:p.handle, price:`${p.price} EUR`, url: productUrl(p.handle) })) });
  } catch (e) {
    res.status(500).json({ ok:false, error:e.message });
  }
});

/* ========= Misc ========= */
app.get("/", (req, res) => res.send("AI Chat up ✅"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AI Chat server ascolta su :${PORT}`));
