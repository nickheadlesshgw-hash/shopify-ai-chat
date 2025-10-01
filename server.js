// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";
import { OpenAI } from "openai";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true })); // serve per la form di test

// Variabili d’ambiente (le imposterai su Render)
const SHOP_DOMAIN = process.env.SHOP_DOMAIN; // es: myshop.myshopify.com
const SF_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN;
const ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SHOPIFY_APP_SECRET = process.env.SHOPIFY_APP_SECRET;

const client = new OpenAI({ apiKey: OPENAI_API_KEY });

// ---------------------
// (FACOLTATIVO) Verifica firma App Proxy
// Per prototipo la lasciamo permissiva (true). In produzione abilita il check.
// ---------------------
function verifyProxySignature(/* query */) {
  return true;
}

// ---------------------
// Helpers Shopify
// ---------------------

// Storefront API (prodotto per handle)
async function storefrontGetProductByHandle(handle) {
  const url = `https://${SHOP_DOMAIN}/api/2024-07/graphql.json`;
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
      "Content-Type":"application/json",
      "X-Shopify-Storefront-Access-Token": SF_TOKEN
    },
    body: JSON.stringify({ query: q, variables: { handle } })
  });
  const json = await r.json();
  return json.data?.product || null;
}

// Admin API (stato ordine)
async function adminGetOrderStatus(email, orderNumber) {
  const url = `https://${SHOP_DOMAIN}/admin/api/2024-07/graphql.json`;
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
      "Content-Type":"application/json",
      "X-Shopify-Access-Token": ADMIN_TOKEN
    },
    body: JSON.stringify({ query: q, variables: { q: queryString } })
  });
  const json = await r.json();
  return json.data?.orders?.edges?.[0]?.node || null;
}

// ---------------------
// Chat con tools (OpenAI)
// ---------------------
async function chatWithTools(messages) {
  const tools = [
    {
      type: "function",
      name: "getProductByHandle",
      description: "Ottieni info prodotto dal negozio",
      parameters: {
        type: "object",
        properties: { handle: { type: "string" } },
        required: ["handle"]
      }
    },
    {
      type: "function",
      name: "getOrderStatus",
      description: "Controlla stato ordine per email+numero",
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
    model: "gpt-4.1-mini",
    input: messages,
    tools
  });

  // Loop per gestire eventuali chiamate a tool
  while (true) {
    const toolCalls = resp?.output?.filter(o => o.type === "tool_call") || [];
    if (!toolCalls.length) break;

    const toolResults = [];
    for (const call of toolCalls) {
      const { name, arguments: args } = call;
      if (name === "getProductByHandle") {
        const data = await storefrontGetProductByHandle(args.handle);
        toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
      }
      if (name === "getOrderStatus") {
        const data = await adminGetOrderStatus(args.email, args.orderNumber);
        toolResults.push({ tool_call_id: call.id, output: JSON.stringify(data) });
      }
    }

    resp = await client.responses.create({
      model: "gpt-4.1-mini",
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
// Rotte
// ---------------------

// Rotta POST per App Proxy (widget)
app.post("/chat-proxy", async (req, res) => {
  try {
    if (!verifyProxySignature(req.query)) {
      return res.status(401).json({ error: "Invalid signature" });
    }
    const userMsg = String(req.body.message || "");
    const messages = [
      { role: "system", content:
        "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. " +
        "NON inserire MAI link esterni. Se serve un link, usa solo URL interni del negozio (es. /products/handle, /policies). " +
        "Se non sei sicuro di una risposta, chiedi chiarimenti o invita a contattare l'assistenza." },
      { role: "user", content: userMsg }
    ];
    const answer = await chatWithTools(messages);

    // Sanitizza eventuali link esterni
    function sanitizeLinks(text, shopDomain) {
      if (!text) return text;
      const allowed
