// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";
import { OpenAI } from "openai";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));

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

// Chat con tools (OpenAI)
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
// Rotta POST per App Proxy (widget)
// Impone: ITA + niente link esterni
// ---------------------
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
    res.json({ answer });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// (Opzionale) GET streaming SSE - spesso l'App Proxy bufferizza: usalo solo se ti serve
app.get("/chat-proxy-stream", async (req, res) => {
  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  const user = req.query.q || "Ciao!";
  const messages = [
    { role: "system", content:
      "Sei l'assistente AI del negozio. Rispondi SOLO in italiano. Non usare mai link esterni." },
    { role: "user", content: String(user) }
  ];

  try {
    const stream = await client.responses.stream({
      model: "gpt-4.1-mini",
      input: messages,
    });

    stream.on("message", (msg) => {
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

const PORT = process.env.PORT || 3000;
app.get("/", (req, res) => res.send("AI Chat up ✅"));
app.listen(PORT, () => console.log(`AI Chat server ascolta su :${PORT}`));
