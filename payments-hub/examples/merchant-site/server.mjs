import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';

const PORT = Number.parseInt(process.env.MERCHANT_PORT || '4000', 10);
const PAYMENTS_HUB_URL = process.env.PAYMENTS_HUB_URL || 'http://localhost:8080';
const SITE_ID = process.env.SITE_ID || 'demo-store';
const SITE_SECRET =
  process.env.SITE_SECRET || 'replace_with_64_random_characters_for_merchant_to_gateway_hmac';
const FULFILLMENT_SECRET =
  process.env.FULFILLMENT_SECRET || 'replace_with_64_random_characters_for_gateway_to_merchant_hmac';
const ORIGIN = `http://localhost:${PORT}`;

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, ORIGIN);

    if (req.method === 'GET' && url.pathname === '/') {
      sendHtml(res, merchantPage());
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/create-checkout') {
      await handleCreateCheckout(res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/payments/webhook') {
      const rawBody = await readRawBody(req);
      verifyWebhookFromHub(req.headers, rawBody);
      const event = JSON.parse(rawBody);
      console.info(`Received ${event.type} for order ${event.data.payment.orderId}`);
      sendJson(res, 200, { ok: true });
      return;
    }

    sendJson(res, 404, { error: 'not_found' });
  } catch (error) {
    sendJson(res, 500, { error: error.message });
  }
});

server.listen(PORT, () => {
  console.info(`Demo merchant listening on ${ORIGIN}`);
});

async function handleCreateCheckout(res) {
  const orderId = `demo_${Date.now()}`;
  const checkoutRequest = {
    siteId: SITE_ID,
    orderId,
    mode: 'payment',
    currency: 'usd',
    items: [
      {
        name: 'Launch Pack',
        description: 'Reusable payment gateway starter purchase',
        unitAmount: 4900,
        quantity: 1,
      },
    ],
    customer: {
      email: 'customer@example.com',
    },
    successUrl: `${ORIGIN}/?status=success&payment_id={CHECKOUT_SESSION_ID}`,
    cancelUrl: `${ORIGIN}/?status=cancelled`,
    metadata: {
      demo: true,
    },
  };

  const body = JSON.stringify(checkoutRequest);
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = hmacHex(SITE_SECRET, `${timestamp}.${body}`);

  const response = await fetch(`${PAYMENTS_HUB_URL}/api/checkout/sessions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-site-id': SITE_ID,
      'x-timestamp': String(timestamp),
      'x-signature': `sha256=${signature}`,
      'idempotency-key': `demo:${orderId}`,
    },
    body,
  });

  const json = await response.json();
  if (!response.ok) {
    sendJson(res, response.status, json);
    return;
  }

  sendJson(res, 200, json);
}

function verifyWebhookFromHub(headers, rawBody) {
  const timestamp = headers['x-payments-timestamp'];
  const signature = String(headers['x-payments-signature'] || '').replace(/^sha256=/, '');

  if (!timestamp || !signature) {
    throw new Error('Missing payments hub signature headers.');
  }

  const expected = hmacHex(FULFILLMENT_SECRET, `${timestamp}.${rawBody}`);
  if (!constantTimeEqualHex(signature, expected)) {
    throw new Error('Invalid payments hub signature.');
  }
}

function hmacHex(secret, payload) {
  return createHmac('sha256', secret).update(payload).digest('hex');
}

function constantTimeEqualHex(left, right) {
  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sendHtml(res, html) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}

function merchantPage() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Demo Store</title>
    <style>
      :root {
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f4f6f9;
        color: #172033;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
      }
      main {
        width: min(640px, calc(100vw - 32px));
        background: #fff;
        border: 1px solid #dbe1ea;
        border-radius: 8px;
        padding: 28px;
        box-shadow: 0 16px 48px rgba(23, 32, 51, 0.08);
      }
      h1 {
        margin: 0 0 12px;
        font-size: 30px;
      }
      p {
        color: #4d5b73;
        line-height: 1.6;
      }
      button {
        appearance: none;
        border: 0;
        background: #174ea6;
        color: white;
        border-radius: 6px;
        padding: 12px 16px;
        font-size: 16px;
        font-weight: 700;
        cursor: pointer;
      }
      button:disabled {
        opacity: 0.65;
        cursor: progress;
      }
      pre {
        overflow: auto;
        background: #edf1f7;
        border-radius: 6px;
        padding: 12px;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Demo Store</h1>
      <p>This fake store asks your merchant backend to create a signed checkout session through the payments hub.</p>
      <button id="checkout">Pay $49.00</button>
      <pre id="output" aria-live="polite"></pre>
    </main>
    <script>
      const button = document.querySelector('#checkout');
      const output = document.querySelector('#output');
      button.addEventListener('click', async () => {
        button.disabled = true;
        output.textContent = 'Creating secure checkout...';
        const response = await fetch('/api/create-checkout', { method: 'POST' });
        const json = await response.json();
        if (!response.ok) {
          output.textContent = JSON.stringify(json, null, 2);
          button.disabled = false;
          return;
        }
        output.textContent = 'Redirecting to hosted Checkout...';
        window.location.href = json.checkoutUrl;
      });
    </script>
  </body>
</html>`;
}
