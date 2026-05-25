# Secure Payments Hub

A reusable payment gateway service for all your future websites. Each website talks to this hub
from its own backend using signed requests. The hub can route INR payments to Razorpay and
non-INR payments to Stripe, verifies provider webhooks, records payment state, supports refunds,
and sends signed payment events back to the website that owns the order.

## Why this shape

Payment security gets much easier when your websites do not collect cards or trust browser-supplied
prices. This project uses hosted/provider checkout surfaces so sensitive payment details stay with
Stripe or Razorpay, and it requires merchant backends to sign the exact order payload before the hub
will create a checkout session.

## Project layout

```text
payments-hub/
  src/                     gateway server
  public/                  tiny status/return pages
  examples/merchant-site/  sample website backend integration
  .env.cloud-preview.example one-URL storefront preview config
  tests/                   built-in Node test suite
  .env.example             configuration template
```

## Quick start: simple website preview

```bash
cd payments-hub
cp .env.cloud-preview.example .env
npm start
```

Open:

```text
http://localhost:8080/store
```

This starts the integrated storefront with `PAYMENT_PROVIDER=mock`, so you can click through a
hosted-checkout-like flow without charging a real card.

## Quick start: real payment mode

```bash
cd payments-hub
cp .env.example .env
```

Fill `.env` with your Razorpay test keys, Stripe test key, and webhook secrets. `PAYMENT_PROVIDER=auto`
routes INR to Razorpay and other currencies to Stripe. Then run:

```bash
npm start
npm run demo:merchant
```

Open `http://localhost:8080/store` for the integrated store, or `http://localhost:4000` for the
separate sample merchant site.

If your machine does not have npm but does have Node, these also work:

```bash
node src/server.mjs
node examples/merchant-site/server.mjs
node --test tests/*.test.mjs
```

## Cloud preview

Use [CLOUD.md](./CLOUD.md) and the root [`render.yaml`](../render.yaml) to deploy the same storefront
as one hosted Render web service. The Blueprint starts in mock mode so you can check `/store` in the
cloud first. Switch `PAYMENT_PROVIDER` to `auto` and add Razorpay plus Stripe secrets when you are
ready to test real payments.

## Stripe setup

1. Create a Stripe account and use test mode first.
2. Put your `sk_test_*` value in `STRIPE_SECRET_KEY`.
3. In local development, use the Stripe CLI to forward events to:

```bash
stripe listen --forward-to localhost:8080/webhooks/stripe
```

4. Copy the printed `whsec_*` value into `STRIPE_WEBHOOK_SECRET`.
5. In production, add a webhook endpoint in Stripe Dashboard pointing to:

```text
https://your-payments-domain.com/webhooks/stripe
```

## Razorpay setup

1. Create a Razorpay account and complete the required KYC.
2. Put your test `rzp_test_*` key ID in `RAZORPAY_KEY_ID`.
3. Put the matching key secret in `RAZORPAY_KEY_SECRET`.
4. Add a Razorpay webhook endpoint pointing to:

```text
https://your-payments-domain.com/webhooks/razorpay
```

5. Set the Razorpay webhook secret in `RAZORPAY_WEBHOOK_SECRET`.
6. Enable international payments in Razorpay Dashboard if you want to accept foreign cards through Razorpay.

Razorpay is used by default for INR payments when `PAYMENT_PROVIDER=auto`.

## Add a new website

Add the site ID to `SITES`, then define its config:

```env
SITES=demo-store,new-shop

SITE_NEW_SHOP_NAME=New Shop
SITE_NEW_SHOP_SECRET=64_random_chars_shared_only_with_new_shop_backend
SITE_NEW_SHOP_ORIGINS=https://new-shop.example.com
SITE_NEW_SHOP_FULFILLMENT_URL=https://new-shop.example.com/api/payments/webhook
SITE_NEW_SHOP_FULFILLMENT_SECRET=64_random_chars_for_gateway_callbacks
```

Only the website backend should know `SITE_NEW_SHOP_SECRET`. Browser code should call your website
backend, and that backend should call the payments hub.

## Merchant backend integration

Sign the exact JSON body with:

```js
import { createHmac } from 'node:crypto';

const body = JSON.stringify({
  siteId: 'new-shop',
  orderId: 'order_123',
  mode: 'payment',
  currency: 'usd',
  items: [{ name: 'Starter Pack', unitAmount: 4900, quantity: 1 }],
  successUrl: 'https://new-shop.example.com/success',
  cancelUrl: 'https://new-shop.example.com/cart'
});

const timestamp = Math.floor(Date.now() / 1000);
const signature = createHmac('sha256', process.env.PAYMENTS_SITE_SECRET)
  .update(`${timestamp}.${body}`)
  .digest('hex');

const response = await fetch('https://payments.example.com/api/checkout/sessions', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'x-site-id': 'new-shop',
    'x-timestamp': String(timestamp),
    'x-signature': `sha256=${signature}`,
    'idempotency-key': 'order_123'
  },
  body
});

const checkout = await response.json();
```

Redirect the browser to `checkout.checkoutUrl`.

## Checkout request fields

```json
{
  "siteId": "new-shop",
  "orderId": "order_123",
  "mode": "payment",
  "currency": "usd",
  "items": [
    {
      "name": "Starter Pack",
      "unitAmount": 4900,
      "quantity": 1
    }
  ],
  "customer": {
    "email": "customer@example.com"
  },
  "successUrl": "https://new-shop.example.com/success",
  "cancelUrl": "https://new-shop.example.com/cart",
  "metadata": {
    "cartId": "cart_123"
  }
}
```

For subscriptions, create Prices in Stripe and send `mode: "subscription"` with line items like:

```json
{
  "priceId": "price_123",
  "quantity": 1
}
```

## Fulfillment webhook on each website

Your website receives signed events from the hub:

```http
POST /api/payments/webhook
x-payments-timestamp: 1710000000
x-payments-signature: sha256=...
content-type: application/json
```

Verify the signature with the `SITE_*_FULFILLMENT_SECRET`, then fulfill only `payment.succeeded`
events. Do not fulfill based on the browser returning to the success page.

## Refunds

Call `POST /api/refunds` with the same merchant signing headers:

```json
{
  "paymentId": "pay_...",
  "amount": 1000,
  "reason": "requested_by_customer"
}
```

Omit `amount` for a full refund.

## Notes

- The starter uses a JSON file store in `data/` so it runs without dependencies. Swap `JsonStore`
  for Postgres, MySQL, or another durable database before high-volume production use.
- Use test keys until your webhook and fulfillment flow is fully verified.
- Keep all provider and site secrets out of frontend code.
