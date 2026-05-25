# Cloud Preview

This project now includes a one-URL storefront at `/store`.

For a quick hosted preview, deploy the root `render.yaml` Blueprint to Render. It creates a Node
web service using `payments-hub` as the service root and starts in `PAYMENT_PROVIDER=mock` mode.
That lets you click through checkout without real card charges.

## Render steps

1. Push this folder to a GitHub or GitLab repository.
2. In Render, create a new Blueprint from the repository.
3. Keep the generated secrets as-is.
4. After the service is live, open:

```text
https://secure-payments-hub-preview.onrender.com/store
```

If Render assigns a different public URL, update these environment variables to that exact URL:

```text
PUBLIC_BASE_URL=https://your-render-url.onrender.com
SITE_DEMO_STORE_ORIGINS={PUBLIC_BASE_URL}
SITE_DEMO_STORE_FULFILLMENT_URL={PUBLIC_BASE_URL}/store/api/payments/webhook
```

## Switch the cloud app to real Stripe

After you confirm the preview flow:

```text
PAYMENT_PROVIDER=auto
RAZORPAY_KEY_ID=rzp_test_...
RAZORPAY_KEY_SECRET=...
RAZORPAY_WEBHOOK_SECRET=...
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

Then add this webhook endpoint in Stripe:

```text
https://your-render-url.onrender.com/webhooks/stripe
```

And add this webhook endpoint in Razorpay:

```text
https://your-render-url.onrender.com/webhooks/razorpay
```

Listen for:

```text
checkout.session.completed
checkout.session.async_payment_succeeded
checkout.session.async_payment_failed
checkout.session.expired
```

The store will still create payments through the hub backend. The browser only receives the hosted
checkout URL. In `auto` mode, INR payments use Razorpay and non-INR payments use Stripe.

## Local preview

```bash
cd payments-hub
cp .env.cloud-preview.example .env
npm start
```

Open:

```text
http://localhost:8080/store
```
