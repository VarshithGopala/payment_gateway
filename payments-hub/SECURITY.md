# Security Model

This gateway is designed so your websites never handle raw card data and never expose provider
secrets to browsers.

## Rules this project enforces

- Card and payment collection happens in Stripe Checkout or Razorpay Checkout, not on your server.
- Every merchant website has a per-site HMAC secret.
- Checkout and refund requests must be sent from the merchant backend, not directly from frontend code.
- The gateway rejects signed requests outside the timestamp tolerance window.
- Success and cancel URLs must belong to the registered site origin.
- Stripe and Razorpay webhooks are verified against the raw request body before any order state changes.
- Stripe webhook event IDs are stored so duplicate deliveries do not fulfill an order twice.
- Fulfillment callbacks sent back to merchant sites are signed with a separate per-site secret.

## Production checklist

1. Use HTTPS for the gateway and every merchant website.
2. Put real secrets in a secret manager, not in source control.
3. Generate at least 32 random bytes for each `SITE_*_SECRET` and `SITE_*_FULFILLMENT_SECRET`.
4. Use `PAYMENT_PROVIDER=auto` for India-first production routing. `PAYMENT_PROVIDER=mock` is only for previews.
5. Configure Razorpay to send webhooks to `https://your-gateway.example.com/webhooks/razorpay`.
6. Configure Stripe to send webhooks to `https://your-gateway.example.com/webhooks/stripe`.
7. Listen for Razorpay events such as `payment.captured`, `order.paid`, `payment.failed`, and refund events.
8. Listen for Stripe events such as `checkout.session.completed`, `checkout.session.async_payment_succeeded`,
   `checkout.session.async_payment_failed`, and `checkout.session.expired`.
9. Fulfill orders only from signed gateway-to-merchant webhook events.
10. Use a real database before high-volume production traffic. The bundled JSON store is meant to
   make the starter run anywhere.
11. Rotate site secrets and provider webhook secrets periodically.
12. Keep server clocks synchronized so replay protection works correctly.
13. Add provider-side fraud tools, taxes, dispute handling, and accounting workflows for your region.
