import test from 'node:test';
import assert from 'node:assert/strict';

import {
  constantTimeEqualHex,
  hmacHex,
  signPayload,
  verifySignedSiteRequest,
  verifyRazorpayPaymentSignature,
  verifyRazorpayWebhookSignature,
  verifyStripeSignature,
} from '../src/security.mjs';

test('signed site requests verify with timestamped HMAC', () => {
  const rawBody = JSON.stringify({ orderId: 'ord_123' });
  const timestamp = Math.floor(Date.now() / 1000);
  const secret = 'a'.repeat(64);
  const site = { id: 'demo-store', secret };
  const signature = signPayload(secret, timestamp, rawBody);

  const verifiedSite = verifySignedSiteRequest({
    headers: {
      'x-site-id': 'demo-store',
      'x-timestamp': String(timestamp),
      'x-signature': `sha256=${signature}`,
    },
    rawBody,
    sites: new Map([[site.id, site]]),
    toleranceSeconds: 300,
  });

  assert.equal(verifiedSite.id, site.id);
});

test('signed site requests reject tampered payloads', () => {
  const rawBody = JSON.stringify({ orderId: 'ord_123' });
  const timestamp = Math.floor(Date.now() / 1000);
  const secret = 'a'.repeat(64);
  const signature = signPayload(secret, timestamp, rawBody);

  assert.throws(
    () =>
      verifySignedSiteRequest({
        headers: {
          'x-site-id': 'demo-store',
          'x-timestamp': String(timestamp),
          'x-signature': `sha256=${signature}`,
        },
        rawBody: JSON.stringify({ orderId: 'ord_456' }),
        sites: new Map([['demo-store', { id: 'demo-store', secret }]]),
        toleranceSeconds: 300,
      }),
    /invalid/i
  );
});

test('Stripe webhook signatures use timestamp dot raw-body HMAC', () => {
  const secret = 'whsec_test_secret';
  const rawBody = JSON.stringify({ id: 'evt_123', type: 'checkout.session.completed' });
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = hmacHex(secret, `${timestamp}.${rawBody}`);

  assert.doesNotThrow(() =>
    verifyStripeSignature(rawBody, `t=${timestamp},v1=${signature}`, secret, 300)
  );
});

test('constantTimeEqualHex requires equal hex strings', () => {
  assert.equal(constantTimeEqualHex('abcd', 'abcd'), true);
  assert.equal(constantTimeEqualHex('abcd', 'abce'), false);
  assert.equal(constantTimeEqualHex('abcd', 'abc'), false);
});

test('Razorpay payment signature verifies order and payment IDs', () => {
  const keySecret = 'razorpay_secret';
  const orderId = 'order_123';
  const paymentId = 'pay_123';
  const signature = hmacHex(keySecret, `${orderId}|${paymentId}`);

  assert.doesNotThrow(() =>
    verifyRazorpayPaymentSignature({
      orderId,
      paymentId,
      signature,
      keySecret,
    })
  );
});

test('Razorpay webhook signature verifies raw body HMAC', () => {
  const webhookSecret = 'webhook_secret';
  const rawBody = JSON.stringify({ event: 'payment.captured' });
  const signature = hmacHex(webhookSecret, rawBody);

  assert.doesNotThrow(() => verifyRazorpayWebhookSignature(rawBody, signature, webhookSecret));
});
