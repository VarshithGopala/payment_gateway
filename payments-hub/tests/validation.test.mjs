import test from 'node:test';
import assert from 'node:assert/strict';

import { validateCheckoutRequest, validateRefundRequest } from '../src/validation.mjs';

const site = {
  id: 'demo-store',
  allowedOrigins: ['http://localhost:4000', 'https://shop.example.com'],
};

const config = {
  isProduction: false,
};

test('validates a one-time checkout request', () => {
  const checkout = validateCheckoutRequest(
    {
      siteId: 'demo-store',
      orderId: 'ord_123',
      currency: 'USD',
      items: [{ name: 'Product', unitAmount: 2500, quantity: 2 }],
      successUrl: 'http://localhost:4000/success',
      cancelUrl: 'http://localhost:4000/cancel',
      customer: { email: 'customer@example.com' },
      metadata: { cart: '123' },
    },
    site,
    config
  );

  assert.equal(checkout.currency, 'usd');
  assert.equal(checkout.totalAmount, 5000);
  assert.equal(checkout.customer.email, 'customer@example.com');
});

test('rejects checkout return URLs outside the registered site origins', () => {
  assert.throws(
    () =>
      validateCheckoutRequest(
        {
          orderId: 'ord_123',
          currency: 'usd',
          items: [{ name: 'Product', unitAmount: 2500, quantity: 1 }],
          successUrl: 'https://attacker.example.com/success',
          cancelUrl: 'http://localhost:4000/cancel',
        },
        site,
        config
      ),
    /not allowed/i
  );
});

test('requires Stripe price IDs for subscriptions', () => {
  assert.throws(
    () =>
      validateCheckoutRequest(
        {
          orderId: 'sub_123',
          mode: 'subscription',
          currency: 'usd',
          items: [{ name: 'Plan', unitAmount: 999, quantity: 1 }],
          successUrl: 'http://localhost:4000/success',
          cancelUrl: 'http://localhost:4000/cancel',
        },
        site,
        config
      ),
    /priceId/i
  );
});

test('validates refund requests', () => {
  const refund = validateRefundRequest({
    paymentId: 'pay_123',
    amount: 1000,
    reason: 'requested_by_customer',
  });

  assert.equal(refund.paymentId, 'pay_123');
  assert.equal(refund.amount, 1000);
});
