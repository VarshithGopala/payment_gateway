import test from 'node:test';
import assert from 'node:assert/strict';

import { getConfig } from '../src/config.mjs';

test('supports mock provider and PUBLIC_BASE_URL site URL templates', () => {
  const config = getConfig({
    NODE_ENV: 'production',
    PORT: '10000',
    PUBLIC_BASE_URL: 'https://example-payments.test',
    PAYMENT_PROVIDER: 'mock',
    SITES: 'demo-store',
    SITE_DEMO_STORE_SECRET: 'a'.repeat(64),
    SITE_DEMO_STORE_ORIGINS: '{PUBLIC_BASE_URL}',
    SITE_DEMO_STORE_FULFILLMENT_URL: '{PUBLIC_BASE_URL}/store/api/payments/webhook',
    SITE_DEMO_STORE_FULFILLMENT_SECRET: 'b'.repeat(64),
  });

  const site = config.sites.get('demo-store');
  assert.equal(config.provider, 'mock');
  assert.equal(site.allowedOrigins[0], 'https://example-payments.test');
  assert.equal(site.fulfillmentUrl, 'https://example-payments.test/store/api/payments/webhook');
});

test('defaults to auto provider for India-first production routing', () => {
  const config = getConfig({
    NODE_ENV: 'production',
    PORT: '10000',
    PUBLIC_BASE_URL: 'https://example-payments.test',
    SITES: 'demo-store',
    SITE_DEMO_STORE_SECRET: 'a'.repeat(64),
    SITE_DEMO_STORE_ORIGINS: '{PUBLIC_BASE_URL}',
    SITE_DEMO_STORE_FULFILLMENT_SECRET: 'b'.repeat(64),
  });

  assert.equal(config.provider, 'auto');
});
