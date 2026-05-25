import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

import { getConfig, loadDotEnv } from './config.mjs';
import { conflict, forbidden, HttpError, notFound, tooManyRequests, unauthorized } from './errors.mjs';
import {
  canonicalJson,
  constantTimeEqualHex,
  generateId,
  redact,
  sha256Hex,
  signPayload,
  signedWebhookHeaders,
  verifyRazorpayPaymentSignature,
  verifyRazorpayWebhookSignature,
  verifySignedSiteRequest,
  verifyStripeSignature,
} from './security.mjs';
import { JsonStore } from './store.mjs';
import { createRazorpayOrder, createRazorpayRefund } from './razorpay.mjs';
import { createCheckoutSession, createRefund } from './stripe.mjs';
import { validateCheckoutRequest, validateRefundRequest } from './validation.mjs';

const PUBLIC_DIR = join(process.cwd(), 'public');
const BODY_LIMIT_BYTES = 1024 * 1024;
const rateBuckets = new Map();

loadDotEnv();
const config = getConfig();
const store = new JsonStore(config.dataDir);
await store.init();

const server = createServer(async (req, res) => {
  const start = Date.now();
  try {
    setSecurityHeaders(req, res);
    applyCors(req, res);

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const rawBody = await readRawBody(req, BODY_LIMIT_BYTES);
    await routeRequest(req, res, rawBody);
  } catch (error) {
    sendError(res, error);
  } finally {
    const elapsed = Date.now() - start;
    const status = res.statusCode || 200;
    console.info(`${req.method} ${req.url} ${status} ${elapsed}ms`);
  }
});

server.listen(config.port, '0.0.0.0', () => {
  console.info(`Payments hub listening on ${config.publicBaseUrl}`);
  console.info(`Payment provider: ${config.provider}`);
  console.info(`Registered sites: ${Array.from(config.sites.keys()).join(', ')}`);
  if (['auto', 'stripe'].includes(config.provider) && (!config.stripe.secretKey || !config.stripe.webhookSecret)) {
    console.info('Stripe keys are not fully configured yet. Copy .env.example to .env before taking payments.');
  }
  if (['auto', 'razorpay'].includes(config.provider) && (!config.razorpay.keyId || !config.razorpay.keySecret)) {
    console.info('Razorpay keys are not fully configured yet. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.');
  }
  if (config.provider === 'mock') {
    console.info('Mock checkout is enabled for cloud/local preview. Do not use it for real payments.');
  }
});

async function routeRequest(req, res, rawBody) {
  const url = new URL(req.url, config.publicBaseUrl);
  const path = url.pathname;

  if (path === '/health' && req.method === 'GET') {
    sendJson(res, 200, {
      ok: true,
      env: config.env,
      provider: config.provider,
      sites: Array.from(config.sites.keys()),
    });
    return;
  }

  if ((path === '/' || path === '/store' || path === '/store/') && req.method === 'GET') {
    await handleStorePage(req, res);
    return;
  }

  if (path === '/store/success' && req.method === 'GET') {
    await handleStoreResultPage(req, res, 'success');
    return;
  }

  if (path === '/store/cancel' && req.method === 'GET') {
    await handleStoreResultPage(req, res, 'cancel');
    return;
  }

  if (path === '/store/api/create-checkout' && req.method === 'POST') {
    enforceRateLimit(req, 'store-checkout', 20, 60_000);
    await handleStoreCreateCheckout(req, res);
    return;
  }

  if (path === '/store/api/payments/webhook' && req.method === 'POST') {
    enforceRateLimit(req, 'store-fulfillment', 120, 60_000);
    await handleStoreFulfillmentWebhook(req, res, rawBody);
    return;
  }

  if (path === '/api/checkout/sessions' && req.method === 'POST') {
    enforceRateLimit(req, 'checkout', 20, 60_000);
    await handleCreateCheckoutSession(req, res, rawBody);
    return;
  }

  if (path === '/api/refunds' && req.method === 'POST') {
    enforceRateLimit(req, 'refunds', 10, 60_000);
    await handleCreateRefund(req, res, rawBody);
    return;
  }

  const paymentMatch = path.match(/^\/api\/payments\/([a-zA-Z0-9_-]+)$/);
  if (paymentMatch && req.method === 'GET') {
    enforceRateLimit(req, 'payment-status', 120, 60_000);
    await handleGetPayment(req, res, rawBody, paymentMatch[1]);
    return;
  }

  if (path === '/webhooks/stripe' && req.method === 'POST') {
    enforceRateLimit(req, 'stripe-webhook', 240, 60_000);
    await handleStripeWebhook(req, res, rawBody);
    return;
  }

  if (path === '/webhooks/razorpay' && req.method === 'POST') {
    enforceRateLimit(req, 'razorpay-webhook', 240, 60_000);
    await handleRazorpayWebhook(req, res, rawBody);
    return;
  }

  const razorpayCheckoutMatch = path.match(/^\/razorpay-checkout\/([a-zA-Z0-9_-]+)$/);
  if (razorpayCheckoutMatch && req.method === 'GET') {
    await handleRazorpayCheckoutPage(res, razorpayCheckoutMatch[1]);
    return;
  }

  const razorpayVerifyMatch = path.match(/^\/razorpay-checkout\/([a-zA-Z0-9_-]+)\/verify$/);
  if (razorpayVerifyMatch && req.method === 'POST') {
    enforceRateLimit(req, 'razorpay-verify', 60, 60_000);
    await handleRazorpayCheckoutVerify(res, rawBody, razorpayVerifyMatch[1]);
    return;
  }

  const mockCheckoutMatch = path.match(/^\/mock-checkout\/([a-zA-Z0-9_-]+)$/);
  if (mockCheckoutMatch && req.method === 'GET') {
    await handleMockCheckoutPage(res, mockCheckoutMatch[1]);
    return;
  }

  const mockCompleteMatch = path.match(/^\/mock-checkout\/([a-zA-Z0-9_-]+)\/complete$/);
  if (mockCompleteMatch && req.method === 'POST') {
    enforceRateLimit(req, 'mock-checkout', 20, 60_000);
    await handleMockCheckoutComplete(res, mockCompleteMatch[1]);
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    await serveStatic(path, res, req.method === 'HEAD');
    return;
  }

  throw notFound('ROUTE_NOT_FOUND', 'Route not found.');
}

async function handleCreateCheckoutSession(req, res, rawBody) {
  const site = verifySignedSiteRequest({
    headers: req.headers,
    rawBody,
    sites: config.sites,
    toleranceSeconds: config.requestSignatureToleranceSeconds,
  });

  const body = parseJsonBody(rawBody);
  const checkout = validateCheckoutRequest(body, site, config);
  const provider = resolveProvider(checkout);
  const requestHash = sha256Hex(canonicalJson(checkout));
  const existing = await store.findPaymentBySiteOrder(site.id, checkout.orderId);

  if (existing) {
    if (existing.requestHash !== requestHash) {
      throw conflict(
        'ORDER_ALREADY_EXISTS',
        'A payment already exists for this site/orderId with different checkout details.'
      );
    }

    sendJson(res, 200, checkoutResponse(existing));
    return;
  }

  const now = new Date().toISOString();
  const payment = await store.createPayment({
    id: generateId('pay'),
    siteId: site.id,
    orderId: checkout.orderId,
    mode: checkout.mode,
    currency: checkout.currency,
    amount: checkout.totalAmount,
    status: 'checkout_creating',
    requestHash,
    items: checkout.items,
    customer: checkout.customer,
    metadata: checkout.metadata,
    successUrl: checkout.successUrl,
    cancelUrl: checkout.cancelUrl,
    providerCheckoutSessionId: null,
    stripeCheckoutSessionId: null,
    stripePaymentIntentId: null,
    razorpayOrderId: null,
    razorpayPaymentId: null,
    checkoutUrl: null,
    provider,
    createdAt: now,
    updatedAt: now,
    events: [],
    fulfillmentAttempts: [],
  });

  try {
    const idempotencyKey =
      req.headers['idempotency-key'] || `checkout:${payment.siteId}:${payment.orderId}:${requestHash}`;
    const session = await createProviderCheckoutSession(payment, checkout, idempotencyKey);
    const updated = await store.updatePayment(payment.id, () => ({
      status: 'checkout_created',
      providerCheckoutSessionId: session.id,
      stripeCheckoutSessionId: provider === 'stripe' ? session.id : null,
      stripePaymentIntentId:
        provider === 'stripe' && typeof session.payment_intent === 'string' ? session.payment_intent : null,
      razorpayOrderId: provider === 'razorpay' ? session.id : null,
      mockCheckoutSessionId: provider === 'mock' ? session.id : null,
      checkoutUrl: session.url,
      providerMode: session.mode,
    }));

    sendJson(res, 201, checkoutResponse(updated));
  } catch (error) {
    await store.updatePayment(payment.id, () => ({
      status: 'checkout_failed',
      lastError: sanitizeError(error),
    }));
    throw error;
  }
}

async function createProviderCheckoutSession(payment, checkout, idempotencyKey) {
  if (payment.provider === 'mock') {
    return {
      id: `mockcs_${payment.id}`,
      mode: checkout.mode,
      payment_intent: `mockpi_${payment.id}`,
      url: `${config.publicBaseUrl}/mock-checkout/${payment.id}`,
    };
  }

  if (payment.provider === 'razorpay') {
    if (checkout.mode !== 'payment' || !checkout.totalAmount) {
      throw new HttpError(400, 'RAZORPAY_ONE_TIME_ONLY', 'Razorpay checkout currently supports one-time amount-based payments.');
    }
    const order = await createRazorpayOrder(config, payment, checkout, idempotencyKey);
    return {
      id: order.id,
      mode: checkout.mode,
      url: `${config.publicBaseUrl}/razorpay-checkout/${payment.id}`,
    };
  }

  return createCheckoutSession(config, payment, checkout, idempotencyKey);
}

function resolveProvider(checkout) {
  if (config.provider === 'auto') {
    return checkout.currency === 'inr' ? 'razorpay' : 'stripe';
  }
  return config.provider;
}

async function handleCreateRefund(req, res, rawBody) {
  const site = verifySignedSiteRequest({
    headers: req.headers,
    rawBody,
    sites: config.sites,
    toleranceSeconds: config.requestSignatureToleranceSeconds,
  });

  const refundRequest = validateRefundRequest(parseJsonBody(rawBody));
  const payment = await store.getPayment(refundRequest.paymentId);

  if (!payment) {
    throw notFound('PAYMENT_NOT_FOUND', 'Payment not found.');
  }
  if (payment.siteId !== site.id) {
    throw forbidden('PAYMENT_SITE_MISMATCH', 'This payment belongs to another site.');
  }
  if (!['paid', 'partially_refunded'].includes(payment.status)) {
    throw conflict('PAYMENT_NOT_REFUNDABLE', 'Only paid payments can be refunded.');
  }

  const idempotencyKey =
    req.headers['idempotency-key'] ||
    `refund:${payment.siteId}:${payment.orderId}:${refundRequest.amount || 'full'}:${refundRequest.reason}`;
  const refund =
    payment.provider === 'mock'
      ? {
          id: generateId('mock_refund'),
          amount: refundRequest.amount || payment.amount,
          status: 'succeeded',
          reason: refundRequest.reason,
        }
      : payment.provider === 'razorpay'
        ? await createRazorpayRefund(config, payment, refundRequest)
        : await createRefund(config, payment, refundRequest, idempotencyKey);
  const refundedAmount = refund.amount || refundRequest.amount || payment.amount;
  const nextRefundedAmount = (payment.refundedAmount || 0) + refundedAmount;
  const status = payment.amount && nextRefundedAmount < payment.amount ? 'partially_refunded' : 'refunded';

  const updated = await store.updatePayment(payment.id, () => ({
    status,
    refundedAmount: nextRefundedAmount,
    lastRefund: {
      id: refund.id,
      amount: refundedAmount,
      status: refund.status,
      reason: refund.reason,
      createdAt: new Date().toISOString(),
    },
  }));

  await notifyMerchantSite(site, 'payment.refunded', updated);

  sendJson(res, 201, {
    paymentId: updated.id,
    status: updated.status,
    refundId: refund.id,
    refundedAmount: nextRefundedAmount,
  });
}

async function handleGetPayment(req, res, rawBody, paymentId) {
  const site = verifySignedSiteRequest({
    headers: req.headers,
    rawBody,
    sites: config.sites,
    toleranceSeconds: config.requestSignatureToleranceSeconds,
  });
  const payment = await store.getPayment(paymentId);

  if (!payment) {
    throw notFound('PAYMENT_NOT_FOUND', 'Payment not found.');
  }
  if (payment.siteId !== site.id) {
    throw forbidden('PAYMENT_SITE_MISMATCH', 'This payment belongs to another site.');
  }

  sendJson(res, 200, publicPayment(payment));
}

async function handleStripeWebhook(req, res, rawBody) {
  verifyStripeSignature(
    rawBody,
    req.headers['stripe-signature'],
    config.stripe.webhookSecret,
    config.stripeSignatureToleranceSeconds
  );

  const event = parseJsonBody(rawBody);
  const isNewEvent = await store.markStripeEvent(event);

  if (!isNewEvent) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  await processStripeEvent(event);
  sendJson(res, 200, { received: true });
}

async function handleRazorpayWebhook(req, res, rawBody) {
  verifyRazorpayWebhookSignature(rawBody, req.headers['x-razorpay-signature'], config.razorpay.webhookSecret);

  const event = parseJsonBody(rawBody);
  const eventId = req.headers['x-razorpay-event-id'] || event.event_id || event.id || generateId('rzp_evt');
  const isNewEvent = await store.markStripeEvent({
    id: `razorpay:${eventId}`,
    type: event.event || 'razorpay.event',
  });

  if (!isNewEvent) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  await processRazorpayEvent(event);
  sendJson(res, 200, { received: true });
}

async function handleStorePage(req, res) {
  const site = requireSimpleStoreSite();
  const storeConfig = config.simpleStore;

  sendHtml(
    res,
    200,
    storePageHtml({
      title: storeConfig.name,
      productName: storeConfig.productName,
      productDescription: storeConfig.productDescription,
      price: formatMoney(storeConfig.productPriceCents, storeConfig.currency),
      provider: config.provider,
      siteName: site.name,
    })
  );
}

async function handleStoreResultPage(req, res, result) {
  requireSimpleStoreSite();
  const isSuccess = result === 'success';
  sendHtml(
    res,
    200,
    storeResultHtml({
      title: isSuccess ? 'Payment Confirmed' : 'Checkout Cancelled',
      heading: isSuccess ? 'Payment confirmed' : 'Checkout cancelled',
      message: isSuccess
        ? 'The store will fulfill the order from the signed server webhook.'
        : 'The order was not completed. You can return to the product and try again.',
      tone: isSuccess ? 'success' : 'cancel',
    })
  );
}

async function handleStoreCreateCheckout(req, res) {
  const site = requireSimpleStoreSite();
  const storeConfig = config.simpleStore;
  const orderId = generateId('order');
  const checkoutRequest = {
    siteId: site.id,
    orderId,
    mode: 'payment',
    currency: storeConfig.currency,
    items: [
      {
        name: storeConfig.productName,
        description: storeConfig.productDescription,
        unitAmount: storeConfig.productPriceCents,
        quantity: 1,
      },
    ],
    customer: {
      email: storeConfig.customerEmail,
    },
    successUrl: `${config.publicBaseUrl}/store/success?session_id={CHECKOUT_SESSION_ID}`,
    cancelUrl: `${config.publicBaseUrl}/store/cancel`,
    metadata: {
      source: 'integrated-store',
    },
  };

  const body = JSON.stringify(checkoutRequest);
  const timestamp = Math.floor(Date.now() / 1000);
  const response = await fetch(`${config.internalBaseUrl}/api/checkout/sessions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-site-id': site.id,
      'x-timestamp': String(timestamp),
      'x-signature': `sha256=${signPayload(site.secret, timestamp, body)}`,
      'idempotency-key': orderId,
    },
    body,
  });

  const text = await response.text();
  res.writeHead(response.status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(text);
}

async function handleStoreFulfillmentWebhook(req, res, rawBody) {
  const site = requireSimpleStoreSite();
  verifyStoreFulfillmentSignature(req.headers, rawBody, site);
  const event = parseJsonBody(rawBody);

  console.info(`Integrated store received ${event.type} for payment ${event.data?.payment?.id || 'unknown'}`);
  sendJson(res, 200, { ok: true });
}

async function handleRazorpayCheckoutPage(res, paymentId) {
  const payment = await store.getPayment(paymentId);
  if (!payment || payment.provider !== 'razorpay') {
    throw notFound('PAYMENT_NOT_FOUND', 'Payment not found.');
  }

  if (!payment.razorpayOrderId) {
    throw conflict('RAZORPAY_ORDER_MISSING', 'Razorpay order is not ready.');
  }

  sendHtml(
    res,
    200,
    razorpayCheckoutHtml({
      keyId: config.razorpay.keyId,
      paymentId: payment.id,
      razorpayOrderId: payment.razorpayOrderId,
      amount: payment.amount || 0,
      currency: payment.currency,
      displayAmount: formatMoney(payment.amount || 0, payment.currency),
      merchantName: config.sites.get(payment.siteId)?.name || payment.siteId,
      description: payment.items?.[0]?.name || payment.orderId,
      customerEmail: payment.customer?.email || payment.customerEmail || '',
    })
  );
}

async function handleRazorpayCheckoutVerify(res, rawBody, paymentId) {
  const payment = await store.getPayment(paymentId);
  if (!payment || payment.provider !== 'razorpay') {
    throw notFound('PAYMENT_NOT_FOUND', 'Payment not found.');
  }

  const body = parseJsonBody(rawBody);
  verifyRazorpayPaymentSignature({
    orderId: payment.razorpayOrderId,
    paymentId: body.razorpay_payment_id,
    signature: body.razorpay_signature,
    keySecret: config.razorpay.keySecret,
  });

  if (body.razorpay_order_id !== payment.razorpayOrderId) {
    throw unauthorized('RAZORPAY_ORDER_MISMATCH', 'Razorpay order ID does not match the stored order.');
  }

  const site = config.sites.get(payment.siteId);
  const updated = await store.updatePayment(payment.id, (current) => ({
    status: 'paid',
    razorpayPaymentId: body.razorpay_payment_id,
    providerCheckoutSessionId: current.razorpayOrderId,
    customerEmail: current.customer?.email || current.customerEmail,
    events: appendEvent(current.events, 'razorpay.checkout.verified', body.razorpay_payment_id),
  }));

  if (site) {
    await notifyMerchantSite(site, 'payment.succeeded', updated);
  }

  sendJson(res, 200, {
    ok: true,
    redirectUrl: withCheckoutSessionId(payment.successUrl || `${config.publicBaseUrl}/store/success`, payment.razorpayOrderId),
  });
}

async function handleMockCheckoutPage(res, paymentId) {
  const payment = await store.getPayment(paymentId);
  if (!payment || payment.provider !== 'mock') {
    throw notFound('PAYMENT_NOT_FOUND', 'Payment not found.');
  }

  sendHtml(
    res,
    200,
    mockCheckoutHtml({
      paymentId: payment.id,
      orderId: payment.orderId,
      amount: formatMoney(payment.amount || 0, payment.currency),
      items: payment.items || [],
      customerEmail: payment.customer?.email || payment.customerEmail || '',
    })
  );
}

async function handleMockCheckoutComplete(res, paymentId) {
  const payment = await store.getPayment(paymentId);
  if (!payment || payment.provider !== 'mock') {
    throw notFound('PAYMENT_NOT_FOUND', 'Payment not found.');
  }

  const site = config.sites.get(payment.siteId);
  const updated = await store.updatePayment(payment.id, (current) => ({
    status: 'paid',
    providerCheckoutSessionId: current.providerCheckoutSessionId || `mockcs_${payment.id}`,
    mockPaymentIntentId: current.mockPaymentIntentId || `mockpi_${payment.id}`,
    customerEmail: current.customer?.email || current.customerEmail,
    events: appendEvent(current.events, 'mock.checkout.completed', payment.id),
  }));

  if (site) {
    await notifyMerchantSite(site, 'payment.succeeded', updated);
  }

  res.writeHead(303, {
    location: withCheckoutSessionId(payment.successUrl || `${config.publicBaseUrl}/store/success`, `mockcs_${payment.id}`),
  });
  res.end();
}

function requireSimpleStoreSite() {
  if (!config.simpleStore.enabled) {
    throw notFound('STORE_DISABLED', 'The integrated store is disabled.');
  }

  const site = config.sites.get(config.simpleStore.siteId);
  if (!site) {
    throw new HttpError(
      500,
      'STORE_SITE_NOT_CONFIGURED',
      `STORE_SITE_ID "${config.simpleStore.siteId}" is not listed in SITES.`
    );
  }
  return site;
}

function verifyStoreFulfillmentSignature(headers, rawBody, site) {
  if (!site.fulfillmentSecret) {
    throw unauthorized('FULFILLMENT_SECRET_MISSING', 'Fulfillment secret is not configured.');
  }

  const timestamp = headers['x-payments-timestamp'];
  const signature = String(headers['x-payments-signature'] || '').replace(/^sha256=/, '');
  const timestampSeconds = Number.parseInt(String(timestamp), 10);

  if (!Number.isFinite(timestampSeconds) || !signature) {
    throw unauthorized('FULFILLMENT_SIGNATURE_MISSING', 'Fulfillment signature headers are required.');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestampSeconds) > config.requestSignatureToleranceSeconds) {
    throw unauthorized('FULFILLMENT_SIGNATURE_EXPIRED', 'Fulfillment signature timestamp is outside the allowed window.');
  }

  const expected = signPayload(site.fulfillmentSecret, timestampSeconds, rawBody);
  if (!constantTimeEqualHex(signature, expected)) {
    throw unauthorized('FULFILLMENT_SIGNATURE_INVALID', 'Fulfillment signature verification failed.');
  }
}

async function processStripeEvent(event) {
  const object = event.data?.object;
  if (!object || typeof object !== 'object') {
    return;
  }

  if (
    [
      'checkout.session.completed',
      'checkout.session.async_payment_succeeded',
      'checkout.session.async_payment_failed',
      'checkout.session.expired',
    ].includes(event.type)
  ) {
    await processCheckoutSessionEvent(event.type, object);
    return;
  }

  if (event.type === 'charge.refunded' || event.type === 'refund.updated') {
    await processRefundLikeEvent(event.type, object);
  }
}

async function processRazorpayEvent(event) {
  const eventName = event.event || '';
  const paymentEntity = event.payload?.payment?.entity;
  const orderEntity = event.payload?.order?.entity;
  const refundEntity = event.payload?.refund?.entity;
  const notes = paymentEntity?.notes || orderEntity?.notes || refundEntity?.notes || {};

  const payment =
    (notes.paymentId && (await store.getPayment(notes.paymentId))) ||
    (orderEntity?.id && (await store.getPaymentByRazorpayOrder(orderEntity.id))) ||
    (paymentEntity?.order_id && (await store.getPaymentByRazorpayOrder(paymentEntity.order_id))) ||
    (paymentEntity?.id && (await store.getPaymentByRazorpayPayment(paymentEntity.id)));

  if (!payment) {
    console.warn(`Razorpay event for unknown payment/order ${paymentEntity?.id || orderEntity?.id || eventName}`);
    return;
  }

  const site = config.sites.get(payment.siteId);
  const status = statusFromRazorpayEvent(eventName, paymentEntity, orderEntity, refundEntity);
  const updated = await store.updatePayment(payment.id, (current) => ({
    status,
    razorpayOrderId: paymentEntity?.order_id || orderEntity?.id || current.razorpayOrderId,
    razorpayPaymentId: paymentEntity?.id || refundEntity?.payment_id || current.razorpayPaymentId,
    customerEmail: paymentEntity?.email || current.customerEmail,
    refundedAmount: refundEntity?.amount ? (current.refundedAmount || 0) + refundEntity.amount : current.refundedAmount,
    events: appendEvent(current.events, eventName, paymentEntity?.id || orderEntity?.id || refundEntity?.id),
  }));

  if (site && ['paid', 'payment_failed', 'refunded'].includes(status)) {
    const merchantEvent =
      status === 'paid' ? 'payment.succeeded' : status === 'refunded' ? 'payment.refunded' : 'payment.failed';
    await notifyMerchantSite(site, merchantEvent, updated);
  }
}

async function processCheckoutSessionEvent(eventType, session) {
  const payment =
    (session.metadata?.paymentId && (await store.getPayment(session.metadata.paymentId))) ||
    (session.id && (await store.getPaymentByStripeSession(session.id)));

  if (!payment) {
    console.warn(`Stripe event for unknown checkout session ${session.id}`);
    return;
  }

  const site = config.sites.get(payment.siteId);
  const status = statusFromCheckoutSession(eventType, session);

  const updated = await store.updatePayment(payment.id, (current) => ({
    status,
    stripeCheckoutSessionId: session.id || current.stripeCheckoutSessionId,
    stripePaymentIntentId:
      typeof session.payment_intent === 'string' ? session.payment_intent : current.stripePaymentIntentId,
    stripeCustomerId: typeof session.customer === 'string' ? session.customer : current.stripeCustomerId,
    customerEmail: session.customer_details?.email || session.customer_email || current.customerEmail,
    events: appendEvent(current.events, eventType, session.id),
  }));

  if (site && ['paid', 'payment_failed', 'expired'].includes(status)) {
    const merchantEvent =
      status === 'paid' ? 'payment.succeeded' : status === 'expired' ? 'payment.expired' : 'payment.failed';
    await notifyMerchantSite(site, merchantEvent, updated);
  }
}

async function processRefundLikeEvent(eventType, object) {
  const paymentIntentId =
    typeof object.payment_intent === 'string'
      ? object.payment_intent
      : typeof object.payment_intent?.id === 'string'
        ? object.payment_intent.id
        : '';

  if (!paymentIntentId) {
    return;
  }

  const allPayments = await findPaymentByIntent(paymentIntentId);
  if (!allPayments) {
    return;
  }

  const site = config.sites.get(allPayments.siteId);
  const updated = await store.updatePayment(allPayments.id, (current) => ({
    status: 'refunded',
    events: appendEvent(current.events, eventType, object.id),
  }));

  if (site) {
    await notifyMerchantSite(site, 'payment.refunded', updated);
  }
}

async function findPaymentByIntent(paymentIntentId) {
  const data = await store.readJson(store.paymentsPath, { payments: [] });
  return data.payments.find((payment) => payment.stripePaymentIntentId === paymentIntentId) || null;
}

async function notifyMerchantSite(site, eventType, payment) {
  if (!site.fulfillmentUrl || !site.fulfillmentSecret) {
    return;
  }

  const body = JSON.stringify({
    id: generateId('evt'),
    type: eventType,
    createdAt: new Date().toISOString(),
    data: {
      payment: publicPayment(payment),
    },
  });

  const headers = {
    'content-type': 'application/json',
    ...signedWebhookHeaders(site.fulfillmentSecret, body),
  };

  try {
    const response = await fetch(site.fulfillmentUrl, {
      method: 'POST',
      headers,
      body,
    });

    const attempt = {
      eventType,
      status: response.status,
      ok: response.ok,
      createdAt: new Date().toISOString(),
    };

    await store.updatePayment(payment.id, (current) => ({
      fulfillmentAttempts: [...(current.fulfillmentAttempts || []), attempt].slice(-20),
    }));

    if (!response.ok) {
      console.warn(`Merchant fulfillment webhook returned ${response.status} for payment ${payment.id}`);
    }
  } catch (error) {
    await store.updatePayment(payment.id, (current) => ({
      fulfillmentAttempts: [
        ...(current.fulfillmentAttempts || []),
        {
          eventType,
          ok: false,
          error: error.message,
          createdAt: new Date().toISOString(),
        },
      ].slice(-20),
    }));
    console.warn(`Merchant fulfillment webhook failed for payment ${payment.id}: ${error.message}`);
  }
}

function statusFromCheckoutSession(eventType, session) {
  if (eventType === 'checkout.session.expired') {
    return 'expired';
  }
  if (eventType === 'checkout.session.async_payment_failed') {
    return 'payment_failed';
  }
  if (eventType === 'checkout.session.async_payment_succeeded') {
    return 'paid';
  }
  if (session.payment_status === 'paid') {
    return 'paid';
  }
  return 'awaiting_payment';
}

function statusFromRazorpayEvent(eventName, paymentEntity, orderEntity, refundEntity) {
  if (eventName === 'refund.processed' || eventName === 'payment.refunded' || refundEntity?.status === 'processed') {
    return 'refunded';
  }
  if (eventName === 'payment.failed' || paymentEntity?.status === 'failed') {
    return 'payment_failed';
  }
  if (
    eventName === 'payment.captured' ||
    eventName === 'order.paid' ||
    paymentEntity?.status === 'captured' ||
    orderEntity?.status === 'paid'
  ) {
    return 'paid';
  }
  if (eventName === 'payment.authorized' || paymentEntity?.status === 'authorized') {
    return 'authorized';
  }
  return 'awaiting_payment';
}

function appendEvent(events = [], type, objectId) {
  return [
    ...events,
    {
      type,
      objectId,
      createdAt: new Date().toISOString(),
    },
  ].slice(-50);
}

function checkoutResponse(payment) {
  return {
    paymentId: payment.id,
    status: payment.status,
    checkoutUrl: payment.checkoutUrl,
    provider: payment.provider,
    providerCheckoutSessionId: payment.providerCheckoutSessionId,
    stripeCheckoutSessionId: payment.stripeCheckoutSessionId,
    razorpayOrderId: payment.razorpayOrderId,
  };
}

function publicPayment(payment) {
  return {
    id: payment.id,
    siteId: payment.siteId,
    orderId: payment.orderId,
    mode: payment.mode,
    currency: payment.currency,
    amount: payment.amount,
    status: payment.status,
    refundedAmount: payment.refundedAmount || 0,
    provider: payment.provider,
    providerCheckoutSessionId: payment.providerCheckoutSessionId,
    stripeCheckoutSessionId: payment.stripeCheckoutSessionId,
    razorpayOrderId: payment.razorpayOrderId,
    createdAt: payment.createdAt,
    updatedAt: payment.updatedAt,
  };
}

function parseJsonBody(rawBody) {
  try {
    return JSON.parse(rawBody || '{}');
  } catch {
    throw new HttpError(400, 'INVALID_JSON', 'Request body must be valid JSON.');
  }
}

async function readRawBody(req, limitBytes) {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return '';
  }

  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > limitBytes) {
      throw new HttpError(413, 'BODY_TOO_LARGE', 'Request body is too large.');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function enforceRateLimit(req, bucketName, limit, windowMs) {
  const key = `${bucketName}:${clientIp(req)}`;
  const now = Date.now();
  const current = rateBuckets.get(key);

  if (!current || current.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return;
  }

  current.count += 1;
  if (current.count > limit) {
    throw tooManyRequests('RATE_LIMITED', 'Too many requests. Try again shortly.');
  }
}

function clientIp(req) {
  if (config.trustProxy && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) {
    return;
  }

  const allowed = Array.from(config.sites.values()).some((site) => site.allowedOrigins.includes(origin));
  if (!allowed) {
    return;
  }

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'content-type,x-site-id,x-timestamp,x-signature,idempotency-key'
  );
}

function setSecurityHeaders(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; img-src 'self' data: https://*.razorpay.com; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://checkout.razorpay.com; connect-src 'self' https://api.razorpay.com; frame-src https://api.razorpay.com https://checkout.razorpay.com; form-action 'self' https://checkout.stripe.com"
  );

  if (req.url?.startsWith('/api/') || req.url?.startsWith('/webhooks/')) {
    res.setHeader('Cache-Control', 'no-store');
  }
}

async function serveStatic(path, res, headOnly) {
  const normalizedPath = path === '/' ? '/index.html' : path;
  const safePath = normalize(normalizedPath).replace(/^(\.\.[/\\])+/, '');
  const filePath = join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    throw forbidden('INVALID_STATIC_PATH', 'Invalid static path.');
  }

  try {
    const file = await readFile(filePath);
    res.writeHead(200, { 'content-type': contentType(filePath) });
    if (!headOnly) {
      res.end(file);
    } else {
      res.end();
    }
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw notFound('STATIC_NOT_FOUND', 'File not found.');
    }
    throw error;
  }
}

function storePageHtml({ title, productName, productDescription, price, provider, siteName }) {
  const isPreview = provider === 'mock';
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      :root {
        color-scheme: light;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f5f7fa;
        color: #172033;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
      }
      main {
        width: min(980px, 100%);
        display: grid;
        grid-template-columns: minmax(280px, 1fr) minmax(280px, 420px);
        gap: 28px;
        align-items: center;
      }
      .product-visual {
        min-height: 520px;
        border-radius: 8px;
        background:
          radial-gradient(circle at 22% 22%, rgba(38, 132, 255, 0.16), transparent 32%),
          linear-gradient(135deg, #e9eef7, #ffffff 54%, #dce8f6);
        border: 1px solid #d7dee9;
        position: relative;
        overflow: hidden;
        display: grid;
        place-items: center;
      }
      .kit {
        width: min(72%, 380px);
        aspect-ratio: 0.78;
        border-radius: 8px;
        background: #17324d;
        color: #fff;
        padding: 30px;
        display: grid;
        align-content: space-between;
        box-shadow: 0 28px 70px rgba(23, 50, 77, 0.28);
        transform: rotate(-2deg);
      }
      .kit-mark {
        width: 74px;
        height: 74px;
        border-radius: 8px;
        background: #4db6ac;
        display: grid;
        place-items: center;
        color: #102a43;
        font-weight: 900;
        font-size: 28px;
      }
      .kit-lines {
        display: grid;
        gap: 12px;
      }
      .kit-lines span {
        height: 12px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.72);
      }
      .kit-lines span:nth-child(2) {
        width: 72%;
      }
      .kit-lines span:nth-child(3) {
        width: 48%;
        background: #f4c95d;
      }
      .panel {
        background: #ffffff;
        border: 1px solid #d7dee9;
        border-radius: 8px;
        padding: 28px;
        box-shadow: 0 18px 48px rgba(23, 32, 51, 0.08);
      }
      .eyebrow {
        margin: 0 0 12px;
        color: #57708e;
        font-size: 14px;
        font-weight: 700;
        text-transform: uppercase;
      }
      h1 {
        margin: 0 0 14px;
        font-size: 36px;
        line-height: 1.08;
      }
      .description {
        margin: 0 0 22px;
        color: #4d5b73;
        line-height: 1.6;
      }
      .price-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        margin: 24px 0;
        padding: 16px 0;
        border-top: 1px solid #e4e9f0;
        border-bottom: 1px solid #e4e9f0;
      }
      .price {
        font-size: 28px;
        font-weight: 800;
      }
      .badge {
        border: 1px solid #bbd6d1;
        background: #eef8f6;
        color: #23655e;
        border-radius: 999px;
        padding: 7px 10px;
        font-size: 13px;
        font-weight: 700;
      }
      button {
        width: 100%;
        min-height: 48px;
        border: 0;
        border-radius: 6px;
        background: #174ea6;
        color: white;
        font-size: 16px;
        font-weight: 800;
        cursor: pointer;
      }
      button:disabled {
        opacity: 0.68;
        cursor: progress;
      }
      .status {
        min-height: 22px;
        margin: 14px 0 0;
        color: #4d5b73;
        line-height: 1.45;
      }
      .preview {
        display: ${isPreview ? 'block' : 'none'};
        margin-top: 16px;
        color: #6c5d1f;
        background: #fff8df;
        border: 1px solid #ebd889;
        border-radius: 6px;
        padding: 12px;
        font-size: 14px;
      }
      @media (max-width: 780px) {
        body {
          padding: 16px;
          place-items: start center;
        }
        main {
          grid-template-columns: 1fr;
        }
        .product-visual {
          min-height: 320px;
        }
        .kit {
          width: min(64%, 300px);
        }
        h1 {
          font-size: 30px;
        }
      }
    </style>
  </head>
  <body>
    <main>
      <section class="product-visual" aria-label="${escapeHtml(productName)} product preview">
        <div class="kit" aria-hidden="true">
          <div class="kit-mark">$</div>
          <div>
            <h2>${escapeHtml(productName)}</h2>
            <div class="kit-lines">
              <span></span>
              <span></span>
              <span></span>
            </div>
          </div>
        </div>
      </section>
      <section class="panel">
        <p class="eyebrow">${escapeHtml(siteName)}</p>
        <h1>${escapeHtml(productName)}</h1>
        <p class="description">${escapeHtml(productDescription)}</p>
        <div class="price-row">
          <span class="price">${escapeHtml(price)}</span>
          <span class="badge">Secure Checkout</span>
        </div>
        <button id="checkoutButton">Buy now</button>
        <p class="status" id="status" aria-live="polite"></p>
        <p class="preview">Preview mode is active, so the checkout page simulates a provider payment.</p>
      </section>
    </main>
    <script>
      const button = document.querySelector('#checkoutButton');
      const status = document.querySelector('#status');
      button.addEventListener('click', async () => {
        button.disabled = true;
        status.textContent = 'Creating checkout...';
        try {
          const response = await fetch('/store/api/create-checkout', { method: 'POST' });
          const checkout = await response.json();
          if (!response.ok) {
            throw new Error(checkout.error?.message || 'Checkout could not be created.');
          }
          window.location.href = checkout.checkoutUrl;
        } catch (error) {
          status.textContent = error.message;
          button.disabled = false;
        }
      });
    </script>
  </body>
</html>`;
}

function storeResultHtml({ title, heading, message, tone }) {
  const color = tone === 'success' ? '#23655e' : '#6c5d1f';
  const background = tone === 'success' ? '#eef8f6' : '#fff8df';
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f5f7fa;
        color: #172033;
      }
      main {
        width: min(560px, 100%);
        background: #ffffff;
        border: 1px solid #d7dee9;
        border-radius: 8px;
        padding: 30px;
        box-shadow: 0 18px 48px rgba(23, 32, 51, 0.08);
      }
      .mark {
        width: 54px;
        height: 54px;
        border-radius: 8px;
        display: grid;
        place-items: center;
        background: ${background};
        color: ${color};
        font-size: 28px;
        font-weight: 900;
      }
      h1 {
        margin: 18px 0 10px;
      }
      p {
        margin: 0 0 22px;
        color: #4d5b73;
        line-height: 1.6;
      }
      a {
        color: #174ea6;
        font-weight: 800;
        text-decoration: none;
      }
    </style>
  </head>
  <body>
    <main>
      <div class="mark">${tone === 'success' ? '$' : '!'}</div>
      <h1>${escapeHtml(heading)}</h1>
      <p>${escapeHtml(message)}</p>
      <a href="/store">Back to store</a>
    </main>
  </body>
</html>`;
}

function mockCheckoutHtml({ paymentId, orderId, amount, items, customerEmail }) {
  const item = items[0] || {};
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Preview Checkout</title>
    <style>
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #edf2f7;
        color: #172033;
      }
      main {
        width: min(520px, 100%);
        background: #ffffff;
        border: 1px solid #d7dee9;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 18px 48px rgba(23, 32, 51, 0.1);
      }
      header {
        background: #17324d;
        color: #ffffff;
        padding: 22px;
      }
      h1 {
        margin: 0;
        font-size: 24px;
      }
      .content {
        padding: 24px;
      }
      dl {
        display: grid;
        gap: 12px;
        margin: 0 0 22px;
      }
      .row {
        display: flex;
        justify-content: space-between;
        gap: 18px;
        border-bottom: 1px solid #e4e9f0;
        padding-bottom: 12px;
      }
      dt {
        color: #57708e;
      }
      dd {
        margin: 0;
        text-align: right;
        font-weight: 800;
      }
      button {
        width: 100%;
        min-height: 48px;
        border: 0;
        border-radius: 6px;
        background: #23655e;
        color: white;
        font-size: 16px;
        font-weight: 800;
        cursor: pointer;
      }
      .note {
        margin: 14px 0 0;
        color: #6c5d1f;
        background: #fff8df;
        border: 1px solid #ebd889;
        border-radius: 6px;
        padding: 12px;
        line-height: 1.45;
      }
    </style>
  </head>
  <body>
    <main>
      <header>
        <h1>Preview Checkout</h1>
      </header>
      <section class="content">
        <dl>
          <div class="row"><dt>Order</dt><dd>${escapeHtml(orderId)}</dd></div>
          <div class="row"><dt>Item</dt><dd>${escapeHtml(item.name || paymentId)}</dd></div>
          <div class="row"><dt>Email</dt><dd>${escapeHtml(customerEmail || 'customer@example.com')}</dd></div>
          <div class="row"><dt>Total</dt><dd>${escapeHtml(amount)}</dd></div>
        </dl>
        <form method="post" action="/mock-checkout/${encodeURIComponent(paymentId)}/complete">
          <button type="submit">Complete preview payment</button>
        </form>
        <p class="note">No real card is charged on this preview provider.</p>
      </section>
    </main>
  </body>
</html>`;
}

function razorpayCheckoutHtml({
  keyId,
  paymentId,
  razorpayOrderId,
  amount,
  currency,
  displayAmount,
  merchantName,
  description,
  customerEmail,
}) {
  const checkoutOptions = {
    key: keyId,
    amount,
    currency: currency.toUpperCase(),
    name: merchantName,
    description,
    order_id: razorpayOrderId,
    prefill: {
      email: customerEmail,
    },
    notes: {
      paymentId,
    },
    theme: {
      color: '#174ea6',
    },
  };

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Razorpay Checkout</title>
    <style>
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f5f7fa;
        color: #172033;
      }
      main {
        width: min(520px, 100%);
        background: #ffffff;
        border: 1px solid #d7dee9;
        border-radius: 8px;
        padding: 28px;
        box-shadow: 0 18px 48px rgba(23, 32, 51, 0.1);
      }
      h1 {
        margin: 0 0 12px;
      }
      p {
        color: #4d5b73;
        line-height: 1.55;
      }
      .total {
        display: flex;
        justify-content: space-between;
        gap: 18px;
        margin: 22px 0;
        padding: 16px 0;
        border-top: 1px solid #e4e9f0;
        border-bottom: 1px solid #e4e9f0;
        font-weight: 800;
      }
      button {
        width: 100%;
        min-height: 48px;
        border: 0;
        border-radius: 6px;
        background: #174ea6;
        color: white;
        font-size: 16px;
        font-weight: 800;
        cursor: pointer;
      }
      .status {
        min-height: 22px;
        margin-top: 14px;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Secure Checkout</h1>
      <p>Complete this payment using Razorpay. UPI, cards, netbanking, wallets, and bank authentication are handled by Razorpay when enabled on your account.</p>
      <div class="total"><span>${escapeHtml(description)}</span><span>${escapeHtml(displayAmount)}</span></div>
      <button id="payButton">Continue to Razorpay</button>
      <p class="status" id="status" aria-live="polite"></p>
    </main>
    <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
    <script>
      const options = ${JSON.stringify(checkoutOptions)};
      const status = document.querySelector('#status');
      const button = document.querySelector('#payButton');
      options.handler = async function (response) {
        status.textContent = 'Verifying payment...';
        button.disabled = true;
        const verify = await fetch('/razorpay-checkout/${encodeURIComponent(paymentId)}/verify', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(response)
        });
        const result = await verify.json();
        if (!verify.ok) {
          status.textContent = result.error?.message || 'Payment verification failed.';
          button.disabled = false;
          return;
        }
        window.location.href = result.redirectUrl;
      };
      options.modal = {
        ondismiss: function () {
          status.textContent = 'Checkout closed. You can try again.';
          button.disabled = false;
        }
      };
      function openCheckout() {
        status.textContent = 'Opening Razorpay...';
        button.disabled = true;
        const checkout = new Razorpay(options);
        checkout.open();
      }
      button.addEventListener('click', openCheckout);
      window.addEventListener('load', openCheckout);
    </script>
  </body>
</html>`;
}

function withCheckoutSessionId(url, sessionId) {
  return String(url).replace('{CHECKOUT_SESSION_ID}', encodeURIComponent(sessionId));
}

function formatMoney(amountCents, currency) {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency.toUpperCase(),
  }).format(amountCents / 100);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function contentType(filePath) {
  const extension = extname(filePath);
  return (
    {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'text/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.png': 'image/png',
    }[extension] || 'application/octet-stream'
  );
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function sendError(res, error) {
  const status = error instanceof HttpError ? error.status : 500;
  const payload = {
    error: {
      code: error instanceof HttpError ? error.code : 'INTERNAL_ERROR',
      message: error instanceof HttpError ? error.message : 'Internal server error.',
    },
  };

  if (error instanceof HttpError && error.details && config.env !== 'production') {
    payload.error.details = error.details;
  }

  if (!(error instanceof HttpError)) {
    console.error(error);
  } else if (status >= 500) {
    console.error(error.code, redact(error.message), error.details || '');
  }

  sendJson(res, status, payload);
}

function sanitizeError(error) {
  if (error instanceof HttpError) {
    return {
      code: error.code,
      message: error.message,
      details: error.details,
    };
  }
  return {
    code: 'INTERNAL_ERROR',
    message: error.message,
  };
}
