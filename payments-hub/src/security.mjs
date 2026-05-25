import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { unauthorized } from './errors.mjs';

export function generateId(prefix) {
  return `${prefix}_${randomBytes(16).toString('hex')}`;
}

export function hmacHex(secret, payload) {
  return createHmac('sha256', secret).update(payload).digest('hex');
}

export function sha256Hex(payload) {
  return createHash('sha256').update(payload).digest('hex');
}

export function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }

  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((result, key) => {
        result[key] = sortValue(value[key]);
        return result;
      }, {});
  }

  return value;
}

export function constantTimeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }

  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');

  if (leftBuffer.length === 0 || leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

export function signPayload(secret, timestamp, rawBody) {
  return hmacHex(secret, `${timestamp}.${rawBody}`);
}

export function verifySignedSiteRequest({ headers, rawBody, sites, toleranceSeconds }) {
  const siteId = headers['x-site-id'];
  const timestamp = headers['x-timestamp'];
  const signatureHeader = headers['x-signature'];

  if (!siteId || !timestamp || !signatureHeader) {
    throw unauthorized(
      'SIGNATURE_HEADERS_MISSING',
      'x-site-id, x-timestamp, and x-signature headers are required.'
    );
  }

  const site = sites.get(siteId);
  if (!site) {
    throw unauthorized('UNKNOWN_SITE', 'The supplied site ID is not registered.');
  }

  const timestampSeconds = Number.parseInt(String(timestamp), 10);
  if (!Number.isFinite(timestampSeconds)) {
    throw unauthorized('SIGNATURE_TIMESTAMP_INVALID', 'x-timestamp must be a Unix timestamp in seconds.');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestampSeconds) > toleranceSeconds) {
    throw unauthorized('SIGNATURE_TIMESTAMP_EXPIRED', 'The signed request timestamp is outside the allowed window.');
  }

  const suppliedSignature = String(signatureHeader).replace(/^sha256=/, '');
  const expectedSignature = signPayload(site.secret, timestampSeconds, rawBody);

  if (!constantTimeEqualHex(suppliedSignature, expectedSignature)) {
    throw unauthorized('SIGNATURE_INVALID', 'The signed request signature is invalid.');
  }

  return site;
}

export function verifyStripeSignature(rawBody, signatureHeader, endpointSecret, toleranceSeconds) {
  if (!endpointSecret) {
    throw unauthorized('STRIPE_WEBHOOK_SECRET_MISSING', 'STRIPE_WEBHOOK_SECRET is not configured.');
  }

  if (!signatureHeader) {
    throw unauthorized('STRIPE_SIGNATURE_MISSING', 'Stripe-Signature header is required.');
  }

  const parts = String(signatureHeader)
    .split(',')
    .map((part) => part.trim())
    .reduce(
      (result, part) => {
        const [key, value] = part.split('=');
        if (key === 't') {
          result.timestamp = value;
        }
        if (key === 'v1') {
          result.v1.push(value);
        }
        return result;
      },
      { timestamp: '', v1: [] }
    );

  const timestampSeconds = Number.parseInt(parts.timestamp, 10);
  if (!Number.isFinite(timestampSeconds) || parts.v1.length === 0) {
    throw unauthorized('STRIPE_SIGNATURE_INVALID', 'Stripe-Signature header is malformed.');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestampSeconds) > toleranceSeconds) {
    throw unauthorized('STRIPE_SIGNATURE_EXPIRED', 'Stripe webhook timestamp is outside the allowed window.');
  }

  const expectedSignature = hmacHex(endpointSecret, `${timestampSeconds}.${rawBody}`);
  const matches = parts.v1.some((signature) => constantTimeEqualHex(signature, expectedSignature));

  if (!matches) {
    throw unauthorized('STRIPE_SIGNATURE_MISMATCH', 'Stripe webhook signature verification failed.');
  }
}

export function verifyRazorpayPaymentSignature({ orderId, paymentId, signature, keySecret }) {
  if (!keySecret) {
    throw unauthorized('RAZORPAY_KEY_SECRET_MISSING', 'RAZORPAY_KEY_SECRET is not configured.');
  }

  if (!orderId || !paymentId || !signature) {
    throw unauthorized('RAZORPAY_PAYMENT_SIGNATURE_MISSING', 'Razorpay payment signature fields are required.');
  }

  const expectedSignature = hmacHex(keySecret, `${orderId}|${paymentId}`);
  if (!constantTimeEqualHex(signature, expectedSignature)) {
    throw unauthorized('RAZORPAY_PAYMENT_SIGNATURE_INVALID', 'Razorpay payment signature verification failed.');
  }
}

export function verifyRazorpayWebhookSignature(rawBody, signatureHeader, webhookSecret) {
  if (!webhookSecret) {
    throw unauthorized('RAZORPAY_WEBHOOK_SECRET_MISSING', 'RAZORPAY_WEBHOOK_SECRET is not configured.');
  }

  if (!signatureHeader) {
    throw unauthorized('RAZORPAY_WEBHOOK_SIGNATURE_MISSING', 'X-Razorpay-Signature header is required.');
  }

  const expectedSignature = hmacHex(webhookSecret, rawBody);
  if (!constantTimeEqualHex(String(signatureHeader), expectedSignature)) {
    throw unauthorized('RAZORPAY_WEBHOOK_SIGNATURE_INVALID', 'Razorpay webhook signature verification failed.');
  }
}

export function signedWebhookHeaders(secret, rawBody) {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signPayload(secret, timestamp, rawBody);
  return {
    'x-payments-timestamp': String(timestamp),
    'x-payments-signature': `sha256=${signature}`,
  };
}

export function redact(value) {
  if (!value || typeof value !== 'string') {
    return value;
  }
  if (value.length <= 8) {
    return '***';
  }
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}
