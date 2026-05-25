import { createHmac, timingSafeEqual } from 'node:crypto';

export function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
    body: JSON.stringify(body),
  };
}

export function parseJson(value) {
  try {
    return JSON.parse(value || '{}');
  } catch {
    return null;
  }
}

export function hmacHex(secret, payload) {
  return createHmac('sha256', secret).update(payload).digest('hex');
}

export function constantTimeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }
  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');
  return leftBuffer.length > 0 && leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function razorpayConfigured() {
  return Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
}

export function readSettlementConfig() {
  return {
    label: process.env.MERCHANT_SETTLEMENT_LABEL || 'Razorpay Dashboard settlement account',
    provider: 'razorpay',
    configuredInProviderDashboard: true,
    note:
      'For real settlements, Razorpay sends funds to the verified bank account configured in your Razorpay account. This app never stores raw bank or UPI details.',
  };
}

