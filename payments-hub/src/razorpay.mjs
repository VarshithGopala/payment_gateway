import { badRequest, upstreamError } from './errors.mjs';

const RAZORPAY_API_BASE_URL = 'https://api.razorpay.com/v1';

export async function createRazorpayOrder(config, payment, checkout, idempotencyKey) {
  const params = {
    amount: checkout.totalAmount,
    currency: checkout.currency.toUpperCase(),
    receipt: checkout.orderId.slice(0, 40),
    notes: {
      paymentId: payment.id,
      siteId: payment.siteId,
      orderId: payment.orderId,
      idempotencyKey,
      ...checkout.metadata,
    },
  };

  return razorpayRequest(config, 'POST', '/orders', params);
}

export async function createRazorpayRefund(config, payment, refundRequest) {
  if (!payment.razorpayPaymentId) {
    throw badRequest('RAZORPAY_PAYMENT_ID_MISSING', 'This payment does not have a Razorpay payment ID yet.');
  }

  return razorpayRequest(config, 'POST', `/payments/${encodeURIComponent(payment.razorpayPaymentId)}/refund`, {
    amount: refundRequest.amount,
    speed: 'normal',
    receipt: `${payment.orderId}`.slice(0, 40),
    notes: {
      paymentId: payment.id,
      siteId: payment.siteId,
      orderId: payment.orderId,
      ...refundRequest.metadata,
    },
  });
}

async function razorpayRequest(config, method, path, params) {
  if (!config.razorpay.keyId || !config.razorpay.keySecret) {
    throw badRequest('RAZORPAY_KEYS_MISSING', 'RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are required.');
  }

  const response = await fetch(`${RAZORPAY_API_BASE_URL}${path}`, {
    method,
    headers: {
      authorization: `Basic ${Buffer.from(`${config.razorpay.keyId}:${config.razorpay.keySecret}`).toString('base64')}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(params),
  });

  const text = await response.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text };
  }

  if (!response.ok) {
    throw upstreamError('RAZORPAY_REQUEST_FAILED', 'Razorpay API request failed.', {
      status: response.status,
      message: json.error?.description || json.error?.reason || 'Unknown Razorpay error.',
      code: json.error?.code,
    });
  }

  return json;
}
