import { json, parseJson, razorpayConfigured } from './_utils.mjs';

const RAZORPAY_API_BASE_URL = 'https://api.razorpay.com/v1';

export async function handler(event) {
  if (event.httpMethod !== 'POST') {
    return json(405, { error: { message: 'Method not allowed.' } });
  }

  const body = parseJson(event.body);
  if (!body) {
    return json(400, { error: { message: 'Request body must be JSON.' } });
  }

  const amountRupees = Number(body.amount);
  if (!Number.isFinite(amountRupees) || amountRupees < 1 || amountRupees > 500000) {
    return json(400, { error: { message: 'Enter an amount from INR 1 to INR 500000.' } });
  }

  if (!razorpayConfigured()) {
    return json(500, {
      error: {
        message:
          'Razorpay live/test keys are not configured in Netlify yet. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.',
      },
    });
  }

  const amountPaise = Math.round(amountRupees * 100);
  const receipt = `client_${Date.now()}`.slice(0, 40);
  const notes = {
    source: 'netlify-client-page',
    customerName: String(body.name || '').slice(0, 120),
    customerEmail: String(body.email || '').slice(0, 120),
  };

  const response = await fetch(`${RAZORPAY_API_BASE_URL}/orders`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`).toString(
        'base64'
      )}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      amount: amountPaise,
      currency: 'INR',
      receipt,
      notes,
    }),
  });

  const text = await response.text();
  let order;
  try {
    order = text ? JSON.parse(text) : {};
  } catch {
    order = { raw: text };
  }

  if (!response.ok) {
    return json(response.status, {
      error: {
        message: order.error?.description || 'Razorpay order creation failed.',
        code: order.error?.code,
      },
    });
  }

  return json(200, {
    provider: 'razorpay',
    keyId: process.env.RAZORPAY_KEY_ID,
    orderId: order.id,
    amount: order.amount,
    currency: order.currency,
    receipt: order.receipt,
    merchantName: process.env.MERCHANT_DISPLAY_NAME || 'Secure Payment Demo',
  });
}

