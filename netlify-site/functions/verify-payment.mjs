import { constantTimeEqualHex, hmacHex, json, parseJson } from './_utils.mjs';

export async function handler(event) {
  if (event.httpMethod !== 'POST') {
    return json(405, { error: { message: 'Method not allowed.' } });
  }

  const body = parseJson(event.body);
  if (!body) {
    return json(400, { error: { message: 'Request body must be JSON.' } });
  }

  const orderId = body.razorpay_order_id;
  const paymentId = body.razorpay_payment_id;
  const signature = body.razorpay_signature;

  if (!process.env.RAZORPAY_KEY_SECRET) {
    return json(500, { error: { message: 'RAZORPAY_KEY_SECRET is not configured.' } });
  }

  if (!orderId || !paymentId || !signature) {
    return json(400, { error: { message: 'Missing Razorpay verification fields.' } });
  }

  const expected = hmacHex(process.env.RAZORPAY_KEY_SECRET, `${orderId}|${paymentId}`);
  if (!constantTimeEqualHex(signature, expected)) {
    return json(401, { error: { message: 'Payment signature verification failed.' } });
  }

  return json(200, {
    ok: true,
    status: 'verified',
    orderId,
    paymentId,
  });
}

