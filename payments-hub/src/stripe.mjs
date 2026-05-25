import { badRequest, upstreamError } from './errors.mjs';

const STRIPE_API_BASE_URL = 'https://api.stripe.com/v1';

export async function createCheckoutSession(config, payment, checkout, idempotencyKey) {
  const metadata = {
    paymentId: payment.id,
    siteId: payment.siteId,
    orderId: payment.orderId,
    ...checkout.metadata,
  };

  const params = {
    mode: checkout.mode,
    success_url: checkout.successUrl,
    cancel_url: checkout.cancelUrl,
    client_reference_id: `${payment.siteId}:${payment.orderId}`,
    customer_email: checkout.customer.email,
    line_items: checkout.items.map((item) => toStripeLineItem(item)),
    metadata,
    allow_promotion_codes: checkout.allowPromotionCodes || undefined,
    automatic_tax: checkout.automaticTax ? { enabled: true } : undefined,
    billing_address_collection: checkout.billingAddressCollection,
    shipping_address_collection: checkout.shippingCountries
      ? { allowed_countries: checkout.shippingCountries }
      : undefined,
    payment_intent_data:
      checkout.mode === 'payment'
        ? {
            metadata,
            statement_descriptor_suffix: checkout.statementDescriptorSuffix,
          }
        : undefined,
    subscription_data:
      checkout.mode === 'subscription'
        ? {
            metadata,
          }
        : undefined,
  };

  return stripeRequest(config, 'POST', '/checkout/sessions', params, idempotencyKey);
}

export async function createRefund(config, payment, refundRequest, idempotencyKey) {
  if (!payment.stripePaymentIntentId) {
    throw badRequest('PAYMENT_INTENT_MISSING', 'This payment does not have a Stripe payment intent yet.');
  }

  const params = {
    payment_intent: payment.stripePaymentIntentId,
    amount: refundRequest.amount,
    reason: refundRequest.reason,
    metadata: {
      paymentId: payment.id,
      siteId: payment.siteId,
      orderId: payment.orderId,
      ...refundRequest.metadata,
    },
  };

  return stripeRequest(config, 'POST', '/refunds', params, idempotencyKey);
}

function toStripeLineItem(item) {
  if (item.priceId) {
    return {
      price: item.priceId,
      quantity: item.quantity,
    };
  }

  return {
    price_data: {
      currency: item.currency,
      product_data: {
        name: item.name,
        description: item.description,
      },
      unit_amount: item.unitAmount,
    },
    quantity: item.quantity,
  };
}

async function stripeRequest(config, method, path, params, idempotencyKey) {
  if (!config.stripe.secretKey) {
    throw badRequest('STRIPE_SECRET_KEY_MISSING', 'STRIPE_SECRET_KEY is not configured.');
  }

  const headers = {
    authorization: `Bearer ${config.stripe.secretKey}`,
    'content-type': 'application/x-www-form-urlencoded',
  };

  if (config.stripe.apiVersion) {
    headers['stripe-version'] = config.stripe.apiVersion;
  }

  if (idempotencyKey) {
    headers['idempotency-key'] = idempotencyKey;
  }

  const response = await fetch(`${STRIPE_API_BASE_URL}${path}`, {
    method,
    headers,
    body: encodeStripeForm(params),
  });

  const text = await response.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text };
  }

  if (!response.ok) {
    throw upstreamError('STRIPE_REQUEST_FAILED', 'Stripe API request failed.', {
      status: response.status,
      requestId: response.headers.get('request-id') || undefined,
      stripeCode: json.error?.code,
      stripeType: json.error?.type,
      message: json.error?.message || 'Unknown Stripe error.',
    });
  }

  return json;
}

export function encodeStripeForm(value) {
  const form = new URLSearchParams();
  appendFormValue(form, '', value);
  return form.toString();
}

function appendFormValue(form, key, value) {
  if (value === undefined || value === null || value === '') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => appendFormValue(form, `${key}[${index}]`, item));
    return;
  }

  if (typeof value === 'object') {
    for (const [childKey, childValue] of Object.entries(value)) {
      appendFormValue(form, key ? `${key}[${childKey}]` : childKey, childValue);
    }
    return;
  }

  form.append(key, String(value));
}
