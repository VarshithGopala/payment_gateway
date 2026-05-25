import { badRequest, forbidden } from './errors.mjs';

const MAX_AMOUNT = 99_999_999;
const MAX_ITEMS = 100;

export function validateCheckoutRequest(body, site, config) {
  assertObject(body, 'body');

  if (body.siteId && body.siteId !== site.id) {
    throw forbidden('SITE_ID_MISMATCH', 'The body siteId must match x-site-id.');
  }

  const mode = body.mode || 'payment';
  if (!['payment', 'subscription'].includes(mode)) {
    throw badRequest('INVALID_MODE', 'mode must be payment or subscription.');
  }

  const orderId = requireString(body.orderId, 'orderId', 1, 120);
  const currency = normalizeCurrency(body.currency || 'usd');
  const items = validateItems(body.items, currency, mode);

  const successUrl = validateSiteUrl(body.successUrl, site, config, 'successUrl');
  const cancelUrl = validateSiteUrl(body.cancelUrl, site, config, 'cancelUrl');

  const metadata = validateMetadata(body.metadata || {});
  const customer = validateCustomer(body.customer || {});
  const billingAddressCollection = validateBillingAddressCollection(body.billingAddressCollection);
  const shippingCountries = validateShippingCountries(body.shippingCountries);
  const statementDescriptorSuffix = optionalString(body.statementDescriptorSuffix, 'statementDescriptorSuffix', 1, 22);

  return {
    mode,
    orderId,
    currency,
    items,
    successUrl,
    cancelUrl,
    customer,
    metadata,
    allowPromotionCodes: body.allowPromotionCodes === true,
    automaticTax: body.automaticTax === true,
    billingAddressCollection,
    shippingCountries,
    statementDescriptorSuffix,
    totalAmount: calculateTotalAmount(items),
  };
}

export function validateRefundRequest(body) {
  assertObject(body, 'body');
  const paymentId = requireString(body.paymentId, 'paymentId', 1, 80);
  const reason = body.reason || 'requested_by_customer';

  if (!['duplicate', 'fraudulent', 'requested_by_customer'].includes(reason)) {
    throw badRequest('INVALID_REFUND_REASON', 'reason must be duplicate, fraudulent, or requested_by_customer.');
  }

  let amount = undefined;
  if (body.amount !== undefined) {
    amount = requirePositiveInteger(body.amount, 'amount', MAX_AMOUNT);
  }

  return {
    paymentId,
    amount,
    reason,
    metadata: validateMetadata(body.metadata || {}),
  };
}

function validateItems(items, defaultCurrency, mode) {
  if (!Array.isArray(items) || items.length === 0) {
    throw badRequest('INVALID_ITEMS', 'items must be a non-empty array.');
  }

  if (items.length > MAX_ITEMS) {
    throw badRequest('TOO_MANY_ITEMS', `items cannot contain more than ${MAX_ITEMS} entries.`);
  }

  return items.map((item, index) => {
    assertObject(item, `items[${index}]`);
    const quantity = requirePositiveInteger(item.quantity || 1, `items[${index}].quantity`, 999);

    if (item.priceId) {
      return {
        priceId: requireString(item.priceId, `items[${index}].priceId`, 1, 200),
        quantity,
      };
    }

    if (mode === 'subscription') {
      throw badRequest(
        'SUBSCRIPTION_REQUIRES_PRICE_ID',
        'subscription mode requires pre-created Stripe priceId values.'
      );
    }

    return {
      name: requireString(item.name, `items[${index}].name`, 1, 120),
      description: optionalString(item.description, `items[${index}].description`, 0, 500),
      unitAmount: requirePositiveInteger(item.unitAmount, `items[${index}].unitAmount`, MAX_AMOUNT),
      currency: normalizeCurrency(item.currency || defaultCurrency),
      quantity,
    };
  });
}

function calculateTotalAmount(items) {
  if (items.some((item) => item.priceId)) {
    return null;
  }

  return items.reduce((total, item) => total + item.unitAmount * item.quantity, 0);
}

function validateMetadata(metadata) {
  assertObject(metadata, 'metadata');
  const entries = Object.entries(metadata);
  if (entries.length > 20) {
    throw badRequest('METADATA_TOO_LARGE', 'metadata can contain at most 20 keys.');
  }

  return entries.reduce((result, [key, value]) => {
    if (!/^[a-zA-Z0-9_.-]{1,40}$/.test(key)) {
      throw badRequest('METADATA_KEY_INVALID', 'metadata keys must be 1-40 safe characters.');
    }

    if (!['string', 'number', 'boolean'].includes(typeof value)) {
      throw badRequest('METADATA_VALUE_INVALID', 'metadata values must be strings, numbers, or booleans.');
    }

    result[key] = String(value).slice(0, 500);
    return result;
  }, {});
}

function validateCustomer(customer) {
  assertObject(customer, 'customer');

  if (!customer.email) {
    return {};
  }

  const email = requireString(customer.email, 'customer.email', 3, 800);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw badRequest('INVALID_CUSTOMER_EMAIL', 'customer.email must be a valid email address.');
  }

  return { email };
}

function validateBillingAddressCollection(value) {
  if (value === undefined) {
    return undefined;
  }
  if (!['auto', 'required'].includes(value)) {
    throw badRequest('INVALID_BILLING_ADDRESS_COLLECTION', 'billingAddressCollection must be auto or required.');
  }
  return value;
}

function validateShippingCountries(value) {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.length === 0 || value.length > 50) {
    throw badRequest('INVALID_SHIPPING_COUNTRIES', 'shippingCountries must be an array of 1-50 country codes.');
  }
  return value.map((country) => {
    const normalized = requireString(country, 'shippingCountries[]', 2, 2).toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalized)) {
      throw badRequest('INVALID_SHIPPING_COUNTRY', 'shippingCountries entries must be ISO 3166-1 alpha-2 codes.');
    }
    return normalized;
  });
}

function validateSiteUrl(value, site, config, field) {
  const rawUrl = requireString(value, field, 1, 2000);
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw badRequest('INVALID_URL', `${field} must be a valid URL.`);
  }

  const origin = parsed.origin;
  if (!site.allowedOrigins.includes(origin)) {
    throw forbidden('URL_ORIGIN_NOT_ALLOWED', `${field} origin is not allowed for this site.`);
  }

  const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (config.isProduction && parsed.protocol !== 'https:') {
    throw forbidden('URL_REQUIRES_HTTPS', `${field} must use https:// in production.`);
  }
  if (!config.isProduction && parsed.protocol !== 'https:' && !isLocalhost) {
    throw forbidden('URL_REQUIRES_HTTPS', `${field} must use https:// unless it is localhost in development.`);
  }

  return parsed.toString();
}

function normalizeCurrency(value) {
  const currency = requireString(value, 'currency', 3, 3).toLowerCase();
  if (!/^[a-z]{3}$/.test(currency)) {
    throw badRequest('INVALID_CURRENCY', 'currency must be a 3-letter ISO currency code.');
  }
  return currency;
}

function assertObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw badRequest('INVALID_OBJECT', `${field} must be an object.`);
  }
}

function requireString(value, field, minLength, maxLength) {
  if (typeof value !== 'string') {
    throw badRequest('INVALID_STRING', `${field} must be a string.`);
  }

  const trimmed = value.trim();
  if (trimmed.length < minLength || trimmed.length > maxLength) {
    throw badRequest('INVALID_STRING_LENGTH', `${field} must be ${minLength}-${maxLength} characters.`);
  }

  return trimmed;
}

function optionalString(value, field, minLength, maxLength) {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  return requireString(value, field, minLength, maxLength);
}

function requirePositiveInteger(value, field, maxValue) {
  if (!Number.isInteger(value) || value <= 0 || value > maxValue) {
    throw badRequest('INVALID_INTEGER', `${field} must be an integer between 1 and ${maxValue}.`);
  }
  return value;
}
