import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';

import { badRequest } from './errors.mjs';

export function loadDotEnv(filePath = join(process.cwd(), '.env')) {
  if (!existsSync(filePath)) {
    return;
  }

  const contents = readFileSync(filePath, 'utf8');
  for (const line of contents.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const equalsIndex = trimmed.indexOf('=');
    if (equalsIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, equalsIndex).trim();
    let value = trimmed.slice(equalsIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

export function envKeyFromSiteId(siteId) {
  return siteId.toUpperCase().replace(/[^A-Z0-9]/g, '_');
}

export function splitCsv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === '') {
    return fallback;
  }
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function parseInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeBaseUrl(url) {
  return String(url || '').replace(/\/+$/, '');
}

function resolveFromCwd(pathValue) {
  if (isAbsolute(pathValue)) {
    return pathValue;
  }
  return resolve(process.cwd(), pathValue);
}

function validateSecret(name, value, isProduction) {
  if (!value) {
    throw badRequest('CONFIG_MISSING_SECRET', `${name} is required.`);
  }

  if (isProduction && value.length < 32) {
    throw badRequest('CONFIG_WEAK_SECRET', `${name} must be at least 32 characters in production.`);
  }
}

function expandUrlTemplate(value, publicBaseUrl) {
  return String(value || '').replaceAll('{PUBLIC_BASE_URL}', publicBaseUrl);
}

function parseSites(env, isProduction, publicBaseUrl) {
  const siteIds = splitCsv(env.SITES);
  if (siteIds.length === 0) {
    throw badRequest('CONFIG_NO_SITES', 'SITES must contain at least one site ID.');
  }

  const sites = new Map();

  for (const siteId of siteIds) {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$/.test(siteId)) {
      throw badRequest(
        'CONFIG_INVALID_SITE_ID',
        `Invalid site ID "${siteId}". Use letters, numbers, underscores, and dashes.`
      );
    }

    const envKey = envKeyFromSiteId(siteId);
    const prefix = `SITE_${envKey}_`;
    const secret = env[`${prefix}SECRET`];
    const fulfillmentSecret = env[`${prefix}FULFILLMENT_SECRET`] || '';
    const allowedOrigins = splitCsv(expandUrlTemplate(env[`${prefix}ORIGINS`], publicBaseUrl));

    validateSecret(`${prefix}SECRET`, secret, isProduction);

    if (fulfillmentSecret) {
      validateSecret(`${prefix}FULFILLMENT_SECRET`, fulfillmentSecret, isProduction);
    }

    if (allowedOrigins.length === 0) {
      throw badRequest('CONFIG_SITE_ORIGINS_MISSING', `${prefix}ORIGINS is required.`);
    }

    sites.set(siteId, {
      id: siteId,
      name: env[`${prefix}NAME`] || siteId,
      secret,
      allowedOrigins,
      fulfillmentUrl: expandUrlTemplate(env[`${prefix}FULFILLMENT_URL`], publicBaseUrl),
      fulfillmentSecret,
    });
  }

  return sites;
}

export function getConfig(env = process.env) {
  const port = parseInteger(env.PORT, 8080);
  const nodeEnv = env.NODE_ENV || 'development';
  const isProduction = nodeEnv === 'production';
  const publicBaseUrl = normalizeBaseUrl(env.PUBLIC_BASE_URL || `http://localhost:${port}`);

  if (isProduction && !publicBaseUrl.startsWith('https://')) {
    throw badRequest('CONFIG_PUBLIC_URL_HTTPS', 'PUBLIC_BASE_URL must use https:// in production.');
  }

  const provider = env.PAYMENT_PROVIDER || 'auto';
  if (!['auto', 'stripe', 'razorpay', 'mock'].includes(provider)) {
    throw badRequest('CONFIG_UNSUPPORTED_PROVIDER', 'PAYMENT_PROVIDER must be auto, stripe, razorpay, or mock.');
  }

  return {
    env: nodeEnv,
    isProduction,
    port,
    provider,
    publicBaseUrl,
    internalBaseUrl: normalizeBaseUrl(env.INTERNAL_BASE_URL || `http://127.0.0.1:${port}`),
    dataDir: resolveFromCwd(env.DATA_DIR || './data'),
    trustProxy: parseBoolean(env.TRUST_PROXY, false),
    requestSignatureToleranceSeconds: parseInteger(env.REQUEST_SIGNATURE_TOLERANCE_SECONDS, 300),
    stripeSignatureToleranceSeconds: parseInteger(env.STRIPE_SIGNATURE_TOLERANCE_SECONDS, 300),
    stripe: {
      secretKey: env.STRIPE_SECRET_KEY || '',
      webhookSecret: env.STRIPE_WEBHOOK_SECRET || '',
      apiVersion: env.STRIPE_API_VERSION || '',
    },
    razorpay: {
      keyId: env.RAZORPAY_KEY_ID || '',
      keySecret: env.RAZORPAY_KEY_SECRET || '',
      webhookSecret: env.RAZORPAY_WEBHOOK_SECRET || '',
    },
    simpleStore: {
      enabled: parseBoolean(env.STORE_ENABLED, true),
      siteId: env.STORE_SITE_ID || 'demo-store',
      name: env.STORE_NAME || 'Launch Kit Store',
      productName: env.STORE_PRODUCT_NAME || 'Website Launch Kit',
      productDescription:
        env.STORE_PRODUCT_DESCRIPTION || 'A secure starter purchase wired through your reusable payments hub.',
      productPriceCents: parseInteger(env.STORE_PRODUCT_PRICE_CENTS, 4900),
      currency: (env.STORE_CURRENCY || 'usd').toLowerCase(),
      customerEmail: env.STORE_CUSTOMER_EMAIL || 'customer@example.com',
    },
    sites: parseSites(env, isProduction, publicBaseUrl),
  };
}
