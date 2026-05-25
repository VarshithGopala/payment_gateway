import { json, razorpayConfigured, readSettlementConfig } from './_utils.mjs';

export async function handler() {
  return json(200, {
    razorpayConfigured: razorpayConfigured(),
    settlement: readSettlementConfig(),
    requiredNetlifyEnv: [
      'RAZORPAY_KEY_ID',
      'RAZORPAY_KEY_SECRET',
      'MERCHANT_DISPLAY_NAME',
      'MERCHANT_SETTLEMENT_LABEL',
    ],
  });
}

