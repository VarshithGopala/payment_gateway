# Netlify Deployment

This folder includes a Netlify-ready payment test app:

- Client page: `/` or `/client`
- Admin page: `/admin`
- Netlify Functions:
  - `/.netlify/functions/create-order`
  - `/.netlify/functions/verify-payment`
  - `/.netlify/functions/settlement-config`

## Important settlement note

Razorpay and Stripe do not let a normal website admin page send settlements to any arbitrary UPI ID
or bank account typed into a form. For real money, funds settle to the verified bank account in your
Razorpay account. If you need to pay many sellers/recipients, use Razorpay Route or Stripe Connect
with KYC and linked accounts.

The included admin page shows settlement configuration status and lets you record a local label, but
it does not store raw bank or UPI details.

## Netlify settings

Netlify will read `netlify.toml` from the repository root.

Build settings:

```text
Publish directory: netlify-site/public
Functions directory: netlify-site/functions
```

Environment variables:

```text
RAZORPAY_KEY_ID=rzp_test_...
RAZORPAY_KEY_SECRET=...
MERCHANT_DISPLAY_NAME=Your Business Name
MERCHANT_SETTLEMENT_LABEL=Verified Razorpay settlement bank account
```

Use Razorpay test keys first. When you are ready to test actual movement of money, switch to live
Razorpay keys in Netlify and make sure your Razorpay account has completed KYC and settlement bank
verification.

## GitHub + Netlify deployment

1. Create a GitHub repository.
2. Push this workspace to the repository.
3. In Netlify, choose **Add new site > Import an existing project**.
4. Pick the GitHub repository.
5. Confirm the build settings from `netlify.toml`.
6. Add the environment variables above.
7. Deploy the site.

After deploy:

```text
https://your-netlify-site.netlify.app/
https://your-netlify-site.netlify.app/admin
```

## Why I cannot complete the deploy without your login

This machine currently does not have `git`, GitHub CLI, Netlify CLI, or authenticated GitHub/Netlify
sessions available. I can deploy it once you provide access by either:

- installing/signing into Git and Netlify on this machine, or
- giving a GitHub repository URL and a Netlify auth token, or
- doing the GitHub/Netlify import steps above from your browser.
