# outbid-receipt-verify

Zero-dependency verifier for Outbid-Receipt v1, the seller-signed delivery receipt on x402-paid HTTP answers.
Node 20+ (`node:crypto` only; `engines` is `>=20`). Spec: https://github.com/twzrd-sol/outbid-receipt/blob/main/SPEC.md.
Reference code and test vectors: https://github.com/twzrd-sol/outbid-receipt

Exports: `DOMAIN`, `KEYS_PATH`, `KEYS`, `REQUEST_KEYS`, `sha256Hex`, `canonicalPayload`, `signReceipt`, `verifyReceipt`, `sseTrailer`, `splitSseReceipt`, `withReceiptVerification`.

Pin the issuer's keys once from `<iss>/.well-known/outbid-receipt-keys.json` (outbid: https://outbid.sh/.well-known/outbid-receipt-keys.json), then verify each receipt offline
against your own request bytes, response bytes, payer, the payment you signed and your age limit. A value you do
not supply is refused (`missing_expectation:<name>`), never passed. No receipt means "no verified receipt",
never "not paid". The `fetch` wrapper reads `Outbid-Receipt` and falls back to `X-Outbid-Receipt` (alias until
2027-01-31).

License: Apache-2.0
