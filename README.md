# Outbid-Receipt v1

A seller-signed delivery receipt for x402-paid HTTP answers. The header is `Outbid-Receipt`
and the key path is `/.well-known/outbid-receipt-keys.json`; the older names work as aliases until 2027-01-31
(see the note at the end).

## What a receipt proves

On a paid `200`, the issuer signs one statement with Ed25519: this request (method, path, SHA-256 of the request
body), paid by this payer to this payee, for this amount of this asset, in this settlement transaction on this
network, was answered as this model with these response bytes (SHA-256), at this time.

A buyer checks it offline against a public key it pinned in advance, and can keep it as evidence if the answer
is disputed.

## What it does not prove

- That the upstream really ran the named model. The receipt is the issuer's statement, and the issuer is
  answerable for it.
- That the bytes arrived. A non-stream receipt is signed before the body is written.
- That the payment happened. That is on chain under `network` and `settlement_ref`; the receipt says which
  payment the delivery belongs to.
- What was asked, to someone who does not hold the request body. Only its hash is signed.
- Anything about a missing receipt. No receipt, or a refused one, means "no verified receipt", never "not paid".

## How to verify

1. Pin keys once, at setup: copy the entries you trust from `<iss>/.well-known/outbid-receipt-keys.json` over TLS into
   your own configuration, together with `iss`. Never fetch keys because a receipt arrived.
2. JSON answers carry the token in the `Outbid-Receipt` response header (read it first; fall back to
   `X-Outbid-Receipt` only when it is absent, see Aliases). Streams carry it as the last SSE
   comment, `: outbid-receipt=v1....`, directly after the `: outbid-sha256=<hex> bytes=<n>` comment; the signed
   body is the first `n` bytes of the stream.
3. Verify the signature over `OUTBID:DELIVERY_RECEIPT_V1.<payload_b64url>` before parsing anything, then the one
   spelling of the payload, the issuer and key validity, then every field against what you know: your request
   bytes, the response bytes, your payer address, the payment requirement you signed (payee, asset, amount), the
   settlement transaction, the model you named, and your own age limit. A value you do not supply is refused as
   `missing_expectation:<name>`, never passed.

The full rules and reason names are in [SPEC.md](SPEC.md). `reference/receipt-ref.mjs` is a reference signer and
verifier using `node:crypto` only:

```js
import { verifyReceipt, splitSseReceipt } from './reference/receipt-ref.mjs';
const r = verifyReceipt(token, { keys, iss, expect, max_age_seconds: 300 });
// { ok: true, receipt, kid } or { ok: false, reason }
```

A zero-dependency npm verifier with a `fetch` wrapper ships as `outbid-receipt-verify` (https://www.npmjs.com/package/outbid-receipt-verify).

## Test vectors

- `vectors/receipt-vectors.json`: 54 cases with inputs and expected verdicts, for a verifier in any language.
  TEST KEYS ONLY: each private seed is the SHA-256 of a sentence given in the file, so it is public by
  construction. Never pin these keys. The issuer is the reserved name `https://outbid.example`.
- `vectors/receipt-fixture-live-20261123.json`: one real receipt from `https://outbid.sh`, 2026-11-23T04:40:51Z,
  with the key, request and response bytes needed to verify it. It is a house payment: 0.001 USDC on Base paid
  by the issuer's own wallet to test the feature. It is not customer traffic and not revenue.

## Links

- Spec: [SPEC.md](SPEC.md)
- Key file: https://outbid.sh/.well-known/outbid-receipt-keys.json
- npm package: https://www.npmjs.com/package/outbid-receipt-verify
- Issue tracker: https://github.com/twzrd-sol/outbid-receipt/issues

## License

Apache-2.0, see [LICENSE](LICENSE).

## Aliases until 2027-01-31

Names were decided on 2026-11-23: header `Outbid-Receipt`, key path `/.well-known/outbid-receipt-keys.json`.
Until 2027-01-31 the issuer also sends the same token as `X-Outbid-Receipt`, the same body digest as
`X-Outbid-Body-SHA256` beside `Outbid-Body-SHA256`, and `/.well-known/receipt-keys.json` serves bytes identical to
the new key path. After that date both old names are
gone. The token format, the signing domain `OUTBID:DELIVERY_RECEIPT_V1`, the SSE trailer `: outbid-receipt=` and
the key id are the same under either name. The test vectors name `Outbid-Receipt`; only their descriptions changed in
the rename, and every token and verdict is the same because the header name is not signed.
