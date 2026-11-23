# Outbid-Receipt v1: seller-signed delivery receipt (rev B)

Status: v1 (rev B). Deployed in production on outbid.sh since 2026-11-23T02:42:23Z. Keys at
`https://outbid.sh/.well-known/outbid-receipt-keys.json`. Rev A was never issued, so rev B is still `v1`.

Names (decided 2026-11-23): the header is `Outbid-Receipt` and the key path is
`/.well-known/outbid-receipt-keys.json`. The token format, the signing domain `OUTBID:DELIVERY_RECEIPT_V1`, the
SSE trailer `: outbid-receipt=` and every verification step are unchanged by the rename.

Aliases until 2027-01-31: the issuer also sends the same token as `X-Outbid-Receipt`, the same body digest as
`X-Outbid-Body-SHA256` beside `Outbid-Body-SHA256`, and `/.well-known/receipt-keys.json` serves bytes identical
to the new key path. A verifier reads `Outbid-Receipt`
first and falls back to `X-Outbid-Receipt` only when the new header is absent. After 2027-01-31 the old header,
the old digest header and the old path are gone; do not build on them.

In this repository:

- `reference/receipt-ref.mjs`: reference signer and verifier, `node:crypto` only. `KEYS_PATH` names the key URL.
- `vectors/receipt-vectors.json`: 54 cases with their inputs and expected verdicts, for a verifier in any language.
- `vectors/receipt-fixture-live-20261123.json`: one real receipt from `https://outbid.sh`, with the key, request
  and response bytes needed to verify it.

## What it is

On a paid `200`, outbid signs one statement: this request, paid by this payer to this payee in this settlement,
was answered as this model with these bytes, at this time. The buyer checks it offline with a pinned public key
and can keep it as evidence if the answer is disputed.

Today the buyer gets two things. The facilitator's `PAYMENT-RESPONSE` proves payment and says nothing about what
was delivered. `Outbid-Body-SHA256` says what was delivered and is unsigned. The receipt joins them, and the
request, under outbid's signature.

It is not intel's V7 receipt and does not claim to be: another domain, no keccak leaf, no shared key and no
shared code. It uses the same Ed25519 primitive (raw 32-byte key, 64-byte signature), so a verifier
that has V7's `ed25519Verifies` needs no new cryptography.

## Wire format

```
Outbid-Receipt: v1.<payload_b64url>.<signature_b64url>
```

Until 2027-01-31 the same token is also sent as `X-Outbid-Receipt` (see Aliases above).

- `<payload_b64url>`: base64url (RFC 4648 section 5, no padding) of the payload text below.
- `<signature_b64url>`: base64url (no padding, 86 characters) of the 64-byte Ed25519 signature over the ASCII
  bytes of `OUTBID:DELIVERY_RECEIPT_V1.<payload_b64url>`, with `<payload_b64url>` exactly as sent.

One header. There is no key header and no key URL in a receipt: a key location that arrives with a receipt is
unauthenticated. Keys live at one fixed URL under `iss` (see Keys).

The signature covers the text as transmitted. A verifier checks it before it parses anything, and never
re-serializes the payload in order to check it.

### Payload

The payload text is a JSON object with exactly these twelve keys, in this order:

| Key | Format | Where outbid has it |
|---|---|---|
| `iss` | `https://` + lowercase host of 1 to 100 of `a-z`, `0-9`, `.`, `-`; no port, path or slash after it | the origin of the configured public base, `https://outbid.sh` (`PUBLIC_BASE_URL`). Never the request's `Host`. It is the https origin of the key URL (see Keys) |
| `kid` | 1 to 64 of `a-z`, `0-9`, `-` | the id of the signing key: `outbid-receipt-ed25519-v1` for the first |
| `issued_at` | non-negative integer, Unix seconds | the clock at signing. The format test is on the parsed number; its spelling is checked by "One spelling" |
| `request` | object with exactly `method`, `path`, `sha256`, in that order | see the next three rows |
| `request.method` | 1 to 16 uppercase letters | `POST` |
| `request.path` | `/` + up to 199 plain characters, no `?` or `#` | the route, `/v1/chat/completions`, without any query string |
| `request.sha256` | 64 lowercase hex | SHA-256 of the request body as received, taken before the body is parsed; the body can be rewritten after that |
| `network` | `eip155:` + chain id, 1 to 32 digits, no leading zero | `s.network ?? matched.network`, where `s` is the settlement result and `matched` the accepted requirement. Nothing else is signed in v1 (see When it is issued) |
| `payer` | `0x` + 40 lowercase hex | `s.payer ?? v.payer` (`v` is the verify result), lowercased; the ledger holds one address in two letter cases |
| `payee` | `0x` + 40 lowercase hex | `matched.payTo`, lowercased: the address the payer's transfer went to |
| `asset` | `0x` + 40 lowercase hex | the `asset` of the accepted requirement, lowercased: the token contract, not a symbol |
| `amount_atomic` | string of 1 to 39 decimal digits, no leading zero, so `"0"` is refused | `String(s.amount ?? matched.amount)`, in the token's smallest unit |
| `settlement_ref` | `0x` + 64 lowercase hex | `s.transaction`, lowercased: the settlement transaction hash on `network` |
| `resolved_model` | 1 to 200 plain characters | `model.id`, the catalog id that was priced and served. A paid request naming an unlisted model is refused with 409 before settlement, so this is the model the buyer named |
| `body_sha256` | 64 lowercase hex | SHA-256 of the body bytes outbid sent, after its own scrub: the value in `Outbid-Body-SHA256` |

A plain character is printable ASCII other than space, `"` and `\` (`[\x21\x23-\x5b\x5d-\x7e]`).
The request body is hashed after any `Content-Encoding` has been removed, which is what `req.body` holds.

### One spelling

Every string is made of characters that JSON writes as themselves, and the only number is a non-negative
integer. So a receipt has exactly one spelling: the keys in the order of the table, no whitespace, no escape
sequence (`/` is written `/`), and `issued_at` in plain decimal. The test vector's payload text is:

```
{"iss":"https://outbid.example","kid":"test-vector-key-1","issued_at":1795392000,"request":{"method":"POST","path":"/v1/chat/completions","sha256":"cf35857f796beccaa3b7716f390fec7134a029b4a90c7cdf2b6a619adf5043a4"},"network":"eip155:8453","payer":"0x1111111111111111111111111111111111111111","payee":"0x2222222222222222222222222222222222222222","asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","amount_atomic":"1500","settlement_ref":"0xabababababababababababababababababababababababababababababababab","resolved_model":"paid/model-a","body_sha256":"578450fb4106a716c230cdfab6fde424a157d27693ee0760471bf92cd4796ecc"}
```

After the signature holds, a verifier rebuilds this text from the parsed values and requires it to equal the
decoded payload byte for byte. That one comparison refuses a duplicate key, another key order, whitespace, an
escape and a number written another way. It needs no canonicalization library, because the text is a fixed
template. The rebuilt text is compared, never signed or verified.

Duplicate keys are rejected by this exact-match check, and by nothing else: `JSON.parse` keeps one of the two
values, so the rebuilt text cannot equal the payload. There is no separate scanner of the raw text.

There is no `ext` field. Any change to the keys or formats waits for `v2`, with domain
`OUTBID:DELIVERY_RECEIPT_V2`.

## When it is issued

Only on x402-paid `/v1/chat/completions`, when all of these hold:

1. Settlement returned success, after the commit point. A failed or unknown settlement sends
   an error and no body, so there is nothing to receipt.
2. The relayed status is 200.
3. The body hash is final: once the body is complete for a non-stream answer, at the end of a stream that finished
   normally for a stream.
4. The signing key is loaded and every field has its format. No payer or no transaction hash means no receipt;
   outbid never signs a null.

Never on a 402, a free-tier answer, a non-200, or a stream that ended by cap, error or disconnect.

v1 is EVM only: `network` starts `eip155:` and `payer`, `payee`, `asset` and `settlement_ref` are `0x` hex,
lowercased before signing. Anything else gets no receipt, and the `200`, its body and `Outbid-Body-SHA256` go
out exactly as without receipts:

- Solana, or any settlement the facilitator reports on a network that is not `eip155:`
  (access log `receipt: "skipped:not_evm"`).
- A payer or transaction that is not `0x` hex of the right length (`receipt: "bad_field:<key>"`).
- The Tempo rail: the Base accept that carries `extra.tempoSettlement` and settles through Tempo's facilitator
  (`receipt: "skipped:tempo_rail"`). Its code and test double put the Base leg in `s.transaction`,
  but as of 2026-11-23 no real Tempo settlement had confirmed that. Signing it waits for a real Tempo-paid
  settlement that shows the Base leg.

Signing never blocks or fails a paid response. With no key at boot the feature is off. If signing fails, the
response goes out without a receipt and the access-log row records the reason (`receipt: "sign_failed"`, or a
format reason such as `bad_field:settlement_ref`); a signed answer records `receipt: "signed"`. A buyer reads a
missing or refused receipt as "no verified receipt", never as "not paid", and keeps the response.

Out of scope for v1: `/v1/session/chat/completions`. There outbid relays infer-mpp. It does not settle, does
not parse the credential, and holds no payer or settlement reference. It also drops reasoning-only frames
from the stream, so infer-mpp could not sign the bytes the buyer receives either.

## Streaming

A stream's headers are flushed before its bytes exist, so a stream's receipt cannot be a header. It is the
last SSE comment, in the same final write as the digest comment outbid sends today:

```
: outbid-sha256=<64 lowercase hex> bytes=<n>
: outbid-receipt=v1.<payload_b64url>.<signature_b64url>

```

Each of the two lines ends with one `\n`, and one more `\n` ends the stream.

- `body_sha256` covers the first `n` bytes of the stream: every byte before the digest comment, as the digest
  does today. The digest line is unchanged and stays first, so existing readers keep working.
- Both lines are SSE comments, which an SSE parser ignores. A named `event: receipt` frame before `[DONE]` would
  change the hashed bytes, and the OpenAI Python SDK 2.24.0 would hand it to the caller as a chunk (read in its
  code, not run).
- The rule:

  > `body_sha256` is SHA-256 of the first n bytes of the response body, where n is the `bytes=` value. The trailer starts at byte n with `: outbid-sha256=`, and `: outbid-receipt=` follows. A missing trailer, or a `bytes=` value that differs from the bytes received before it, means unverified.

- The digest comment's hex is not compared with anything; the signed `body_sha256` decides. A trailer whose token
  is not a well-formed `v1` token is `bad_sse_trailer`.
- With receipts off the final write is the digest comment alone, byte for byte as before.
- A buyer that wants the receipt keeps the raw stream bytes. It finds the last `: outbid-receipt=` line,
  requires the digest comment directly before it and `n` to equal the number of bytes before that comment, and
  verifies the token against those `n` bytes. The signed `body_sha256` decides; the digest comment is unsigned.

## Keys

- A new Ed25519 key pair made for this only. It is not a wallet key (it can move no funds), not the CDP API key
  and not intel's receipt key.
- The key URL is `<iss>/.well-known/outbid-receipt-keys.json`, one path everywhere: `KEYS_PATH` in `receipt-ref.mjs`,
  `RECEIPT_KEYS_PATH` in outbid's `src/receipt-v1.mjs` (the route in `src/server.js`), and `skill/SKILL.md`.
  Until 2027-01-31 `<iss>/.well-known/receipt-keys.json` serves identical bytes as an alias. The file's `issuer` equals `iss`, and `iss`
  equals the https origin the file was fetched from: a verifier refuses a file whose `issuer` is anything else,
  and pins `iss` with the keys. outbid serves it while receipts are on and answers `404` while they are off:

```json
{ "issuer": "https://outbid.sh",
  "keys": [ { "kid": "outbid-receipt-ed25519-v1", "kty": "OKP", "crv": "Ed25519", "x": "<base64url, 32 bytes>",
              "not_before": 1795392000, "retired_at": null } ] }
```

  `kid`, `kty`, `crv` and `x` are the JWK members of an Ed25519 public key (RFC 8037). `not_before` and
  `retired_at` are Unix seconds; `retired_at` is `null` while the key signs.
- Pinning: a verifier copies the entries it trusts into its own configuration, with the issuer, from this file
  over TLS at setup or from `skill/SKILL.md`. It never fetches a key because a receipt arrived, and nothing in a
  receipt says where keys are.
- `kid`: the verifier checks the signature under its pinned keys, then requires the payload's `kid` to equal the
  `kid` of the key that verified. Choosing the key by `kid` first would mean parsing before verifying.
- Validity: a receipt whose `issued_at` is before the key's `not_before`, or at or after its `retired_at`, is refused.
- Rotation: add the new key, switch signing, set `retired_at` on the old key, and leave it listed so earlier
  receipts still verify.
- The private key is loaded once at boot and never logged. outbid reads `OUTBID_RECEIPT_SIGNING_KEY` from its
  environment: the 32-byte Ed25519 seed as 43 base64url characters (the JWK `d`). Optional:
  `OUTBID_RECEIPT_KEY_ID` (default `outbid-receipt-ed25519-v1`) and `OUTBID_RECEIPT_NOT_BEFORE` (Unix seconds,
  published as `not_before`; `null` when unset). Unset key: receipts off, nothing logged. Malformed key, key id,
  `not_before` or issuer: off, with one log line `{"event":"receipts_off","reason":...}`. Generating the key
  and setting it is an operator step.

## Verifying

The steps run in this order and the first failure is the verdict. The names in brackets are the reasons the
reference and the vectors use.

1. Token shape [`bad_token`]. A string of at most 6200 characters in three parts separated by `.`; the first is
   `v1`; the payload is 1 to 6000 base64url characters and the signature is 86; decoding each and encoding it
   again gives the same text.
2. Signature [`bad_signature`]. The pinned keys come first [`bad_pinned_keys`: none, or an entry that is not an
   Ed25519 JWK with a valid `kid` and a 43-character `x`]. Ed25519 over the ASCII bytes of `OUTBID:DELIVERY_RECEIPT_V1.<payload_b64url>`
   under one of the pinned keys. Nothing is parsed before this passes.
3. One reading. The decoded payload parses as a JSON object [`bad_json`]. It has exactly the twelve keys, and
   `request` exactly its three [`bad_keys`]. Every value has its format [`bad_field:<key>`, for example
   `bad_field:body_sha256` or `bad_field:request.sha256`]. The text is the one spelling [`not_canonical`].
   The format test is a pattern match, so a `body_sha256` that is not 64 lowercase hex is refused here and never
   reaches a byte comparison that could throw. Formats are tested in the order of the table, `request`'s members
   after the top-level keys, and the first failure names the reason. `issued_at` is tested as the parsed number,
   so `1795392000.0` passes here and fails at `not_canonical`.
4. Issuer and key. `kid` equals the verifying key's [`mismatch:kid`]. `iss` equals the issuer the keys were
   pinned for [`mismatch:iss`]; a pinned issuer that is not itself an https origin in the `iss` format is
   [`missing_expectation:iss`]. `issued_at` is inside the key's validity [`key_not_valid_at_issued_at`].
5. What the buyer knows [`mismatch:<key>`], compared in this order:
   - `body_sha256` with the SHA-256 of the response bytes received (for a stream, the first `n` bytes);
   - `request.method`, `request.path` and `request.sha256` with the request it sent;
   - `network`, `payer`, `payee`, `asset` and `amount_atomic` with its paying address and the payment requirement it signed;
   - `settlement_ref` with the transaction in `PAYMENT-RESPONSE`, or found on chain;
   - `resolved_model` with the `model` it named in the request, exactly. There is no "requested model" to fall back on.

   The `mismatch:` names are `body_sha256`, `request.method`, `request.path`, `request.sha256`, `network`,
   `payer`, `payee`, `asset`, `amount_atomic`, `settlement_ref`, `resolved_model`.
   A value the caller does not supply is [`missing_expectation:<name>`], never a pass. The names, checked in this
   order before any comparison: `body`, `request_body`, `method`, `path`, `network`, `payer`, `payee`,
   `asset`, `amount_atomic`, `settlement_ref`, `model`, `max_age_seconds`, `now_seconds`. Addresses and hashes the
   buyer holds are lowercased before the comparison, because they are hex. Nothing else is normalized.
6. Age. `issued_at` more than 300 seconds ahead of the caller's clock is [`issued_in_future`]; older than the
   caller's own limit, strictly, is [`too_old`] (exactly at the limit passes).

An exception inside the verifier is [`verifier_error`]; none is expected.

For a stream, splitting the trailer comes first: [`no_receipt`] when the stream has no `: outbid-receipt=` line,
[`bad_sse_trailer`] when it has one and the two comments are not exactly as above.

A verifier never throws on a receipt: every outcome is a verdict. `verifyReceipt()` and `splitSseReceipt()` in
`receipt-ref.mjs` do all of this.

## Test vectors

`vectors/receipt-vectors.json`. TEST KEYS ONLY: each private seed is the SHA-256 of an ASCII sentence given in the file, so
it is public by construction, and the issuer is the reserved name `https://outbid.example`.

The valid non-stream receipt:

- Public key `x`: `KQjFByQqnIFQVo8QNM6MA199x9gLQRR1-WQl2cqdfoE` (kid `test-vector-key-1`)
- Request body: `{"model":"paid/model-a","messages":[{"role":"user","content":"Say ok."}]}`
- Response body: `{"id":"chatcmpl-test","object":"chat.completion","model":"paid/model-a","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`
- Payload text: as shown under "One spelling"
- Header value (917 bytes):

```
v1.eyJpc3MiOiJodHRwczovL291dGJpZC5leGFtcGxlIiwia2lkIjoidGVzdC12ZWN0b3Ita2V5LTEiLCJpc3N1ZWRfYXQiOjE3OTUzOTIwMDAsInJlcXVlc3QiOnsibWV0aG9kIjoiUE9TVCIsInBhdGgiOiIvdjEvY2hhdC9jb21wbGV0aW9ucyIsInNoYTI1NiI6ImNmMzU4NTdmNzk2YmVjY2FhM2I3NzE2ZjM5MGZlYzcxMzRhMDI5YjRhOTBjN2NkZjJiNmE2MTlhZGY1MDQzYTQifSwibmV0d29yayI6ImVpcDE1NTo4NDUzIiwicGF5ZXIiOiIweDExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJwYXllZSI6IjB4MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiIsImFzc2V0IjoiMHg4MzM1ODlmY2Q2ZWRiNmUwOGY0YzdjMzJkNGY3MWI1NGJkYTAyOTEzIiwiYW1vdW50X2F0b21pYyI6IjE1MDAiLCJzZXR0bGVtZW50X3JlZiI6IjB4YWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYiIsInJlc29sdmVkX21vZGVsIjoicGFpZC9tb2RlbC1hIiwiYm9keV9zaGEyNTYiOiI1Nzg0NTBmYjQxMDZhNzE2YzIzMGNkZmFiNmZkZTQyNGExNTdkMjc2OTNlZTA3NjA0NzFiZjkyY2Q0Nzk2ZWNjIn0.0S2adC4dhNMcBcsmR_Dn5xbmyOdHP5UfgM2ylrKHVTEzoRqI1OYQX8sgQ9HsP908V6pY7uIGsKV1ePlRjPUvAw
```

The valid stream is `sse.stream_utf8` in the file: a 554-byte body, then the trailer.

The 54 cases:

| What is wrong | Cases | Verdict |
|---|---|---|
| Nothing | non-stream; stream; second of two pinned keys; exactly at the age limit; buyer holds its hex in another letter case | ok (5) |
| Another payload text under a valid signature: pretty-printed, reordered, a duplicate key, a respelled number, one changed character. Also one changed signature character, the wrong pinned key, a signature made without the domain or under another | `bad_signature` (9) |
| The token says `v2`; a signature whose last character has unused bits set | `bad_token` (2) |
| Signed by the pinned key, but spelled another way: duplicate key, reordered, pretty-printed, respelled number, an escaped character | `not_canonical` (5) |
| Signed with an unknown key, a missing key, or an unknown key inside `request` | `bad_keys` (3) |
| Signed with a non-hex `body_sha256`, an uppercase hash, a mixed-case payer, a string `issued_at`, `USDC` as the asset, or a prefixed settlement reference | `bad_field:...` (6) |
| Signed text that is not a JSON object | `bad_json` (2) |
| A real receipt for something else: another model than the buyer named; another body, request, path, network, payer, payee, amount or settlement; another issuer; a `kid` naming another pinned key | `mismatch:...` (12) |
| The caller supplies no model to compare with | `missing_expectation:model` (1) |
| Too old; issued in the future; key retired; key not yet valid | `too_old`, `issued_in_future`, `key_not_valid_at_issued_at` (4) |
| Stream with only today's digest comment, or with the receipt as a named event | `no_receipt` (2) |
| Stream with a wrong byte count, the two comments in the other order, or cut inside the receipt | `bad_sse_trailer` (3) |

One stream case, a changed body character, is among the `mismatch` cases. The generator also sends the reference
31 malformed inputs (wrong types, empty, oversized); none throws.

Run on Node v24.22.1. Cross-checked in Python 3 with `cryptography` 46.0.5: both valid signatures verify, both
hashes match, and the payload text built with one format string equals the signed text. A verifier written in
Python from this text and the vectors alone gets 54 of 54. outbid's `test/receipt-v1.test.js` runs all 54
against `src/receipt-v1.mjs` and reproduces both tokens byte for byte.

## What it proves, and what it does not

It proves that the holder of outbid's receipt key stated: this request, paid by this payer to this payee with
this amount in this transaction, was answered as this model with these bytes at this time.

It does not prove:

- that the upstream really ran that model. It is outbid's statement, and the point is that outbid is answerable for it.
- that the bytes arrived. A non-stream receipt is signed before the body is written.
- that the payment happened. That is on chain under `network` and `settlement_ref`; the receipt says which payment the delivery belongs to.
- what was asked, to someone who does not have the request body. Only its hash is signed.

## Implementation notes (outbid)

No dependency is added.

- `src/receipt-v1.mjs`: a port of `receipt-ref.mjs` plus `loadReceiptSigner(env, { base, log })`, which
  returns null (off) or `{ keys(), sign(fields) }` with `iss` and `kid` filled in.
- The server builds the signer once, `iss` = the origin of `PUBLIC_BASE_URL` (else `https://outbid.sh`), and
  serves `GET /.well-known/outbid-receipt-keys.json` (CORS `*`, `max-age=300`; `404` while off), and the same
  bytes at `/.well-known/receipt-keys.json` until 2027-01-31.
- Only the settled relay gets a receipt, after a successful settle; the scope rules above live there.
- The request bytes are kept before the parse and any rewrite; the relay signs on a `200` only, sets
  `Outbid-Receipt` (and the alias `X-Outbid-Receipt` until 2027-01-31) after `Outbid-Body-SHA256` (and its alias
  `X-Outbid-Body-SHA256`), or adds the trailer line on a stream that finished normally; all four names are in the
  CORS expose list of every such response.
- `skill/SKILL.md`: a "Delivery receipts (v1)" paragraph. The OpenAPI template is unchanged.
- Tests: the 54 vectors and token reproduction; loader off and malformed cases, seed never
  logged; Base-paid JSON 200 and stream receipts verified against the bytes received and the 402's accept;
  `solana:` settlement, a non-hash settlement reference, and the Tempo rail get none with the `200` intact;
  no key: paid answer, digest header and stream trailer as before, key file `404`.

## Not checked

- The Tempo rail on a real settlement (see When it is issued); it is skipped until then.
- `asset` from a live facilitator: the tests take it from the 402's `accepts[]`, as a buyer would.
- A compressed request body end to end.

## Open questions

1. Signing the Tempo rail once a real Tempo-paid settlement shows its Base leg.
