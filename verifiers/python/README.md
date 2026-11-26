# Outbid-Receipt v1 - independent Python verifier

Clean-room verifier for the Outbid-Receipt v1 (rev B) seller-signed delivery receipt. Built from
`SPEC.md` alone; the vectors were used only afterwards, to test it. No reference implementation, no other
repository and no network were consulted.

## Requirements

- Python 3.10+
- `cryptography` (Ed25519 only; tested with 50.x). Nothing else third-party.

## Run the vectors

From the repository root:

```
python3 verifiers/python/test_vectors.py            # default dir: ../../vectors relative to this file
python3 -I verifiers/python/test_vectors.py
OUTBID_VECTORS_DIR=/path/to/vectors python3 verifiers/python/test_vectors.py
python3 verifiers/python/test_vectors.py /path/to/vectors
```

Prints one line per vector file, any `MISMATCH` lines, then `PASS n/n` (exit 0) or `FAIL k/n` (exit 1).
Files with `defaults` + `cases` run as case files; a file with `token` + `result` runs as a single live
fixture, plus four negative controls derived from it (tampered signature, other body, other model, too old).

## Library

```python
from outbid_receipt_verify import verify_receipt, verify_stream, split_sse_receipt, receipt_from_headers
v = verify_receipt(token, keys=pinned_keys, iss="https://outbid.sh",
                   expect={"body": resp_bytes, "request_body": req_bytes, "method": "POST",
                           "path": "/v1/chat/completions", "network": "eip155:8453",
                           "payer": "0x..", "payee": "0x..", "asset": "0x..",
                           "amount_atomic": "1000", "settlement_ref": "0x..", "model": "paid/..."},
                   max_age_seconds=900, now_seconds=time.time())
v.ok, v.reason, v.kid, v.payload
```

`verify_stream(raw_sse_bytes, ...)` splits the trailer and verifies against the first `n` bytes.
Nothing raises on a receipt; every outcome is a `Verdict`. Reasons are the spec's bracketed names;
any reason starting `nonnormative:` is this verifier's own (see `AMBIGUITIES.md`).

## CLI

```
python3 outbid_receipt_verify.py --keys keys.json --iss https://outbid.sh --token v1.... \
  --body-file resp.bin --request-body-file req.bin --method POST --path /v1/chat/completions \
  --network eip155:8453 --payer 0x.. --payee 0x.. --asset 0x.. --amount-atomic 1000 \
  --settlement-ref 0x.. --model paid/... --max-age-seconds 900 [--now-seconds N]
```

`--keys` takes a key list or a key file (`{"issuer":..., "keys":[...]}`); `--stream-file` replaces
`--token`/`--body-file` for SSE. Exit 0 on ok, 1 otherwise; the verdict is printed as JSON.

## What it checks (SPEC.md "Verifying", in order; first failure wins)

1. Token shape (`bad_token`): str, <= 6200 chars, `v1.<p>.<s>`, payload 1..6000 base64url chars,
   signature 86, both strict unpadded base64url that re-encodes to the same text.
2. Pinned keys (`bad_pinned_keys`) then Ed25519 over `OUTBID:DELIVERY_RECEIPT_V1.<payload_b64url>`
   under any pinned key (`bad_signature`). Nothing is parsed before this.
3. Strict UTF-8 + JSON object (`bad_json`), exact key sets (`bad_keys`), per-field formats in table
   order (`bad_field:<key>`), byte-exact rebuild of the one spelling (`not_canonical`).
4. `mismatch:kid`, `missing_expectation:iss`, `mismatch:iss`, `key_not_valid_at_issued_at`.
5. `missing_expectation:<name>` for all 13 names first, then `mismatch:<key>` in spec order
   (hex expectations lowercased, nothing else normalized).
6. `issued_in_future` (> 300 s ahead), `too_old` (strictly older than `max_age_seconds`).

Streams: `no_receipt` / `bad_sse_trailer` before any of the above.
