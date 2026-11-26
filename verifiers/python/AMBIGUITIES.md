# AMBIGUITIES.md - Outbid-Receipt v1 (rev B), Python clean-room verifier

Process: SPEC.md read in full and the verifier written from it before any vector was run. The only
thing read from the vectors before the first run was the harness layout (field names, `how_to_run`),
because SPEC.md does not define a verifier API. The first run passed 54/54 + the live fixture, so no
code change was driven by a vector failure. Every "Vectors" note below is a check done after the fact.

Legend: **Chose** = what this verifier does. **Vectors** = confirmed / not covered / contradicted.
Reasons prefixed `nonnormative:` are this verifier's own, because the spec defines none.

## Inputs and API

1. **No verifier API in the spec.** SPEC "Verifying" step 5 names expectations `body`, `request_body`,
   `method`, ..., `model`, `max_age_seconds`, `now_seconds`, and step 4 a pinned issuer and pinned keys,
   but gives no signature or data types. The vectors use `body_utf8`, `request_body_utf8`, and the
   fixture `body_base64`. **Chose** `verify_receipt(token, keys=, iss=, expect={body: bytes,
   request_body: bytes, <rest>: str}, max_age_seconds=, now_seconds=)`; the runner maps `*_utf8` to
   UTF-8 bytes and `*_base64` to standard base64 (with validation). **Vectors**: layout from
   `how_to_run`; the fixture's `about` says base64/utf8 "must be bytes".
2. **Pinned key container.** SPEC "Keys" shows a key file `{issuer, keys:[...]}`; the vectors pass a bare
   key list with `iss` beside it. **Chose** accept either a list or an object with `keys`; the issuer is
   always the separate `iss` argument (the CLI defaults it to the file's `issuer`). **Vectors**: list form.
3. **What "not supplied" means** (step 5 "A value the caller does not supply is
   `missing_expectation:<name>`"). **Chose** absent/None, and also wrong type, count as not supplied:
   `body`/`request_body` not bytes-like (a `str` body is NOT auto-encoded, "Nothing else is
   normalized"), string fields not `str` (an int `amount_atomic` is refused, not `str()`-ed),
   `max_age_seconds` not a finite number >= 0, `now_seconds` not a finite number. An empty string is
   "supplied" and then compared (so it ends in `mismatch:`). **Vectors**: only "model removed" covered.
4. **Where the missing-expectation check runs.** Step 5 says "checked in this order before any
   comparison". It could mean before step 1 or at the start of step 5. **Chose** start of step 5 (after
   step 4), all 13 names including `max_age_seconds` and `now_seconds` (step 6 inputs) before the first
   `mismatch:` comparison. Consequence: a bad token with a missing expectation is `bad_token`.
   **Vectors**: `expectation_missing` cannot distinguish the two readings.
5. **Pinned issuer is not in the step-5 name list**; step 4 defines `missing_expectation:iss` only for
   "a pinned issuer that is not itself an https origin in the `iss` format". **Chose** an absent/None or
   non-string pinned issuer is also `missing_expectation:iss`. A pinned issuer with a trailing slash or
   upper case is `missing_expectation:iss` (no normalization), not `mismatch:iss`. **Vectors**: only a
   well-formed other issuer (`wrong_issuer` -> `mismatch:iss`).

## Token shape (step 1, `bad_token`)

6. **Input type.** "A string". **Chose** only `str`; `bytes` and anything else -> `bad_token`. No
   whitespace trimming inside `verify_receipt` (`" v1...."` -> `bad_token`).
7. **6200-character limit is redundant**: the longest valid token is 2+1+6000+1+86 = 6090. Applied
   anyway, as a length in Python characters, before splitting.
8. **Three parts.** Split on every `.`; anything other than exactly 3 parts -> `bad_token`. `v1` is
   compared exactly and case-sensitively (`V1` refused). **Vectors**: `version_v2` confirms.
9. **base64url details.** RFC 4648 s5 alphabet `A-Za-z0-9-_`; `=` padding refused ("no padding");
   standard `+`/`/` refused; length mod 4 == 1 refused; non-zero spare bits refused by the
   decode-then-re-encode rule. **Vectors**: `signature_spare_bits` confirms for the signature; no vector
   has a payload with spare bits set (same rule applied). Signature must decode to exactly 64 bytes
   (86 chars always do once canonical).

## Signature (step 2)

10. **Order of key validation vs token shape.** "The pinned keys come first" sits inside step 2, so
    **Chose** token shape (step 1) before `bad_pinned_keys`. Not covered by vectors.
11. **`bad_pinned_keys` definition** ("none, or an entry that is not an Ed25519 JWK with a valid `kid`
    and a 43-character `x`"). **Chose**: list non-empty; each entry an object with `kty == "OKP"` and
    `crv == "Ed25519"` (exact case); `kid` matching the payload `kid` format `[a-z0-9-]{1,64}` ("valid"
    is not defined otherwise); `x` exactly 43 chars of strict base64url decoding to 32 bytes. Extra JWK
    members (`alg`, `use`, ...) ignored. Duplicate `kid`s among pinned keys are not refused.
    **Non-normative tightening**: `not_before`/`retired_at` that are present, not null and not a number
    also give `bad_pinned_keys` (fail closed). Not covered by vectors.
12. **Which key verifies.** "under one of the pinned keys". **Chose** try in the given order, first key
    that verifies wins, then compare `kid` (step 4). If two entries had the same `x` with different
    `kid`s, the first would win and a receipt naming the second would get `mismatch:kid`; the spec does
    not say. **Vectors**: `valid_second_pinned_key`, `kid_names_another_key` confirm try-all then kid.
13. **Ed25519 variant.** Spec says only "Ed25519 (raw 32-byte key, 64-byte signature)". Strict vs
    cofactored verification, non-canonical `S`, small-order or non-canonical public keys are unspecified.
    **Chose** `cryptography`/OpenSSL `Ed25519PublicKey.verify` (RFC 8032, rejects `S >= L`). No vector
    exercises edge points; a different library could diverge on crafted keys/signatures.
14. **Signing input** is `b"OUTBID:DELIVERY_RECEIPT_V1." + payload_b64url` as transmitted (ASCII).
    **Vectors**: `signed_without_domain`, `signed_under_other_domain` confirm; both reference tokens
    reproduce byte for byte from the test seeds.

## One reading (step 3)

15. **Bytes to text.** "The decoded payload parses as a JSON object"; the spec mentions `JSON.parse`
    but not the UTF-8 decoding mode. **Chose** strict UTF-8: invalid UTF-8 -> `bad_json`. A lenient
    decoder (U+FFFD replacement) would instead reach `bad_field:<key>`. A UTF-8 BOM -> `bad_json`
    (Python's json refuses it). Not covered by vectors.
16. **JSON dialect.** Python's `json` accepts `NaN`/`Infinity`/`-Infinity`; `JSON.parse` does not.
    **Chose** refuse them (`bad_json`). Deep nesting (RecursionError) -> `bad_json`. Leading/trailing
    whitespace parses and is then caught by `not_canonical`. **Vectors**: `signed_not_json`,
    `signed_array` (top level must be an object, arrays -> `bad_json`) confirm.
17. **Duplicate keys.** "JSON.parse keeps one of the two values". Python keeps the last, like
    `JSON.parse`. Rejection then comes only from the rebuild compare, unless the surviving value fails a
    format first (then `bad_field:`, which is what the step order says). **Vectors**:
    `signed_duplicate_key` (decoy first) -> `not_canonical` confirms.
18. **`request` that is not an object.** Spec puts "`request` exactly its three [`bad_keys`]" in the key
    check, but the table also gives `request` a format row ("object with exactly ..."), suggesting
    `bad_field:request`. **Chose** `bad_keys`. Not covered by vectors.
19. **Format test order** ("in the order of the table, `request`'s members after the top-level keys").
    **Chose** `iss, kid, issued_at, network, payer, payee, asset, amount_atomic, settlement_ref,
    resolved_model, body_sha256, request.method, request.path, request.sha256` (the `request` row is
    satisfied by the key check). Vectors are single-fault, so the order is unconfirmed.
20. **`issued_at` type.** Parsed number, integer-valued, >= 0. JSON `true` refused (Python `bool` is an
    `int`; explicitly excluded). `1795392000.0` passes the format and fails `not_canonical` (spec
    explicit; confirmed with a self-signed probe, no vector). `-0` parses to int 0 -> `not_canonical`.
    **Vectors**: `signed_string_issued_at` -> `bad_field:issued_at`; `signed_number_respelled`
    (`1.795392e9`) -> `not_canonical`.
21. **`issued_at` upper bound.** None in spec. Python ints are exact, JS numbers are doubles. A 30-digit
    `issued_at` passes the rebuild here and ends `issued_in_future`; a double-based verifier would respell
    it (`1e+29`) and say `not_canonical`. Refused either way; the reason can differ across languages.
22. **`network` "1 to 32 digits, no leading zero".** Is `eip155:0` allowed? **Chose** refuse
    (`[1-9][0-9]{0,31}`), matching `amount_atomic`'s explicit "so `"0"` is refused". Unconfirmed.
23. **`request.path` length.** "`/` + up to 199 plain characters" -> total 1..200; characters
    `[\x21\x24-\x3e\x40-\x5b\x5d-\x7e]` (plain minus `#`, `?`). A bare `/` is valid. No percent-decoding.
24. **`iss` format.** `https://[a-z0-9.-]{1,100}` literally: no DNS label structure check (`https://..`,
    `https://-` pass). Same pattern used for the pinned issuer.
25. **Python `re` `$` matches before a trailing `\n`.** All patterns use `fullmatch`, so `"POST\n"` is
    refused. Implementation hazard rather than a spec ambiguity, recorded for other ports.
26. **Unicode in strings.** Every allowed character is ASCII, so any non-ASCII value -> `bad_field`;
    a lone-surrogate escape (`\ud800`) -> `bad_field` (probe); an escaped ASCII character
    (`/`) passes formats and fails `not_canonical`. **Vectors**: `signed_escaped_character` confirms.
27. **Rebuild compare.** Byte comparison of the UTF-8 of the rebuilt template with the decoded payload
    bytes (not of re-decoded text). Since all fields are ASCII without `"` or `\`, no escaping logic is
    needed; `issued_at` written as `int(...)` in decimal. **Vectors**: all five `not_canonical` cases.

## Issuer and key (step 4)

28. **Order inside step 4.** **Chose** `mismatch:kid`, then `missing_expectation:iss` (pinned issuer
    format), then `mismatch:iss`, then validity, as listed. Whether a malformed pinned issuer should be
    reported before `mismatch:kid` is not said.
29. **Validity window.** Refused if `issued_at < not_before` or `issued_at >= retired_at`. `not_before:
    null` is not defined by step 4; SPEC "Keys" says it is published `null` when unset. **Chose** null
    = no lower bound, null `retired_at` = no upper bound. **Vectors**: `key_retired` (retired_at ==
    issued_at refused), `key_not_yet_valid` (not_before = issued_at + 1) confirm the boundaries; the live
    fixture's `not_before: null` with expected ok confirms the null reading.

## What the buyer knows (step 5)

30. **Normalization.** "Addresses and hashes the buyer holds are lowercased": applied to `payer`,
    `payee`, `asset`, `settlement_ref`. `body_sha256` and `request.sha256` are computed locally (always
    lowercase). Not normalized: `method` (`post` -> `mismatch:request.method`), `path`, `network`,
    `amount_atomic`, `model`. **Vectors**: default `asset` is checksum case;
    `valid_uppercase_hex_expectations` confirms for `settlement_ref`.
31. **Body for streams.** For a stream the caller's `body` is replaced by the first `n` bytes of the
    stream. Not stated whether a caller-supplied body should also be cross-checked.
32. **Coverage gaps.** No vector for `mismatch:request.method` or `mismatch:asset`; mismatch order is
    unconfirmed (all mismatch vectors are single-fault).

## Age (step 6)

33. **Boundaries.** `issued_in_future` iff `issued_at - now > 300` (exactly 300 ahead passes, probe only);
    `too_old` iff `now - issued_at > max_age_seconds`. Future check first. The 300 s skew is fixed, not
    caller-configurable. Fractional `now_seconds` accepted. **Vectors**: `valid_at_age_limit`, `too_old`
    (+1 s), `issued_in_future` (301 s ahead) confirm. There is no default `max_age_seconds`; it is required.

## Streams (SPEC "Streaming", `no_receipt` / `bad_sse_trailer`)

34. **Line endings.** SSE allows `\r\n`, `\r`, `\n`; the spec shows `\n`. **Chose** `\n` only; a CRLF
    trailer is refused (`bad_sse_trailer`, or `no_receipt` if no line starts with the prefix after `\n`).
35. **"The last `: outbid-receipt=` line".** **Chose** a line beginning at byte 0 or right after `\n`;
    the prefix elsewhere (inside a `data:` line) does not count. **Vectors**: `sse_named_event`,
    `sse_digest_comment_only` -> `no_receipt` confirm.
36. **End of stream.** "one more `\n` ends the stream": **Chose** the receipt line must be followed by
    exactly `\n\n` and then end of input; bytes after it -> `bad_sse_trailer`. **Vectors**:
    `sse_receipt_before_digest`, `sse_truncated` confirm.
37. **Token inside the trailer.** "not a well-formed `v1` token is `bad_sse_trailer`": the step-1 shape
    test runs at split time, so a `v2` or spare-bit token in a stream is `bad_sse_trailer`, not
    `bad_token`. Non-ASCII or `\r` in the token -> `bad_sse_trailer`.
38. **Digest line.** Required directly before the receipt line: `: outbid-sha256=<64 lowercase hex>
    bytes=<n>`. **Chose** `n` in plain decimal without leading zeros (`bytes=0554` refused), at most 20
    digits; uppercase digest hex refused (spec says "64 lowercase hex"); the hex value itself is never
    compared (spec explicit). `n` must equal the byte offset where `: outbid-sha256=` starts. The digest
    comment is not required to start a line ("The trailer starts at byte n"), so a body without a final
    `\n` is accepted if `n` matches. **Vectors**: `sse_wrong_byte_count` confirms the offset rule.
39. **Non-bytes stream input** -> `nonnormative:stream_not_bytes` (no spec reason).

## Headers

40. **Header lookup** (SPEC "Aliases"). `receipt_from_headers` reads `Outbid-Receipt` first and
    `X-Outbid-Receipt` only if the first is absent. Names case-insensitive (HTTP); surrounding SP/HTAB
    stripped (RFC 9110 OWS). Present-but-malformed `Outbid-Receipt` does not fall back (spec: "only when
    the new header is absent"). Repeated / comma-joined header values are unspecified; not handled.
    `Outbid-Body-SHA256` is never used: the verifier hashes the body itself.

## Errors and robustness

41. **Precedence.** First failure in step order; within step 3 `bad_json` > `bad_keys` > `bad_field` >
    `not_canonical`. **Vectors**: consistent across all 54 (each single-fault).
42. **`verifier_error`.** A catch-all around both entry points; never observed. The spec's "31 malformed
    inputs" are not in the vector files; I ran my own (~25: None, ints, bytes, dicts, empty, oversized,
    padded, bad keys of 8 kinds, broken streams) - none threw or returned `verifier_error`.

## Spec / vector consistency notes

43. SPEC refers to `reference/receipt-ref.mjs`, `src/receipt-v1.mjs`, `skill/SKILL.md`; not used (out of
    bounds). Cross-checked instead: header value is 917 bytes and equals `non_stream.token`; the "One
    spelling" text equals `non_stream.payload_text`; both test seeds derive the listed `x`; both tokens
    reproduce byte for byte; the SSE body is 554 bytes and hashes to the signed `body_sha256`; the case
    counts per verdict match the SPEC table (5/9/2/5/3/6/2/12/1/4/2/3 = 54).
44. SPEC table wording "Signed with an unknown key, a missing key ..." under `bad_keys` means JSON keys,
    not signing keys (resolved by case names `signed_extra_key`, `signed_missing_key`).
45. The live fixture's `about` calls it an "`X-Outbid-Receipt`" (the alias); the token is the same either
    way. The fixture's verdict field is `result`, not `expected`, and it carries `kid`, which the runner
    checks.
46. **Live fixture key provenance.** The fixture carries the key inline. SPEC says keys are pinned from
    `https://outbid.sh/.well-known/outbid-receipt-keys.json` over TLS; no network was used, so this
    verifier proves the fixture is internally consistent (signature, hashes, fields, age at the
    fixture's `now_seconds`), not that outbid.sh serves that key. The `onchain` block was only compared
    with the payload (tx, network, amount), not checked on chain.
