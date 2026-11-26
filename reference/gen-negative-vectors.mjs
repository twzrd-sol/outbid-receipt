// Writes vectors/receipt-negative-vectors.json: tampered and edge cases beyond receipt-vectors.json.
// node reference/gen-negative-vectors.mjs            (writes the file)
// node reference/gen-negative-vectors.mjs --check    (exits 1 if the file on disk differs)
// node:crypto only. TEST KEYS ONLY, the same public-by-construction seeds as receipt-vectors.json.
// Every "expected" below is read from SPEC.md, not from a verifier's output. A case whose reason SPEC.md does not
// define has expected { ok: false } and "reason_undefined_by_spec": true; any verifier must still refuse it.
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const here = new URL('.', import.meta.url);
const OUT = new URL('../vectors/receipt-negative-vectors.json', here);
const BASE = JSON.parse(readFileSync(new URL('../vectors/receipt-vectors.json', here), 'utf8'));
const DOMAIN = 'OUTBID:DELIVERY_RECEIPT_V1';
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const priv = (seedText) => crypto.createPrivateKey({
  key: Buffer.concat([PKCS8, crypto.createHash('sha256').update(seedText, 'ascii').digest()]), format: 'der', type: 'pkcs8',
});
const [K1, K2] = BASE.test_keys;
const SK = { [K1.kid]: priv(K1.seed_text), [K2.kid]: priv(K2.seed_text) };
const pub = ({ seed_text, ...k }) => k; // eslint-disable-line no-unused-vars
const P1 = pub(K1), P2 = pub(K2);
const NS = BASE.non_stream;
const R = NS.receipt;
const ISSUED = R.issued_at;

// Sign any payload text (no field checks), so a case can carry a field the reference signer would refuse.
const signText = (text, kid = K1.kid) => {
  const payload = b64u(Buffer.from(text, 'utf8'));
  return 'v1.' + payload + '.' + b64u(crypto.sign(null, Buffer.from(DOMAIN + '.' + payload, 'ascii'), SK[kid]));
};
const canon = (r) => JSON.stringify({
  iss: r.iss, kid: r.kid, issued_at: r.issued_at,
  request: { method: r.request.method, path: r.request.path, sha256: r.request.sha256 },
  network: r.network, payer: r.payer, payee: r.payee, asset: r.asset, amount_atomic: r.amount_atomic,
  settlement_ref: r.settlement_ref, resolved_model: r.resolved_model, body_sha256: r.body_sha256,
});
const signed = (over = {}, kid) => {
  const r = { ...R, ...over, request: { ...R.request, ...(over.request || {}) } };
  return signText(canon(r), kid ?? r.kid);
};
const GOOD = signed();
if (GOOD !== BASE.cases.find((c) => c.name === 'valid_non_stream').token) throw new Error('generator does not reproduce valid_non_stream');
const [, P, S] = GOOD.split('.');

const cases = [];
const add = (name, what, token, expected, w) => cases.push({ name, what, ...(w ? { with: w } : {}), token, expected });
const no = (reason) => ({ ok: false, reason });
const undef = (what) => ({ ok: false, reason_undefined_by_spec: true, note: what });

// --- body hash -----------------------------------------------------------------------------------------------
add('body_empty', 'The buyer received an empty body.', GOOD, no('mismatch:body_sha256'), { expect: { body_utf8: '' } });
add('body_trailing_newline', 'One byte appended to the body received.', GOOD, no('mismatch:body_sha256'),
  { expect: { body_utf8: NS.response_body_utf8 + '\n' } });
add('body_hash_of_request', 'The seller signed the request body hash as body_sha256.',
  signed({ body_sha256: R.request.sha256 }), no('mismatch:body_sha256'));
add('signed_short_body_sha256', 'Signed body_sha256 of 63 hex characters.',
  signed({ body_sha256: R.body_sha256.slice(1) }), no('bad_field:body_sha256'));

// --- request hash, method, path -----------------------------------------------------------------------------
add('other_method', 'The buyer sent GET.', GOOD, no('mismatch:request.method'), { expect: { method: 'GET' } });
add('method_lowercase', 'The buyer holds "post": nothing but hex is normalized.', GOOD, no('mismatch:request.method'),
  { expect: { method: 'post' } });
add('request_body_empty', 'The buyer sent an empty request body.', GOOD, no('mismatch:request.sha256'),
  { expect: { request_body_utf8: '' } });
add('request_body_whitespace', 'The buyer sent the same JSON with a space.', GOOD, no('mismatch:request.sha256'),
  { expect: { request_body_utf8: NS.request_body_utf8.replace('"messages"', ' "messages"') } });
add('path_with_query', 'The buyer holds the path with a query string.', GOOD, no('mismatch:request.path'),
  { expect: { path: '/v1/chat/completions?x=1' } });
add('signed_uppercase_request_sha256', 'Signed request.sha256 in uppercase.',
  signed({ request: { sha256: R.request.sha256.toUpperCase() } }), no('bad_field:request.sha256'));
add('signed_lowercase_method', 'Signed request.method "post".', signed({ request: { method: 'post' } }), no('bad_field:request.method'));
add('signed_path_with_query', 'Signed request.path with "?".', signed({ request: { path: '/v1/chat/completions?x=1' } }),
  no('bad_field:request.path'));

// --- payment fields -------------------------------------------------------------------------------------------
add('other_asset', 'The buyer paid in another token contract.', GOOD, no('mismatch:asset'),
  { expect: { asset: '0x' + '3'.repeat(40) } });
add('amount_leading_zero_expected', 'The buyer holds "01500".', GOOD, no('mismatch:amount_atomic'), { expect: { amount_atomic: '01500' } });
add('amount_decimal_expected', 'The buyer holds "1500.0".', GOOD, no('mismatch:amount_atomic'), { expect: { amount_atomic: '1500.0' } });
add('other_chain', 'The buyer paid on Base Sepolia.', GOOD, no('mismatch:network'), { expect: { network: 'eip155:84532' } });
add('settlement_ref_without_0x', 'The buyer holds the hash without 0x.', GOOD, no('mismatch:settlement_ref'),
  { expect: { settlement_ref: R.settlement_ref.slice(2) } });
add('payee_swapped_with_payer', 'Payer and payee exchanged in the buyer\'s expectation.', GOOD, no('mismatch:payer'),
  { expect: { payer: R.payee, payee: R.payer } });
add('signed_amount_zero', 'Signed amount_atomic "0".', signed({ amount_atomic: '0' }), no('bad_field:amount_atomic'));
add('signed_amount_negative', 'Signed amount_atomic "-1500".', signed({ amount_atomic: '-1500' }), no('bad_field:amount_atomic'));
add('signed_amount_number', 'Signed amount_atomic as a JSON number.',
  signText(canon(R).replace('"amount_atomic":"1500"', '"amount_atomic":1500')), no('bad_field:amount_atomic'));
add('signed_network_leading_zero', 'Signed network "eip155:08453".', signed({ network: 'eip155:08453' }), no('bad_field:network'));
add('signed_solana_network', 'Signed a solana: network (v1 signs eip155 only).',
  signed({ network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' }), no('bad_field:network'));

// --- kid ------------------------------------------------------------------------------------------------------
add('unknown_kid', 'Signed by the pinned key, but the payload names a kid that is not pinned.',
  signed({ kid: 'test-vector-key-9' }, K1.kid), no('mismatch:kid'));
add('kid_other_case', 'The payload kid differs from the verifying key\'s only in letter case (refused by format first).',
  signed({ kid: 'Test-Vector-Key-1' }, K1.kid), no('bad_field:kid'));
add('pinned_keys_empty', 'No pinned keys.', GOOD, no('bad_pinned_keys'), { keys: [] });
add('pinned_key_wrong_curve', 'The pinned key says crv X25519.', GOOD, no('bad_pinned_keys'), { keys: [{ ...P1, crv: 'X25519' }] });
add('pinned_key_short_x', 'The pinned key x has 42 characters.', GOOD, no('bad_pinned_keys'), { keys: [{ ...P1, x: P1.x.slice(1) }] });
add('pinned_key_no_kid', 'The pinned key has no kid.', GOOD, no('bad_pinned_keys'), { keys: [{ kty: P1.kty, crv: P1.crv, x: P1.x, not_before: P1.not_before, retired_at: null }] });
add('pinned_keys_one_bad_entry', 'A good key and a malformed one pinned together.', GOOD, no('bad_pinned_keys'),
  { keys: [P1, { ...P2, kty: 'EC' }] });
add('pinned_keys_not_list', 'Pinned keys passed as one object, not a list.', GOOD,
  undef('SPEC.md says "none, or an entry that is not an Ed25519 JWK" and does not say what container the keys come in.'),
  { keys: P1 });
const boundNote = 'SPEC.md says not_before and retired_at are Unix seconds or null, but bad_pinned_keys lists only kid, kty/crv and x, so a malformed bound has no named reason. Read as "no bound" it would let a retired key verify; a verifier must refuse.';
add('pinned_key_string_not_before', 'The pinned key\'s not_before is a numeric string.', GOOD, undef(boundNote),
  { keys: [{ ...P1, not_before: String(P1.not_before) }] });
add('retired_key_retired_at_iso_string', 'Old key retired before issued_at, retired_at written as an ISO date string.', GOOD, undef(boundNote),
  { keys: [{ ...P1, retired_at: new Date((ISSUED - 86400) * 1000).toISOString() }] });
add('retired_key_retired_at_numeric_string', 'Old key retired before issued_at, retired_at as a numeric string.', GOOD, undef(boundNote),
  { keys: [{ ...P1, retired_at: String(ISSUED - 1) }] });
add('retired_key_retired_at_float', 'Old key retired before issued_at, retired_at as a non-integer number.', GOOD, undef(boundNote),
  { keys: [{ ...P1, retired_at: ISSUED - 0.5 }] });
add('not_yet_valid_key_not_before_string', 'not_before after issued_at, written as a numeric string.', GOOD, undef(boundNote),
  { keys: [{ ...P1, not_before: String(ISSUED + 1) }] });

// --- rotated key ----------------------------------------------------------------------------------------------
add('rotated_old_key_retired_at_issued_at', 'Old key retired exactly at issued_at ("at or after" is refused).', GOOD,
  no('key_not_valid_at_issued_at'), { keys: [{ ...P1, retired_at: ISSUED }] });
add('rotated_old_key_retired_after_issued_at', 'Old key retired one second after issued_at: earlier receipts still verify.', GOOD,
  { ok: true }, { keys: [{ ...P1, retired_at: ISSUED + 1 }, P2] });
add('rotated_new_key_signs', 'After rotation: old key retired, new key signs, both pinned.', signed({ kid: K2.kid }, K2.kid),
  { ok: true }, { keys: [{ ...P1, retired_at: ISSUED - 1 }, P2] });
add('rotated_new_key_not_before_is_issued_at', 'New key whose not_before equals issued_at (inclusive).', signed({ kid: K2.kid }, K2.kid),
  { ok: true }, { keys: [{ ...P2, not_before: ISSUED }] });
add('rotated_new_key_not_before_after_issued_at', 'New key whose not_before is one second after issued_at.', signed({ kid: K2.kid }, K2.kid),
  no('key_not_valid_at_issued_at'), { keys: [{ ...P2, not_before: ISSUED + 1 }] });
add('rotated_old_key_signs_after_retirement', 'Signed by the old key after it was retired, both pinned.', GOOD,
  no('key_not_valid_at_issued_at'), { keys: [{ ...P1, retired_at: ISSUED - 1 }, P2] });
add('rotated_buyer_never_pinned_new_key', 'Signed by the new key; the buyer pinned only the old one.', signed({ kid: K2.kid }, K2.kid),
  no('bad_signature'));
add('rotated_new_key_signs_payload_names_old_kid', 'Signed by the new key, payload names the old key\'s kid.', signed({ kid: K1.kid }, K2.kid),
  no('mismatch:kid'), { keys: [P1, P2] });

// --- malformed header value -----------------------------------------------------------------------------------
add('header_leading_space', 'Header value with a leading space left in.', ' ' + GOOD, no('bad_token'));
add('header_trailing_crlf', 'Header value with CRLF left in.', GOOD + '\r\n', no('bad_token'));
add('header_uppercase_version', 'Version "V1".', 'V1.' + P + '.' + S, no('bad_token'));
add('header_four_parts', 'An extra ".part".', GOOD + '.AAAA', no('bad_token'));
add('header_two_parts', 'No signature part.', 'v1.' + P, no('bad_token'));
add('header_padded_signature', 'Signature with "==" padding.', GOOD + '==', no('bad_token'));
const S_STD = S.replace(/-/g, '+').replace(/_/g, '/');
if (S_STD === S) throw new Error('signature has no - or _ to respell');
add('header_standard_base64', 'Signature in standard base64 ("+" and "/" for "-" and "_").', 'v1.' + P + '.' + S_STD, no('bad_token'));
add('header_empty', 'Empty header value.', '', no('bad_token'));
add('header_two_values_folded', 'Outbid-Receipt and X-Outbid-Receipt folded into one value by a proxy.', GOOD + ', ' + GOOD, no('bad_token'));
add('header_short_signature', 'Signature of 85 characters.', 'v1.' + P + '.' + S.slice(1), no('bad_token'));
add('header_empty_payload', 'Payload part empty.', 'v1..' + S, no('bad_token'));
add('header_oversized_payload', 'Payload of 6004 base64url characters.', 'v1.' + 'A'.repeat(6004) + '.' + S, no('bad_token'));
add('header_bearer_prefix', 'Value with a "Bearer " prefix.', 'Bearer ' + GOOD, no('bad_token'));
add('header_not_string', 'The value is JSON null, not a string.', null, no('bad_token'));

// --- spec does not name the reason ----------------------------------------------------------------------------
add('signed_invalid_utf8', 'Signed payload bytes that are not UTF-8.', (() => {
  const payload = b64u(Buffer.concat([Buffer.from(canon(R).slice(0, -2), 'utf8'), Buffer.from([0xff, 0x22, 0x7d])]));
  return 'v1.' + payload + '.' + b64u(crypto.sign(null, Buffer.from(DOMAIN + '.' + payload, 'ascii'), SK[K1.kid]));
})(), undef('SPEC.md says the decoded payload "parses as a JSON object" but not how bytes become text.'));
add('signed_two_faults', 'Signed with a mixed-case payer and an uppercase body_sha256.',
  signed({ payer: '0x' + 'A'.repeat(40), body_sha256: R.body_sha256.toUpperCase() }), no('bad_field:payer'));

const doc = {
  spec: BASE.spec,
  warning: BASE.warning,
  about: 'Negative and edge cases beyond receipt-vectors.json: body hash, request hash, payment fields, kid, pinned keys, key rotation, malformed header values. Generated by reference/gen-negative-vectors.mjs from the same test keys. Every expected verdict is read from SPEC.md. A case with reason_undefined_by_spec has no reason to match: a verifier passes it by refusing it with any reason.',
  domain: DOMAIN,
  test_keys: BASE.test_keys,
  how_to_run: BASE.how_to_run,
  defaults: BASE.defaults,
  cases,
};
const text = JSON.stringify(doc, null, 2) + '\n';
if (process.argv.includes('--check')) {
  const disk = readFileSync(OUT, 'utf8');
  if (disk !== text) { console.error('vectors/receipt-negative-vectors.json is stale: run node reference/gen-negative-vectors.mjs'); process.exit(1); }
  console.log('receipt-negative-vectors.json up to date (' + cases.length + ' cases)');
} else {
  writeFileSync(OUT, text);
  console.log('wrote ' + cases.length + ' cases');
}
