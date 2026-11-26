// Outbid-Receipt v1 (spec rev B): reference signer and verifier for the spec in this folder.
// node:crypto only. Not outbid production code.
// verifyReceipt() and splitSseReceipt() answer { ok: false, reason } on any input and never throw.
import crypto from 'node:crypto';

export const DOMAIN = 'OUTBID:DELIVERY_RECEIPT_V1';
// The issuer serves its public keys here, under iss: iss is exactly the https origin of this URL.
// Alias until 2027-01-31: /.well-known/receipt-keys.json serves identical bytes.
export const KEYS_PATH = '/.well-known/outbid-receipt-keys.json';
export const KEYS = ['iss', 'kid', 'issued_at', 'request', 'network', 'payer', 'payee', 'asset', 'amount_atomic', 'settlement_ref', 'resolved_model', 'body_sha256'];
export const REQUEST_KEYS = ['method', 'path', 'sha256'];

// The same construction as ed25519Verifies() in twzrd-x402-gate: SPKI prefix + raw 32-byte key.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const str = (re) => (v) => typeof v === 'string' && re.test(v);
const HEX64 = str(/^[0-9a-f]{64}$/);
const ADDRESS = str(/^0x[0-9a-f]{40}$/);
// [\x21\x23-\x5b\x5d-\x7e] is printable ASCII without space, " and \ : JSON writes such a string as itself.
const FORMAT = {
  iss: str(/^https:\/\/[a-z0-9.-]{1,100}$/),
  kid: str(/^[a-z0-9-]{1,64}$/),
  issued_at: (v) => Number.isSafeInteger(v) && v >= 0,
  network: str(/^eip155:[1-9][0-9]{0,31}$/),
  payer: ADDRESS,
  payee: ADDRESS,
  asset: ADDRESS,
  amount_atomic: str(/^[1-9][0-9]{0,38}$/),
  settlement_ref: str(/^0x[0-9a-f]{64}$/),
  resolved_model: str(/^[\x21\x23-\x5b\x5d-\x7e]{1,200}$/),
  body_sha256: HEX64,
};
const REQUEST_FORMAT = {
  method: str(/^[A-Z]{1,16}$/),
  path: str(/^\/[\x21\x24-\x3e\x40-\x5b\x5d-\x7e]{0,199}$/), // as above, and no ? or #: the path without its query
  sha256: HEX64,
};

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isBytes = (v) => v instanceof Uint8Array;
const isStr = (v) => typeof v === 'string';
const no = (reason) => ({ ok: false, reason });
const b64u = (b) => Buffer.from(b).toString('base64url');
export const sha256Hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

/** null when r has exactly the v1 keys in the v1 formats, else the reason. */
function fieldError(r) {
  if (!isObj(r) || Object.keys(r).length !== KEYS.length || !KEYS.every((k) => Object.hasOwn(r, k))) return 'bad_keys';
  const q = r.request;
  if (!isObj(q) || Object.keys(q).length !== REQUEST_KEYS.length || !REQUEST_KEYS.every((k) => Object.hasOwn(q, k))) return 'bad_keys';
  for (const k of KEYS) if (k !== 'request' && !FORMAT[k](r[k])) return 'bad_field:' + k;
  for (const k of REQUEST_KEYS) if (!REQUEST_FORMAT[k](q[k])) return 'bad_field:request.' + k;
  return null;
}

/** The one spelling of a receipt: keys in spec order, no whitespace, no escapes, integers in plain decimal. */
export function canonicalPayload(r) {
  return JSON.stringify({
    iss: r.iss, kid: r.kid, issued_at: r.issued_at,
    request: { method: r.request.method, path: r.request.path, sha256: r.request.sha256 },
    network: r.network, payer: r.payer, payee: r.payee, asset: r.asset, amount_atomic: r.amount_atomic,
    settlement_ref: r.settlement_ref, resolved_model: r.resolved_model, body_sha256: r.body_sha256,
  });
}

/** { ok: true, token } or { ok: false, reason }. A caller on a paid path sends the response either way. */
export function signReceipt(fields, privateKey) {
  try {
    const bad = fieldError(fields);
    if (bad) return no(bad);
    const payload = b64u(canonicalPayload(fields));
    const sig = crypto.sign(null, Buffer.from(DOMAIN + '.' + payload, 'ascii'), privateKey);
    return { ok: true, token: 'v1.' + payload + '.' + b64u(sig) };
  } catch {
    return no('sign_failed');
  }
}

// not_before and retired_at are Unix seconds or null (absent reads as null). Any other value refuses the key set:
// read as "no bound", a retired_at written as a date string or a float would let a retired key verify.
const validBound = (v) => v === null || v === undefined || (Number.isSafeInteger(v) && v >= 0);
const validKey = (k) => isObj(k) && FORMAT.kid(k.kid) && k.kty === 'OKP' && k.crv === 'Ed25519' && isStr(k.x) && /^[A-Za-z0-9_-]{43}$/.test(k.x)
  && validBound(k.not_before) && validBound(k.retired_at);
const publicKey = (x) => crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(x, 'base64url')]), format: 'der', type: 'spki' });

/**
 * token: the Outbid-Receipt value (or the text after ": outbid-receipt=" on a stream).
 * opts.keys: the verifier's pinned key entries. opts.iss: the issuer those keys were pinned for.
 * opts.expect: what the buyer knows about its own request, payment and response. Every entry is required.
 * opts.max_age_seconds: the caller's own limit. opts.now_seconds defaults to the clock.
 */
export function verifyReceipt(token, opts) {
  try {
    return verify(token, isObj(opts) ? opts : {});
  } catch {
    return no('verifier_error');
  }
}

function verify(token, { keys, iss, expect, max_age_seconds, now_seconds = Math.floor(Date.now() / 1000), max_future_seconds = 300 }) {
  // 1. Token shape. Nothing is decoded as JSON yet.
  if (!isStr(token) || token.length > 6200) return no('bad_token');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return no('bad_token');
  const [, payload, sigText] = parts;
  if (!/^[A-Za-z0-9_-]{1,6000}$/.test(payload) || !/^[A-Za-z0-9_-]{86}$/.test(sigText)) return no('bad_token');
  const payloadBytes = Buffer.from(payload, 'base64url');
  const sig = Buffer.from(sigText, 'base64url');
  if (payloadBytes.toString('base64url') !== payload || sig.toString('base64url') !== sigText) return no('bad_token');

  // 2. Signature over the text exactly as sent, under a pinned key.
  if (!Array.isArray(keys) || keys.length === 0 || !keys.every(validKey)) return no('bad_pinned_keys');
  const message = Buffer.from(DOMAIN + '.' + payload, 'ascii');
  const key = keys.find((k) => crypto.verify(null, message, publicKey(k.x), sig));
  if (!key) return no('bad_signature');

  // 3. One reading: exactly the v1 keys, the v1 formats, and the one canonical spelling.
  let r;
  try { r = JSON.parse(payloadBytes.toString('utf8')); } catch { return no('bad_json'); }
  if (!isObj(r)) return no('bad_json');
  const bad = fieldError(r);
  if (bad) return no(bad);
  if (!Buffer.from(canonicalPayload(r), 'utf8').equals(payloadBytes)) return no('not_canonical');

  // 4. Issuer and key.
  if (r.kid !== key.kid) return no('mismatch:kid');
  if (!FORMAT.iss(iss)) return no('missing_expectation:iss');
  if (r.iss !== iss) return no('mismatch:iss');
  if (Number.isSafeInteger(key.not_before) && r.issued_at < key.not_before) return no('key_not_valid_at_issued_at');
  if (Number.isSafeInteger(key.retired_at) && r.issued_at >= key.retired_at) return no('key_not_valid_at_issued_at');

  // 5. What the buyer knows. A value the caller did not supply is a check that did not happen, so it is refused.
  const e = isObj(expect) ? expect : {};
  const need = { body: isBytes, request_body: isBytes, method: isStr, path: isStr, network: isStr, payer: isStr, payee: isStr, asset: isStr, amount_atomic: isStr, settlement_ref: isStr, model: isStr };
  for (const [name, test] of Object.entries(need)) if (!test(e[name])) return no('missing_expectation:' + name);
  if (!Number.isSafeInteger(max_age_seconds) || max_age_seconds < 0) return no('missing_expectation:max_age_seconds');
  if (!Number.isSafeInteger(now_seconds)) return no('missing_expectation:now_seconds');
  const checks = [
    ['body_sha256', sha256Hex(e.body), r.body_sha256],
    ['request.method', e.method, r.request.method],
    ['request.path', e.path, r.request.path],
    ['request.sha256', sha256Hex(e.request_body), r.request.sha256],
    ['network', e.network, r.network],
    ['payer', e.payer.toLowerCase(), r.payer],            // 0x addresses and hashes are hex: letter case carries nothing
    ['payee', e.payee.toLowerCase(), r.payee],
    ['asset', e.asset.toLowerCase(), r.asset],
    ['amount_atomic', e.amount_atomic, r.amount_atomic],
    ['settlement_ref', e.settlement_ref.toLowerCase(), r.settlement_ref],
    ['resolved_model', e.model, r.resolved_model],          // exact: the model the buyer named, nothing else
  ];
  for (const [name, want, got] of checks) if (want !== got) return no('mismatch:' + name);

  // 6. Age, by the caller's limit.
  if (r.issued_at - now_seconds > max_future_seconds) return no('issued_in_future');
  if (now_seconds - r.issued_at > max_age_seconds) return no('too_old');
  return { ok: true, receipt: r, kid: key.kid };
}

const TRAILER = /^: outbid-sha256=([0-9a-f]{64}) bytes=(0|[1-9][0-9]{0,15})\n: outbid-receipt=(v1\.[A-Za-z0-9_-]{1,6000}\.[A-Za-z0-9_-]{86})\n\n$/;

/** The last write of a paid stream: the digest comment outbid sends today, then the receipt comment. */
export function sseTrailer(body, token) {
  return ': outbid-sha256=' + sha256Hex(body) + ' bytes=' + body.length + '\n: outbid-receipt=' + token + '\n\n';
}

/** Splits a whole received stream into { body, digest, token }. body is every byte before the digest comment. */
export function splitSseReceipt(stream) {
  try {
    if (!isBytes(stream)) return no('bad_sse_trailer');
    const buf = Buffer.from(stream.buffer, stream.byteOffset, stream.byteLength);
    const receiptAt = buf.lastIndexOf(': outbid-receipt=');
    if (receiptAt < 0) return no('no_receipt');
    const at = buf.lastIndexOf(': outbid-sha256=', receiptAt);
    if (at < 0) return no('bad_sse_trailer');
    const m = TRAILER.exec(buf.subarray(at).toString('latin1'));
    if (!m || Number(m[2]) !== at) return no('bad_sse_trailer');
    return { ok: true, body: buf.subarray(0, at), digest: m[1], token: m[3] };
  } catch {
    return no('bad_sse_trailer');
  }
}
