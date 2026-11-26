// outbid-receipt-verify: zero-dependency verifier for Outbid-Receipt v1 (spec rev B).
// The verifier section is receipt-ref.mjs from the spec folder, unchanged except this header.
// verifyReceipt() and splitSseReceipt() answer { ok: false, reason } on any input and never throw.
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

// ---------------------------------------------------------------------------
// fetch wrapper. It never discards, replaces or delays a paid response body for
// the caller: it returns the same Response object with a `receipt` property.
// ---------------------------------------------------------------------------

// Outbid-Receipt is read first. X-Outbid-Receipt is the alias the issuer still sends until 2027-01-31.
const RECEIPT_HEADERS = ['outbid-receipt', 'x-outbid-receipt'];

/** The receipt token from the first receipt header that has a value, or null. */
function readReceiptHeader(headers) {
  for (const name of RECEIPT_HEADERS) {
    const v = headers.get(name);
    if (v && v.trim()) return v;
  }
  return null;
}
const PAYMENT_RESPONSE_HEADERS = ['payment-response', 'x-payment-response'];

const toBytes = (b) => {
  if (typeof b === 'string') return Buffer.from(b, 'utf8');
  if (b instanceof Uint8Array) return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  if (b instanceof ArrayBuffer) return Buffer.from(b);
  return undefined;
};

/** The x402 settlement header (base64 JSON), or {} when absent or unreadable. */
function readPaymentResponse(headers) {
  for (const name of PAYMENT_RESPONSE_HEADERS) {
    const v = headers.get(name);
    if (!v) continue;
    try {
      const j = JSON.parse(Buffer.from(v, 'base64').toString('utf8'));
      if (isObj(j)) return j;
    } catch { /* unreadable: treated as absent */ }
  }
  return {};
}

/** What the buyer knows about the request, before it is sent. Unknown values stay undefined. */
async function describeRequest(input, init) {
  const req = typeof Request !== 'undefined' && input instanceof Request ? input : null;
  const url = req ? req.url : String(input instanceof URL ? input.href : input);
  const method = String((init && init.method) || (req && req.method) || 'GET').toUpperCase();
  let body;
  if (init && init.body !== undefined) body = toBytes(init.body);
  else if (req && req.body !== null) body = Buffer.from(await req.clone().arrayBuffer());
  else if (!req || req.body === null) body = Buffer.alloc(0);
  let path;
  try { path = new URL(url).pathname; } catch { path = undefined; }
  let model;
  try { const j = body ? JSON.parse(body.toString('utf8')) : undefined; if (isObj(j) && isStr(j.model)) model = j.model; } catch { /* not JSON */ }
  return { method, path, request_body: body, model };
}

function buildExpect(reqInfo, res, staticExpect, body) {
  const settled = readPaymentResponse(res.headers);
  const e = { ...(isObj(staticExpect) ? staticExpect : {}) };
  return {
    body,
    request_body: reqInfo.request_body,
    method: reqInfo.method,
    path: reqInfo.path,
    model: e.model ?? reqInfo.model,
    network: e.network ?? (isStr(settled.network) ? settled.network : undefined),
    payer: e.payer ?? (isStr(settled.payer) ? settled.payer : undefined),
    payee: e.payee,
    asset: e.asset,
    amount_atomic: e.amount_atomic,
    settlement_ref: e.settlement_ref ?? (isStr(settled.transaction) ? settled.transaction : undefined),
  };
}

const verdict = (r) => (r && r.ok ? { ok: true, reason: null, kid: r.kid } : { ok: false, reason: (r && r.reason) || 'verifier_error' });

/**
 * Wraps a fetch so every response carries response.receipt = { ok, reason }.
 *
 * opts.keys          pinned key entries (copied from <iss>/.well-known/outbid-receipt-keys.json at setup, never fetched per receipt)
 * opts.iss           the issuer those keys were pinned for, e.g. "https://outbid.sh"
 * opts.maxAgeSeconds the caller's own age limit
 * opts.expect        optional: { payee, asset, amount_atomic } from the payment requirement the buyer signed, and
 *                    overrides for payer, network, settlement_ref, model. A plain object, or a function
 *                    (request info) => object. Without payee, asset and amount_atomic the verdict is
 *                    missing_expectation:<name>: a check that did not happen is never a pass.
 * opts.now           optional () => Unix seconds, for tests.
 *
 * JSON answers: the Outbid-Receipt header (or, when it is absent, the alias X-Outbid-Receipt) is verified against a clone of the body before the response is returned.
 * SSE answers (text/event-stream): the response is returned at once with receipt { ok: false, reason: "pending" };
 * response.receiptReady resolves to the verdict once the stream ends and also updates response.receipt.
 * A missing or refused receipt means "no verified receipt", never "not paid". The response is always returned.
 */
export function withReceiptVerification(fetchImpl, opts = {}) {
  const { keys, iss, maxAgeSeconds, expect, now } = isObj(opts) ? opts : {};
  return async function receiptFetch(input, init) {
    let reqInfo = {};
    try { reqInfo = await describeRequest(input, init); } catch { reqInfo = {}; }
    const res = await fetchImpl(input, init); // a transport error is the caller's, as without the wrapper
    const check = async () => {
      try {
        const staticExpect = typeof expect === 'function' ? expect(reqInfo) : expect;
        const nowSeconds = typeof now === 'function' ? now() : Math.floor(Date.now() / 1000);
        const base = { keys, iss, max_age_seconds: maxAgeSeconds, now_seconds: nowSeconds };
        const type = (res.headers.get('content-type') || '').toLowerCase();
        const header = readReceiptHeader(res.headers);
        if (res.status !== 200) return { ok: false, reason: 'no_receipt' };
        if (!type.includes('text/event-stream')) {
          if (!header) return { ok: false, reason: 'no_receipt' };
          const body = Buffer.from(await res.clone().arrayBuffer());
          return verdict(verifyReceipt(header.trim(), { ...base, expect: buildExpect(reqInfo, res, staticExpect, body) }));
        }
        const stream = Buffer.from(await res.clone().arrayBuffer());
        const split = splitSseReceipt(stream);
        if (!split.ok) return verdict(split);
        return verdict(verifyReceipt(split.token, { ...base, expect: buildExpect(reqInfo, res, staticExpect, split.body) }));
      } catch {
        return { ok: false, reason: 'verifier_error' };
      }
    };
    const isStream = (res.headers.get('content-type') || '').toLowerCase().includes('text/event-stream');
    try {
      if (isStream && res.status === 200) {
        res.receipt = { ok: false, reason: 'pending' };
        res.receiptReady = check().then((v) => (res.receipt = v));
      } else {
        res.receipt = await check();
        res.receiptReady = Promise.resolve(res.receipt);
      }
    } catch {
      try { res.receipt = { ok: false, reason: 'verifier_error' }; } catch { /* frozen object: still returned */ }
    }
    return res;
  };
}
