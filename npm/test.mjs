// Runs every case in receipt-vectors.json, the live fixture, and the fetch wrapper. node --test test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReceipt, splitSseReceipt, withReceiptVerification, KEYS_PATH } from './index.mjs';

const dir = new URL(process.env.RECEIPT_VECTORS_DIR ? 'file://' + process.env.RECEIPT_VECTORS_DIR.replace(/\/?$/, '/') : '../vectors/', import.meta.url);
const V = JSON.parse(readFileSync(new URL('receipt-vectors.json', dir), 'utf8'));
const F = JSON.parse(readFileSync(new URL('receipt-fixture-live-20261123.json', dir), 'utf8'));
const N = JSON.parse(readFileSync(new URL('receipt-negative-vectors.json', dir), 'utf8'));
const utf8 = (s) => Buffer.from(s, 'utf8');

function optsFor(c, doc = V) {
  const d = doc.defaults, w = c.with || {};
  const e = { ...d.expect, ...(w.expect || {}) };
  for (const k of w.expect_remove || []) delete e[k];
  return {
    keys: w.keys ?? d.keys, iss: w.iss ?? d.iss, now_seconds: w.now_seconds ?? d.now_seconds,
    max_age_seconds: w.max_age_seconds ?? d.max_age_seconds, e,
  };
}

function runCase(c, doc = V) {
  const { e, ...o } = optsFor(c, doc);
  let token = c.token, body = e.body_utf8 === undefined ? undefined : utf8(e.body_utf8);
  if (c.stream_utf8 !== undefined) {
    const s = splitSseReceipt(utf8(c.stream_utf8));
    if (!s.ok) return s;
    token = s.token; body = s.body;
  }
  const expect = { body, request_body: e.request_body_utf8 === undefined ? undefined : utf8(e.request_body_utf8) };
  for (const k of ['method', 'path', 'network', 'payer', 'payee', 'asset', 'amount_atomic', 'settlement_ref', 'model']) expect[k] = e[k];
  return verifyReceipt(token, { ...o, expect });
}

test('vector file has 54 cases', () => assert.equal(V.cases.length, 54));

for (const c of V.cases) {
  test('vector ' + c.name, () => {
    const r = runCase(c);
    if (c.expected.ok) assert.equal(r.ok, true, JSON.stringify(r));
    else assert.deepEqual({ ok: r.ok, reason: r.reason }, { ok: false, reason: c.expected.reason });
  });
}

// receipt-negative-vectors.json: a case with reason_undefined_by_spec passes on any refusal (SPEC.md names no reason).
for (const c of N.cases) {
  test('negative vector ' + c.name, () => {
    const r = runCase(c, N);
    if (c.expected.ok) assert.equal(r.ok, true, JSON.stringify(r));
    else if (c.expected.reason_undefined_by_spec) assert.equal(r.ok, false, JSON.stringify(r));
    else assert.deepEqual({ ok: r.ok, reason: r.reason }, { ok: false, reason: c.expected.reason });
  });
}

const fixtureExpect = () => ({
  body: Buffer.from(F.expect.body_base64, 'base64'), request_body: utf8(F.expect.request_body_utf8),
  method: F.expect.method, path: F.expect.path, network: F.expect.network, payer: F.expect.payer, payee: F.expect.payee,
  asset: F.expect.asset, amount_atomic: F.expect.amount_atomic, settlement_ref: F.expect.settlement_ref, model: F.expect.model,
});

test('live fixture (house payment, 2026-11-23) verifies', () => {
  const r = verifyReceipt(F.token, { keys: F.keys, iss: F.iss, expect: fixtureExpect(), max_age_seconds: F.max_age_seconds, now_seconds: F.now_seconds });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.kid, F.result.kid);
});

test('live fixture refuses a changed body', () => {
  const ex = fixtureExpect(); ex.body = Buffer.concat([ex.body, utf8(' ')]);
  const r = verifyReceipt(F.token, { keys: F.keys, iss: F.iss, expect: ex, max_age_seconds: F.max_age_seconds, now_seconds: F.now_seconds });
  assert.deepEqual({ ok: r.ok, reason: r.reason }, { ok: false, reason: 'mismatch:body_sha256' });
});

// --- fetch wrapper ---------------------------------------------------------
const paymentResponse = (o) => Buffer.from(JSON.stringify({ success: true, ...o })).toString('base64');
const mockFetch = (status, headers, body) => async () => new Response(body, { status, headers });

const fixtureWrapperOpts = () => ({
  keys: F.keys, iss: F.iss, maxAgeSeconds: F.max_age_seconds, now: () => F.now_seconds,
  expect: { payee: F.expect.payee, asset: F.expect.asset, amount_atomic: F.expect.amount_atomic },
});
const fixtureHeaders = (extra = {}) => ({
  'content-type': 'application/json', 'outbid-receipt': F.token,
  'payment-response': paymentResponse({ transaction: F.expect.settlement_ref, network: F.expect.network, payer: F.expect.payer }), ...extra,
});
const fixtureInit = () => ({ method: 'POST', body: F.expect.request_body_utf8 });

test('wrapper: JSON header receipt ok, body intact', async () => {
  const body = Buffer.from(F.expect.body_base64, 'base64');
  const f = withReceiptVerification(mockFetch(200, fixtureHeaders(), body), fixtureWrapperOpts());
  const res = await f('https://outbid.sh/v1/chat/completions', fixtureInit());
  assert.equal(res.receipt.ok, true, JSON.stringify(res.receipt));
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), body);
});

const headersWith = (receiptHeaders) => {
  const h = fixtureHeaders(); delete h['outbid-receipt'];
  return { ...h, ...receiptHeaders };
};

test('wrapper: only the new Outbid-Receipt header verifies', async () => {
  const h = headersWith({ 'outbid-receipt': F.token });
  assert.equal('x-outbid-receipt' in h, false);
  const f = withReceiptVerification(mockFetch(200, h, Buffer.from(F.expect.body_base64, 'base64')), fixtureWrapperOpts());
  const res = await f('https://outbid.sh/v1/chat/completions', fixtureInit());
  assert.deepEqual(res.receipt, { ok: true, reason: null, kid: F.result.kid });
});

test('wrapper: only the old X-Outbid-Receipt header still verifies (alias until 2027-01-31)', async () => {
  const h = headersWith({ 'x-outbid-receipt': F.token });
  assert.equal('outbid-receipt' in h, false);
  const f = withReceiptVerification(mockFetch(200, h, Buffer.from(F.expect.body_base64, 'base64')), fixtureWrapperOpts());
  const res = await f('https://outbid.sh/v1/chat/completions', fixtureInit());
  assert.deepEqual(res.receipt, { ok: true, reason: null, kid: F.result.kid });
});

test('wrapper: with both headers, Outbid-Receipt is the one read', async () => {
  const body = Buffer.from(F.expect.body_base64, 'base64');
  const good = withReceiptVerification(mockFetch(200, headersWith({ 'outbid-receipt': F.token, 'x-outbid-receipt': 'v1.AAAA.AAAA' }), body), fixtureWrapperOpts());
  assert.equal((await good('https://outbid.sh/v1/chat/completions', fixtureInit())).receipt.ok, true);
  const bad = withReceiptVerification(mockFetch(200, headersWith({ 'outbid-receipt': 'v1.AAAA.AAAA', 'x-outbid-receipt': F.token }), body), fixtureWrapperOpts());
  assert.equal((await bad('https://outbid.sh/v1/chat/completions', fixtureInit())).receipt.ok, false);
});

test('wrapper: KEYS_PATH is the renamed path', () => assert.equal(KEYS_PATH, '/.well-known/outbid-receipt-keys.json'));

test('wrapper: tampered body is still returned, receipt refused', async () => {
  const body = Buffer.concat([Buffer.from(F.expect.body_base64, 'base64'), utf8('x')]);
  const f = withReceiptVerification(mockFetch(200, fixtureHeaders(), body), fixtureWrapperOpts());
  const res = await f('https://outbid.sh/v1/chat/completions', fixtureInit());
  assert.deepEqual(res.receipt, { ok: false, reason: 'mismatch:body_sha256' });
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), body);
});

test('wrapper: missing payment terms is missing_expectation, not a pass', async () => {
  const o = fixtureWrapperOpts(); delete o.expect;
  const f = withReceiptVerification(mockFetch(200, fixtureHeaders(), Buffer.from(F.expect.body_base64, 'base64')), o);
  const res = await f('https://outbid.sh/v1/chat/completions', fixtureInit());
  assert.deepEqual(res.receipt, { ok: false, reason: 'missing_expectation:payee' });
});

test('wrapper: paid 200 without a receipt is returned with no_receipt', async () => {
  const f = withReceiptVerification(mockFetch(200, { 'content-type': 'application/json' }, '{"ok":1}'), fixtureWrapperOpts());
  const res = await f('https://outbid.sh/v1/chat/completions', fixtureInit());
  assert.deepEqual(res.receipt, { ok: false, reason: 'no_receipt' });
  assert.equal(await res.text(), '{"ok":1}');
});

test('wrapper: garbage options never throw', async () => {
  const f = withReceiptVerification(mockFetch(200, fixtureHeaders(), 'x'), null);
  const res = await f('https://outbid.sh/v1/chat/completions', { method: 'POST', body: 'x' });
  assert.equal(res.receipt.ok, false);
  assert.equal(await res.text(), 'x');
});

const sseOpts = () => {
  const d = V.defaults;
  return { keys: d.keys, iss: d.iss, maxAgeSeconds: d.max_age_seconds, now: () => d.now_seconds,
    expect: { payee: d.expect.payee, asset: d.expect.asset, amount_atomic: d.expect.amount_atomic } };
};
const sseHeaders = () => ({ 'content-type': 'text/event-stream',
  'payment-response': paymentResponse({ transaction: V.sse.receipt.settlement_ref, network: V.defaults.expect.network, payer: V.defaults.expect.payer }) });

test('wrapper: SSE trailer receipt ok after the stream ends, stream intact', async () => {
  const f = withReceiptVerification(mockFetch(200, sseHeaders(), V.sse.stream_utf8), sseOpts());
  const res = await f('https://outbid.example/v1/chat/completions', { method: 'POST', body: V.sse.request_body_utf8 });
  assert.equal(res.receipt.reason, 'pending');
  const text = await res.text();
  assert.equal(text, V.sse.stream_utf8);
  const v = await res.receiptReady;
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(res.receipt.ok, true);
});

test('wrapper: SSE with digest comment only is no_receipt', async () => {
  const s = V.cases.find((c) => c.name === 'sse_digest_comment_only').stream_utf8;
  const f = withReceiptVerification(mockFetch(200, sseHeaders(), s), sseOpts());
  const res = await f('https://outbid.example/v1/chat/completions', { method: 'POST', body: V.sse.request_body_utf8 });
  assert.equal(await res.text(), s);
  assert.deepEqual(await res.receiptReady, { ok: false, reason: 'no_receipt' });
});
