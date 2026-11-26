#!/usr/bin/env python3
"""Clean-room verifier for Outbid-Receipt v1 (rev B), built from SPEC.md alone.

Library:
    verify_receipt(token, keys=..., iss=..., expect=..., max_age_seconds=..., now_seconds=...)
    split_sse_receipt(stream_bytes)
    verify_stream(stream_bytes, keys=..., iss=..., expect=..., max_age_seconds=..., now_seconds=...)
    receipt_from_headers(headers)

Every call returns a Verdict; nothing raises on a receipt. Reasons are the spec's bracketed
names (SPEC.md "Verifying"). Reasons prefixed "nonnormative:" are not defined by the spec;
see AMBIGUITIES.md.

CLI:
    outbid_receipt_verify.py --keys keys.json --iss https://outbid.sh \
        (--token TOKEN | --token-file F | --stream-file F) [--body-file F] \
        --request-body-file F --method POST --path /v1/chat/completions \
        --network eip155:8453 --payer 0x.. --payee 0x.. --asset 0x.. \
        --amount-atomic 1000 --settlement-ref 0x.. --model M \
        --max-age-seconds 900 [--now-seconds N]
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"OUTBID:DELIVERY_RECEIPT_V1."
MAX_TOKEN_CHARS = 6200
MAX_PAYLOAD_CHARS = 6000
SIG_CHARS = 86
FUTURE_SKEW_SECONDS = 300

KEY_ORDER = (
    "iss", "kid", "issued_at", "request", "network", "payer", "payee", "asset",
    "amount_atomic", "settlement_ref", "resolved_model", "body_sha256",
)
REQUEST_KEY_ORDER = ("method", "path", "sha256")

# Character classes (SPEC.md "Payload"). A plain character: printable ASCII other than
# space, '"' and '\'. Path characters: plain characters other than '?' and '#'.
_PLAIN = r"[\x21\x23-\x5b\x5d-\x7e]"
_PATH_CH = r"[\x21\x24-\x3e\x40-\x5b\x5d-\x7e]"
_HEX64 = r"[0-9a-f]{64}"
_ADDR = r"0x[0-9a-f]{40}"

ISS_RE = re.compile(r"https://[a-z0-9.\-]{1,100}")
KID_RE = re.compile(r"[a-z0-9\-]{1,64}")
STRING_FORMATS = {
    "iss": ISS_RE,
    "kid": KID_RE,
    "network": re.compile(r"eip155:[1-9][0-9]{0,31}"),
    "payer": re.compile(_ADDR),
    "payee": re.compile(_ADDR),
    "asset": re.compile(_ADDR),
    "amount_atomic": re.compile(r"[1-9][0-9]{0,38}"),
    "settlement_ref": re.compile(r"0x" + _HEX64),
    "resolved_model": re.compile(_PLAIN + r"{1,200}"),
    "body_sha256": re.compile(_HEX64),
    "request.method": re.compile(r"[A-Z]{1,16}"),
    "request.path": re.compile(r"/" + _PATH_CH + r"{0,199}"),
    "request.sha256": re.compile(_HEX64),
}
B64URL_RE = re.compile(r"[A-Za-z0-9_\-]*")

SSE_DIGEST_PREFIX = b": outbid-sha256="
SSE_RECEIPT_PREFIX = b": outbid-receipt="
_SSE_DIGEST_AT_END = re.compile(rb": outbid-sha256=([0-9a-f]{64}) bytes=(0|[1-9][0-9]*)\Z")

# missing_expectation names, in the spec's order. Mapped to (where, key).
EXPECTATION_ORDER = (
    "body", "request_body", "method", "path", "network", "payer", "payee", "asset",
    "amount_atomic", "settlement_ref", "model", "max_age_seconds", "now_seconds",
)


@dataclass
class Verdict:
    ok: bool
    reason: Optional[str] = None
    kid: Optional[str] = None
    payload: Optional[dict] = None
    # For streams: the n body bytes the receipt covers.
    body: Optional[bytes] = field(default=None, repr=False)
    token: Optional[str] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        d: dict = {"ok": self.ok}
        if self.ok:
            d["kid"] = self.kid
        else:
            d["reason"] = self.reason
        return d


def _fail(reason: str, **kw) -> Verdict:
    return Verdict(ok=False, reason=reason, **kw)


# ---------------------------------------------------------------- base64url (RFC 4648 s5)

def b64url_decode_strict(text: Any) -> Optional[bytes]:
    """Decode unpadded base64url; None unless re-encoding gives back the exact text."""
    if not isinstance(text, str) or not B64URL_RE.fullmatch(text):
        return None
    if len(text) % 4 == 1:
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    if b64url_encode(raw) != text:
        return None
    return raw


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------- helpers

def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _is_nonneg_integer_number(v: Any) -> bool:
    """JS-style: a parsed JSON number that is an integer and >= 0 (1.0 counts)."""
    if not _is_number(v):
        return False
    if isinstance(v, float) and not v.is_integer():
        return False
    return v >= 0


def _reject_constant(name: str):
    raise ValueError("non-JSON constant " + name)


def _parse_json_strict(text: str) -> Any:
    # RFC 8259 / JSON.parse: no NaN, Infinity, -Infinity.
    return json.loads(text, parse_constant=_reject_constant)


def _canonical_text(p: Mapping) -> str:
    """The one spelling (SPEC.md "One spelling"). Values already passed their formats, so
    every string is written as itself and issued_at as plain decimal."""
    r = p["request"]
    issued = int(p["issued_at"])
    return (
        '{"iss":"%s","kid":"%s","issued_at":%d,"request":{"method":"%s","path":"%s","sha256":"%s"},'
        '"network":"%s","payer":"%s","payee":"%s","asset":"%s","amount_atomic":"%s",'
        '"settlement_ref":"%s","resolved_model":"%s","body_sha256":"%s"}'
    ) % (
        p["iss"], p["kid"], issued, r["method"], r["path"], r["sha256"],
        p["network"], p["payer"], p["payee"], p["asset"], p["amount_atomic"],
        p["settlement_ref"], p["resolved_model"], p["body_sha256"],
    )


def _check_formats(p: Mapping) -> Optional[str]:
    """Returns 'bad_field:<key>' for the first failure in table order, request members last."""
    for key in KEY_ORDER:
        if key == "request":
            continue  # already known to be an object with its three keys
        v = p[key]
        if key == "issued_at":
            if not _is_nonneg_integer_number(v):
                return "bad_field:issued_at"
            continue
        if not _is_str(v) or not STRING_FORMATS[key].fullmatch(v):
            return "bad_field:" + key
    r = p["request"]
    for key in REQUEST_KEY_ORDER:
        v = r[key]
        if not _is_str(v) or not STRING_FORMATS["request." + key].fullmatch(v):
            return "bad_field:request." + key
    return None


@dataclass
class _PinnedKey:
    kid: str
    pub: Ed25519PublicKey
    not_before: Optional[float]
    retired_at: Optional[float]


def _load_pinned_keys(keys: Any) -> Optional[list]:
    """None means bad_pinned_keys."""
    if isinstance(keys, Mapping) and "keys" in keys:
        keys = keys["keys"]  # accept a whole key file too
    if not isinstance(keys, (list, tuple)) or len(keys) == 0:
        return None
    out = []
    for k in keys:
        if not isinstance(k, Mapping):
            return None
        if k.get("kty") != "OKP" or k.get("crv") != "Ed25519":
            return None
        kid = k.get("kid")
        if not _is_str(kid) or not KID_RE.fullmatch(kid):
            return None
        x = k.get("x")
        if not _is_str(x) or len(x) != 43:
            return None
        raw = b64url_decode_strict(x)
        if raw is None or len(raw) != 32:
            return None
        nb = k.get("not_before")
        ra = k.get("retired_at")
        for bound in (nb, ra):
            if bound is not None and not _is_number(bound):
                return None  # non-normative tightening, see AMBIGUITIES.md
        try:
            pub = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError:
            return None
        out.append(_PinnedKey(kid=kid, pub=pub, not_before=nb, retired_at=ra))
    return out


def _as_bytes(v: Any) -> Optional[bytes]:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    return None


# ---------------------------------------------------------------- token shape

def parse_token_shape(token: Any) -> Optional[tuple]:
    """Step 1. Returns (payload_b64url, payload_bytes, signature_bytes) or None (bad_token)."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS:
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        return None
    p64, s64 = parts[1], parts[2]
    if not (1 <= len(p64) <= MAX_PAYLOAD_CHARS) or len(s64) != SIG_CHARS:
        return None
    payload = b64url_decode_strict(p64)
    sig = b64url_decode_strict(s64)
    if payload is None or sig is None or len(sig) != 64:
        return None
    return p64, payload, sig


# ---------------------------------------------------------------- main verification

def verify_receipt(
    token: Any,
    *,
    keys: Any,
    iss: Any,
    expect: Optional[Mapping] = None,
    max_age_seconds: Any = None,
    now_seconds: Any = None,
) -> Verdict:
    """Verify one token. `expect` holds body, request_body (bytes), method, path, network,
    payer, payee, asset, amount_atomic, settlement_ref, model (str)."""
    try:
        return _verify(token, keys, iss, expect, max_age_seconds, now_seconds)
    except Exception:  # pragma: no cover - none expected
        return _fail("verifier_error")


def _verify(token, keys, iss, expect, max_age_seconds, now_seconds) -> Verdict:
    # 1. Token shape.
    shape = parse_token_shape(token)
    if shape is None:
        return _fail("bad_token")
    p64, payload_bytes, sig = shape

    # 2. Signature. Pinned keys first.
    pinned = _load_pinned_keys(keys)
    if pinned is None:
        return _fail("bad_pinned_keys")
    signing_input = DOMAIN + p64.encode("ascii")
    verifying = None
    for k in pinned:
        try:
            k.pub.verify(sig, signing_input)
        except InvalidSignature:
            continue
        verifying = k
        break
    if verifying is None:
        return _fail("bad_signature")

    # 3. One reading.
    try:
        text = payload_bytes.decode("utf-8")  # strict; see AMBIGUITIES.md
        p = _parse_json_strict(text)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _fail("bad_json")
    if not isinstance(p, dict):
        return _fail("bad_json")
    if set(p.keys()) != set(KEY_ORDER) or len(p) != len(KEY_ORDER):
        return _fail("bad_keys")
    req = p["request"]
    if not isinstance(req, dict) or set(req.keys()) != set(REQUEST_KEY_ORDER):
        return _fail("bad_keys")
    bad = _check_formats(p)
    if bad:
        return _fail(bad)
    if _canonical_text(p).encode("utf-8") != payload_bytes:
        return _fail("not_canonical")

    # 4. Issuer and key.
    if p["kid"] != verifying.kid:
        return _fail("mismatch:kid")
    if not _is_str(iss) or not ISS_RE.fullmatch(iss):
        return _fail("missing_expectation:iss")
    if p["iss"] != iss:
        return _fail("mismatch:iss")
    issued_at = p["issued_at"]
    if verifying.not_before is not None and issued_at < verifying.not_before:
        return _fail("key_not_valid_at_issued_at")
    if verifying.retired_at is not None and issued_at >= verifying.retired_at:
        return _fail("key_not_valid_at_issued_at")

    # 5. What the buyer knows. Every expectation is present before any comparison.
    e = dict(expect or {})
    supplied = {
        "body": _as_bytes(e.get("body")),
        "request_body": _as_bytes(e.get("request_body")),
        "max_age_seconds": max_age_seconds if (_is_number(max_age_seconds) and max_age_seconds >= 0) else None,
        "now_seconds": now_seconds if _is_number(now_seconds) else None,
    }
    for name in ("method", "path", "network", "payer", "payee", "asset",
                 "amount_atomic", "settlement_ref", "model"):
        v = e.get(name)
        supplied[name] = v if _is_str(v) else None
    for name in EXPECTATION_ORDER:
        if supplied[name] is None:
            return _fail("missing_expectation:" + name)

    s = supplied
    if p["body_sha256"] != hashlib.sha256(s["body"]).hexdigest():
        return _fail("mismatch:body_sha256")
    if req["method"] != s["method"]:
        return _fail("mismatch:request.method")
    if req["path"] != s["path"]:
        return _fail("mismatch:request.path")
    if req["sha256"] != hashlib.sha256(s["request_body"]).hexdigest():
        return _fail("mismatch:request.sha256")
    if p["network"] != s["network"]:
        return _fail("mismatch:network")
    for name in ("payer", "payee", "asset"):
        if p[name] != s[name].lower():
            return _fail("mismatch:" + name)
    if p["amount_atomic"] != s["amount_atomic"]:
        return _fail("mismatch:amount_atomic")
    if p["settlement_ref"] != s["settlement_ref"].lower():
        return _fail("mismatch:settlement_ref")
    if p["resolved_model"] != s["model"]:
        return _fail("mismatch:resolved_model")

    # 6. Age.
    now = s["now_seconds"]
    if issued_at - now > FUTURE_SKEW_SECONDS:
        return _fail("issued_in_future")
    if now - issued_at > s["max_age_seconds"]:
        return _fail("too_old")

    return Verdict(ok=True, kid=verifying.kid, payload=p)


# ---------------------------------------------------------------- streams

def split_sse_receipt(stream: Any) -> Verdict:
    """Split the trailer off a raw SSE stream. On success ok=True with .body (first n bytes)
    and .token; otherwise reason no_receipt or bad_sse_trailer."""
    try:
        return _split(stream)
    except Exception:  # pragma: no cover
        return _fail("verifier_error")


def _split(stream: Any) -> Verdict:
    data = _as_bytes(stream)
    if data is None:
        return _fail("nonnormative:stream_not_bytes")
    # Last line that starts with ': outbid-receipt='.
    i = data.rfind(b"\n" + SSE_RECEIPT_PREFIX)
    if i >= 0:
        start = i + 1
    elif data.startswith(SSE_RECEIPT_PREFIX):
        start = 0
    else:
        return _fail("no_receipt")
    # The receipt line ends with one \n and one more \n ends the stream.
    rest = data[start + len(SSE_RECEIPT_PREFIX):]
    if not rest.endswith(b"\n\n"):
        return _fail("bad_sse_trailer")
    tok_bytes = rest[:-2]
    if b"\n" in tok_bytes or b"\r" in tok_bytes:
        return _fail("bad_sse_trailer")
    try:
        token = tok_bytes.decode("ascii")
    except UnicodeDecodeError:
        return _fail("bad_sse_trailer")
    if parse_token_shape(token) is None:
        return _fail("bad_sse_trailer")
    # The digest comment directly before it, starting at byte n.
    if start == 0:
        return _fail("bad_sse_trailer")
    before = data[:start - 1]  # drop the \n that ends the digest line
    m = _SSE_DIGEST_AT_END.search(before)
    if m is None:
        return _fail("bad_sse_trailer")
    n_text = m.group(2)
    if len(n_text) > 20:
        return _fail("bad_sse_trailer")
    n = int(n_text)
    if n != m.start():
        return _fail("bad_sse_trailer")
    return Verdict(ok=True, body=data[:n], token=token)


def verify_stream(stream: Any, *, keys: Any, iss: Any, expect: Optional[Mapping] = None,
                  max_age_seconds: Any = None, now_seconds: Any = None) -> Verdict:
    """Split first, then verify the receipt against the first n bytes (overrides expect.body)."""
    sp = split_sse_receipt(stream)
    if not sp.ok:
        return sp
    e = dict(expect or {})
    e["body"] = sp.body
    v = verify_receipt(sp.token, keys=keys, iss=iss, expect=e,
                       max_age_seconds=max_age_seconds, now_seconds=now_seconds)
    v.body, v.token = sp.body, sp.token
    return v


def receipt_from_headers(headers: Mapping[str, str]) -> Optional[str]:
    """Outbid-Receipt first; X-Outbid-Receipt only when the new header is absent.
    Header names compare case-insensitively (HTTP); the value is used as-is apart from
    optional surrounding whitespace (RFC 9110 field-value OWS)."""
    lower = {str(k).lower(): v for k, v in headers.items()}
    for name in ("outbid-receipt", "x-outbid-receipt"):
        if name in lower:
            v = lower[name]
            return v.strip(" \t") if isinstance(v, str) else v
    return None


# ---------------------------------------------------------------- CLI

def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Verify an Outbid-Receipt v1 token or SSE stream.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--token")
    src.add_argument("--token-file")
    src.add_argument("--stream-file", help="raw SSE stream bytes including the trailer")
    ap.add_argument("--keys", required=True, help="JSON file: a key list or a key file with 'keys'")
    ap.add_argument("--iss", help="pinned issuer (default: the key file's 'issuer')")
    ap.add_argument("--body-file")
    ap.add_argument("--request-body-file")
    for name in ("method", "path", "network", "payer", "payee", "asset",
                 "amount-atomic", "settlement-ref", "model"):
        ap.add_argument("--" + name)
    ap.add_argument("--max-age-seconds", type=float)
    ap.add_argument("--now-seconds", type=float)
    a = ap.parse_args(argv)

    keydoc = json.loads(_read(a.keys))
    iss = a.iss if a.iss is not None else (keydoc.get("issuer") if isinstance(keydoc, dict) else None)
    expect: dict = {}
    if a.body_file:
        expect["body"] = _read(a.body_file)
    if a.request_body_file:
        expect["request_body"] = _read(a.request_body_file)
    for name in ("method", "path", "network", "payer", "payee", "asset",
                 "amount_atomic", "settlement_ref", "model"):
        v = getattr(a, name)
        if v is not None:
            expect[name] = v
    now = a.now_seconds if a.now_seconds is not None else time.time()
    common = dict(keys=keydoc, iss=iss, expect=expect,
                  max_age_seconds=a.max_age_seconds, now_seconds=now)
    if a.stream_file:
        v = verify_stream(_read(a.stream_file), **common)
    else:
        tok = a.token if a.token is not None else _read(a.token_file).decode("ascii", "replace").strip()
        v = verify_receipt(tok, **common)
    out = v.to_dict()
    if v.ok and v.payload is not None:
        out["payload"] = v.payload
    print(json.dumps(out, indent=2))
    return 0 if v.ok else 1


if __name__ == "__main__":
    sys.exit(main())
