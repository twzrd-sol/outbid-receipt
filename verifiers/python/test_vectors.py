#!/usr/bin/env python3
"""Run every Outbid-Receipt v1 vector file against outbid_receipt_verify.

Usage: test_vectors.py [VECTORS_DIR]   (or env OUTBID_VECTORS_DIR; default ../../vectors)
Exit status is non-zero on any mismatch. Last line: PASS n/n or FAIL k/n.
"""
from __future__ import annotations

import base64
import copy
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # needed under python3 -I, which drops the script dir

import outbid_receipt_verify as orv  # noqa: E402


def _expect_from_json(e: dict) -> dict:
    """Vector expectations carry bodies as body_utf8 / body_base64 / request_body_utf8."""
    out = {}
    for k, v in e.items():
        if k.endswith("_utf8"):
            out[k[: -len("_utf8")]] = v.encode("utf-8")
        elif k.endswith("_base64"):
            out[k[: -len("_base64")]] = base64.b64decode(v, validate=True)
        else:
            out[k] = v
    return out


def _check(name: str, verdict: orv.Verdict, expected: dict) -> list:
    errs = []
    if verdict.ok != bool(expected.get("ok")):
        errs.append("ok=%s want %s" % (verdict.ok, expected.get("ok")))
    if "reason" in expected and verdict.reason != expected["reason"]:
        errs.append("reason=%r want %r" % (verdict.reason, expected["reason"]))
    if expected.get("ok") and "kid" in expected and verdict.kid != expected["kid"]:
        errs.append("kid=%r want %r" % (verdict.kid, expected["kid"]))
    if not expected.get("ok") and verdict.ok:
        errs.append("negative control accepted")
    return ["%s: %s" % (name, e) for e in errs]


def run_case_file(path: str, doc: dict) -> tuple:
    """A file with "defaults" and "cases" (receipt-vectors.json)."""
    results = []
    defaults = doc["defaults"]
    for case in doc["cases"]:
        w = case.get("with", {})
        keys = copy.deepcopy(w.get("keys", defaults["keys"]))
        iss = w.get("iss", defaults["iss"])
        now = w.get("now_seconds", defaults["now_seconds"])
        max_age = w.get("max_age_seconds", defaults["max_age_seconds"])
        exp = dict(defaults["expect"])
        exp.update(w.get("expect", {}))
        for k in w.get("expect_remove", []):
            exp.pop(k, None)
        expect = _expect_from_json(exp)
        common = dict(keys=keys, iss=iss, expect=expect, max_age_seconds=max_age, now_seconds=now)
        if "stream_utf8" in case:
            v = orv.verify_stream(case["stream_utf8"].encode("utf-8"), **common)
        elif "token" in case:
            v = orv.verify_receipt(case["token"], **common)
        else:
            results.append((case.get("name"), ["%s: case has neither token nor stream_utf8" % case.get("name")]))
            continue
        results.append((case["name"], _check(case["name"], v, case["expected"])))
    return results


def run_fixture(path: str, doc: dict) -> tuple:
    """A single live receipt with keys, iss, expect, max_age_seconds, now_seconds, result."""
    expect = _expect_from_json(doc["expect"])
    v = orv.verify_receipt(doc["token"], keys=doc["keys"], iss=doc["iss"], expect=expect,
                           max_age_seconds=doc["max_age_seconds"], now_seconds=doc["now_seconds"])
    name = os.path.basename(path)
    errs = _check(name, v, doc["result"])
    # Extra consistency checks the fixture's onchain block allows (no network used).
    oc = doc.get("onchain") or {}
    if v.ok and oc:
        p = v.payload
        if oc.get("tx") and oc["tx"].lower() != p["settlement_ref"]:
            errs.append("%s: onchain.tx != settlement_ref" % name)
        if oc.get("network") and oc["network"] != p["network"]:
            errs.append("%s: onchain.network != network" % name)
        amt = oc.get("usdc_transfer_payer_to_payee_atomic")
        if amt is not None and amt != p["amount_atomic"]:
            errs.append("%s: onchain amount != amount_atomic" % name)
    results = [(name, errs)]
    # Negative controls derived from the live receipt: they must all be refused.
    tok = doc["token"]
    controls = {
        "live/tampered_signature": (tok[:-2] + ("A" if tok[-2] != "A" else "B") + tok[-1], {}, "bad_signature"),
        "live/other_body": (tok, {"body": expect["body"] + b" "}, "mismatch:body_sha256"),
        "live/other_model": (tok, {"model": "paid/other"}, "mismatch:resolved_model"),
        "live/too_old": (tok, {"_now": doc["now_seconds"] + doc["max_age_seconds"] + 10}, "too_old"),
    }
    for cname, (t, over, reason) in controls.items():
        e = dict(expect)
        now = over.pop("_now", doc["now_seconds"])
        e.update(over)
        cv = orv.verify_receipt(t, keys=doc["keys"], iss=doc["iss"], expect=e,
                                max_age_seconds=doc["max_age_seconds"], now_seconds=now)
        results.append((cname, _check(cname, cv, {"ok": False, "reason": reason})))
    return results


def main(argv) -> int:
    vdir = (argv[1] if len(argv) > 1 else None) or os.environ.get("OUTBID_VECTORS_DIR") \
        or os.path.join(HERE, "..", "..", "vectors")
    files = sorted(glob.glob(os.path.join(vdir, "*.json")))
    if not files:
        print("FAIL 0/0 (no vector files in %s)" % vdir)
        return 2
    total, failed = 0, 0
    for path in files:
        with open(path, "rb") as f:
            doc = json.loads(f.read())
        if "cases" in doc:
            res = run_case_file(path, doc)
        elif "token" in doc and "result" in doc:
            res = run_fixture(path, doc)
        else:
            print("%s: unrecognised vector file" % os.path.basename(path))
            failed += 1
            total += 1
            continue
        nfail = sum(1 for _, e in res if e)
        print("%s: %d cases, %d failed" % (os.path.basename(path), len(res), nfail))
        for _, errs in res:
            for e in errs:
                print("  MISMATCH " + e)
        total += len(res)
        failed += nfail
    if failed:
        print("FAIL %d/%d" % (total - failed, total))
        return 1
    print("PASS %d/%d" % (total, total))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
