#!/usr/bin/env python3
"""Small, deterministic feasibility probe; no NLP and no universal scam rules.

Run --self-test for explicitly synthetic, offline engine tests. A normal run
accepts JSON input and independently chosen --authority-host values, retrieves
every policy source live, and checks its exact quote before comparing typed facts.
See examples/contradiction_case.json for the input shape. PASS means the specified
comparisons were possible, including when their verdict is CONTRADICTED.
No arguments runs the three India examples, whose observed messages are synthetic.
"""

import argparse
import base64
import copy
import hashlib
import html.parser
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


CAPABILITY = "deterministic_scam_process_contradictions"
MAX_BYTES = 2 * 1024 * 1024
SCOPE_KEYS = {"organization", "process", "stage", "jurisdiction"}
KINDS = {"upfront_payment", "urgent_transfer", "payment_channel", "credential_request", "interview_requirement"}
DEFAULT_HOSTS = {"www.infosys.com", "www.cert-in.org.in", "sbi.bank.in", "home.sbi.bank.in"}
STATES = {"CONTRADICTED": "CONTRADICTED_BY_AUTHORITATIVE_SOURCE",
          "NO_CONTRADICTION_FOUND": "CONSISTENT_BUT_NOT_IDENTITY_PROVING",
          "INSUFFICIENT": "NO_AUTHORITATIVE_DATA"}
LIMITATIONS = [
    "PASS measures evidence retrieval and explicit fact comparison, not whether a message is a scam or safe.",
    "An operator must independently choose authoritative hosts and correctly interpret policy scope, quote, and observation facts. Quote presence does not verify that interpretation.",
    "Scopes must match exactly. No fuzzy matching, text inference, urgency scoring, or universal payment/interview/credential rule is used.",
    "Live HTTPS HTML/plain-text only; blocked pages, HTTP errors, unsupported content, and missing quotes fail visibly. Dynamic-only text and PDFs are unsupported.",
    "Observation text is supplied by the operator and its authenticity is not verified. Synthetic examples cannot establish real-world detection accuracy.",
    "Bank credential comparisons concern disclosure to a caller; they do not prohibit entering an OTP/password into the bank's own legitimate authentication flow.",
    "The police example concerns immediate money pressure during a claimed investigation; it does not classify every government fee, fine, or transfer as illegitimate.",
]


class InputError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError(message)


def norm(value):
    return " ".join(value.split())


def require_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{label} must be a nonempty string")


def require_bool(value, label):
    if type(value) is not bool:
        raise InputError(f"{label} must be true or false; unknown/null is insufficient evidence")


def string_list(value, label, allow_empty=False):
    if not isinstance(value, list) or (not value and not allow_empty):
        raise InputError(f"{label} must be {'a' if allow_empty else 'a nonempty'} string list")
    for item in value:
        require_text(item, label)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", item):
            raise InputError(f"{label} uses lowercase tokens such as gift_card, password, or otp")
    if len(value) != len(set(value)):
        raise InputError(f"{label} contains duplicate tokens")


def exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise InputError(f"{label} must have exactly these keys: {', '.join(sorted(expected))}")


def validate_case(case):
    exact_keys(case, {"id", "kind", "policy", "observation"}, "check")
    require_text(case["id"], "check.id")
    if case["kind"] not in KINDS:
        raise InputError(f"unsupported kind {case['kind']!r}; choose {', '.join(sorted(KINDS))}")
    policy, observation = case["policy"], case["observation"]
    exact_keys(policy, {"scope", "source_url", "quote", "fact"}, "policy")
    exact_keys(observation, {"scope", "raw_text", "excerpt", "fact"}, "observation")
    for name, record in (("policy", policy), ("observation", observation)):
        exact_keys(record["scope"], SCOPE_KEYS, f"{name}.scope")
        for key, value in record["scope"].items():
            require_text(value, f"{name}.scope.{key}")
    require_text(policy["source_url"], "policy.source_url")
    quotes = policy["quote"] if isinstance(policy["quote"], list) else [policy["quote"]]
    if not quotes:
        raise InputError("policy.quote must contain at least one exact quote")
    for quote in quotes:
        require_text(quote, "policy.quote")
    for key in ("raw_text", "excerpt"):
        require_text(observation[key], f"observation.{key}")
    if norm(observation["excerpt"]) not in norm(observation["raw_text"]):
        raise InputError("observation.excerpt does not occur in observation.raw_text")
    p, o = policy["fact"], observation["fact"]
    if case["kind"] in {"upfront_payment", "urgent_transfer"}:
        exact_keys(p, {"allowed"}, "policy.fact")
        exact_keys(o, {"requested"}, "observation.fact")
        require_bool(p["allowed"], "policy.fact.allowed")
        require_bool(o["requested"], "observation.fact.requested")
    elif case["kind"] in {"payment_channel", "credential_request"}:
        exact_keys(p, {"forbidden"}, "policy.fact")
        exact_keys(o, {"requested"}, "observation.fact")
        string_list(p["forbidden"], "policy.fact.forbidden")
        string_list(o["requested"], "observation.fact.requested", allow_empty=True)
    else:
        exact_keys(p, {"required"}, "policy.fact")
        exact_keys(o, {"required"}, "observation.fact")
        require_bool(p["required"], "policy.fact.required")
        require_bool(o["required"], "observation.fact.required")


def evaluate_facts(case):
    """Call only after validation and, for normal runs, policy quote verification."""
    if case["policy"]["scope"] != case["observation"]["scope"]:
        return {"verdict": "INSUFFICIENT", "failure_reason": "Policy and observation scopes do not match exactly."}
    p, o = case["policy"]["fact"], case["observation"]["fact"]
    kind = case["kind"]
    matched = []
    if kind in {"upfront_payment", "urgent_transfer"}:
        contradiction = p["allowed"] is False and o["requested"] is True
        rule = "Payment requested although the scoped policy forbids it." if kind == "upfront_payment" else "Immediate money transfer pressured although the scoped authority statement rules it out."
    elif kind in {"payment_channel", "credential_request"}:
        matched = sorted(set(p["forbidden"]) & set(o["requested"]))
        contradiction = bool(matched)
        rule = "Requested tokens intersect the scoped policy's explicit forbidden tokens."
    else:
        contradiction = p["required"] is True and o["required"] is False
        rule = "Observation explicitly waives an interview required by the scoped policy."
    return {
        "verdict": "CONTRADICTED" if contradiction else "NO_CONTRADICTION_FOUND",
        "failure_reason": None,
        "comparison": rule,
        "matched_tokens": matched,
    }


class VisibleText(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "template"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "template"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def checked_url(url, hosts):
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputError(f"Invalid policy URL port: {exc}") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or port not in (None, 443):
        raise InputError("Policy URLs must use HTTPS on port 443 with no URL credentials.")
    if parsed.hostname.lower() not in hosts:
        raise InputError(f"Policy host {parsed.hostname!r} is absent from independently supplied --authority-host values.")


class CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts, history):
        self.hosts, self.history = hosts, history

    def redirect_request(self, request, fp, code, message, headers, newurl):
        entry = {"from": request.full_url, "status": code, "to": newurl, "headers": list(headers.items())}
        self.history.append(entry)
        checked_url(newurl, self.hosts)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def fetch_policy(url, hosts, timeout):
    started = time.perf_counter()
    evidence = {"url": url, "redirects": [], "http_status": None, "headers": [], "raw_body": None,
                "response_truncated": False, "error": None}
    visible = None
    try:
        checked_url(url, hosts)
        opener = urllib.request.build_opener(CheckedRedirect(hosts, evidence["redirects"]))
        request = urllib.request.Request(url, headers={"User-Agent": "HackathonFeasibilityProbe/1.0", "Accept": "text/html,text/plain"})
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            evidence["http_status"] = response.status
            evidence["final_url"] = response.geturl()
            evidence["headers"] = list(response.headers.items())
            raw = response.read(MAX_BYTES + 1)
            evidence["response_truncated"] = len(raw) > MAX_BYTES
            evidence["raw_body_base64"] = base64.b64encode(raw[:MAX_BYTES]).decode("ascii")
            evidence["captured_sha256"] = hashlib.sha256(raw[:MAX_BYTES]).hexdigest()
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                body = raw[:MAX_BYTES].decode(charset, errors="replace")
            except LookupError:
                body = raw[:MAX_BYTES].decode("utf-8", errors="replace")
                evidence["charset_warning"] = f"Unknown charset {charset!r}; UTF-8 replacement decoding used."
            evidence["raw_body"] = body
            if not 200 <= response.status < 300:
                raise InputError(f"Policy HTTP request failed: status {response.status}.")
            if evidence["response_truncated"]:
                raise InputError(f"Policy response exceeds {MAX_BYTES} bytes; raw evidence is explicitly truncated.")
            mime = response.headers.get_content_type()
            if mime in {"text/html", "application/xhtml+xml"}:
                parser = VisibleText()
                parser.feed(body)
                visible = norm(" ".join(parser.parts))
            elif mime == "text/plain":
                visible = norm(body)
            else:
                raise InputError(f"Unsupported policy content type {mime!r}; only HTML/plain text is supported.")
    except Exception as exc:
        evidence["error"] = {"type": type(exc).__name__, "message": str(exc)}
    evidence["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return evidence, visible


def self_test():
    """Generated records are synthetic local assertions, never network responses."""
    scope = {"organization": "SYNTHETIC", "process": "SYNTHETIC", "stage": "SYNTHETIC", "jurisdiction": "SYNTHETIC"}
    base = {"id": "synthetic", "kind": "upfront_payment",
            "policy": {"scope": scope, "source_url": "https://synthetic.invalid/policy", "quote": "Synthetic policy text.", "fact": {"allowed": False}},
            "observation": {"scope": scope, "raw_text": "Synthetic observation text.", "excerpt": "Synthetic observation text.", "fact": {"requested": True}}}
    results = []
    for kind, policy, observed_yes, observed_no in [
        ("upfront_payment", {"allowed": False}, {"requested": True}, {"requested": False}),
        ("urgent_transfer", {"allowed": False}, {"requested": True}, {"requested": False}),
        ("payment_channel", {"forbidden": ["gift_card"]}, {"requested": ["gift_card"]}, {"requested": ["bank_transfer"]}),
        ("credential_request", {"forbidden": ["otp", "password"]}, {"requested": ["otp"]}, {"requested": []}),
        ("interview_requirement", {"required": True}, {"required": False}, {"required": True}),
    ]:
        for fact, expected in ((observed_yes, "CONTRADICTED"), (observed_no, "NO_CONTRADICTION_FOUND")):
            case = copy.deepcopy(base)
            case.update(id=f"{kind}:{expected}", kind=kind)
            case["policy"]["fact"], case["observation"]["fact"] = policy, fact
            started = time.perf_counter()
            validate_case(case)
            actual = evaluate_facts(case)["verdict"]
            results.append({"id": case["id"], "expected": expected, "actual": actual, "raw_fixture": case,
                            "case_passed": actual == expected, "evidence_state": "NO_AUTHORITATIVE_DATA",
                            "status": "PASS" if actual == expected else "FAIL", "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                            "failure_reason": None if actual == expected else "Synthetic assertion mismatch."})
    for mutation, expected in (("scope_mismatch", "INSUFFICIENT"), ("unknown_null", "REJECTED"), ("excerpt_missing", "REJECTED"), ("malformed_fact", "REJECTED")):
        case = copy.deepcopy(base)
        if mutation == "scope_mismatch":
            case["observation"]["scope"] = dict(scope, stage="OTHER")
        elif mutation == "unknown_null":
            case["observation"]["fact"]["requested"] = None
        elif mutation == "excerpt_missing":
            case["observation"]["excerpt"] = "Absent text."
        else:
            case["policy"]["fact"] = {"allowed": "false"}
        started = time.perf_counter()
        error = None
        try:
            validate_case(case)
            actual = evaluate_facts(case)["verdict"]
        except InputError as exc:
            actual, error = "REJECTED", str(exc)
        results.append({"id": mutation, "expected": expected, "actual": actual, "raw_fixture": case, "rejection_reason": error,
                        "case_passed": actual == expected, "evidence_state": "NO_AUTHORITATIVE_DATA",
                        "status": "PASS" if actual == expected else "FAIL", "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                        "failure_reason": None if actual == expected else "Synthetic assertion mismatch."})
    return results


def main(argv=None):
    started = time.perf_counter()
    report = {"capability": CAPABILITY, "status": "FAIL", "latency_ms": 0, "failure_reason": None,
              "evidence": {}, "checks": [], "evidence_state": "NO_AUTHORITATIVE_DATA", "limitations": LIMITATIONS}
    try:
        parser = Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument("--input", type=Path, help="JSON file: dataset_origin and checks; default: three synthetic India observations with live policy retrieval")
        parser.add_argument("--authority-host", action="append", default=[], help="Independently identified authority hostname; repeat for redirects. No wildcards.")
        parser.add_argument("--timeout", type=float, default=12.0, help="HTTP socket timeout in seconds (default 12; not a total-run deadline)")
        parser.add_argument("--self-test", action="store_true", help="Run labeled synthetic local engine tests only; performs no network requests")
        args = parser.parse_args(argv)
        if args.self_test:
            if args.input or args.authority_host:
                raise InputError("--self-test cannot be combined with --input or --authority-host")
            report["evidence"] = {"dataset_origin": "synthetic_self_test", "network_requests": 0, "live_policy_verified": False}
            report["checks"] = self_test()
            report["status"] = "PASS" if all(c["status"] == "PASS" for c in report["checks"]) else "FAIL"
            report["failure_reason"] = None if report["status"] == "PASS" else "One or more synthetic engine assertions failed."
        else:
            using_defaults = args.input is None
            if using_defaults:
                args.input = Path(__file__).resolve().parent / "examples" / "contradiction_case.json"
            if not math.isfinite(args.timeout) or not 0 < args.timeout <= 120:
                raise InputError("--timeout must be finite and between 0 and 120 seconds")
            hosts = {host.lower().strip() for host in args.authority_host} or (DEFAULT_HOSTS if using_defaults else set())
            if not hosts or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or "." not in host for host in hosts):
                raise InputError("At least one independently chosen valid --authority-host hostname is required")
            report["evidence"]["authority_hosts_operator_asserted"] = sorted(hosts)
            raw_input = args.input.read_text(encoding="utf-8-sig")
            report["evidence"]["raw_input"] = raw_input
            data = json.loads(raw_input)
            exact_keys(data, {"dataset_origin", "checks"}, "input")
            if data["dataset_origin"] not in {"operator_supplied", "synthetic_example"}:
                raise InputError("dataset_origin must be operator_supplied or synthetic_example")
            report["evidence"]["dataset_origin"] = data["dataset_origin"]
            if not isinstance(data["checks"], list) or not data["checks"]:
                raise InputError("checks must be a nonempty list")
            seen_ids = set()
            fetched = {}
            report["evidence"]["policy_fetches"] = []
            for index, case in enumerate(data["checks"]):
                case_started = time.perf_counter()
                check = {"input": {"index": index, "id": case.get("id") if isinstance(case, dict) else None, "dataset_origin": data["dataset_origin"]},
                         "raw_evidence": {"observation": case.get("observation") if isinstance(case, dict) else case},
                         "source": {}, "latency_ms": 0, "result": {"evidence_state": "NO_AUTHORITATIVE_DATA"},
                         "confidence_boundary": "Deterministic comparison of operator-normalized facts in the exact scope; no sender identity verification or automatic text understanding.",
                         "status": "FAIL", "failure_reason": None}
                try:
                    validate_case(case)
                    if case["id"] in seen_ids:
                        raise InputError(f"Duplicate check id {case['id']!r}")
                    seen_ids.add(case["id"])
                    url = case["policy"]["source_url"]
                    if url not in fetched:
                        fetched[url] = fetch_policy(url, hosts, args.timeout)
                        report["evidence"]["policy_fetches"].append(fetched[url][0])
                    evidence, visible = fetched[url]
                    check["source"] = {"url": url, "quote": case["policy"]["quote"], "scope": case["policy"]["scope"], "live_fetch_evidence_index": list(fetched).index(url)}
                    if evidence["error"]:
                        raise InputError(f"Policy source retrieval failed: {evidence['error']['type']}: {evidence['error']['message']}")
                    quotes = case["policy"]["quote"] if isinstance(case["policy"]["quote"], list) else [case["policy"]["quote"]]
                    check["source"]["quote_matches"] = [{"quote": quote, "found": norm(quote) in visible} for quote in quotes]
                    if not all(item["found"] for item in check["source"]["quote_matches"]):
                        raise InputError("Exact policy quote was absent from retrieved visible text (whitespace normalized).")
                    result = evaluate_facts(case)
                    check["failure_reason"] = result.pop("failure_reason")
                    check["result"] = {"evidence_state": STATES[result.pop("verdict")], **result}
                    check["status"] = "FAIL" if check["result"]["evidence_state"] == "NO_AUTHORITATIVE_DATA" else "PASS"
                except Exception as exc:
                    check["failure_reason"] = f"{type(exc).__name__}: {exc}"
                check["latency_ms"] = round((time.perf_counter() - case_started) * 1000, 3)
                report["checks"].append(check)
            failures = [c for c in report["checks"] if c["status"] == "FAIL"]
            report["status"] = "FAIL" if failures else "PASS"
            report["failure_reason"] = f"{len(failures)} of {len(report['checks'])} configured checks could not be evaluated; see per-check failure_reason." if failures else None
            states = [c["result"]["evidence_state"] for c in report["checks"]]
            report["evidence_state"] = "CONTRADICTED_BY_AUTHORITATIVE_SOURCE" if "CONTRADICTED_BY_AUTHORITATIVE_SOURCE" in states else ("NO_AUTHORITATIVE_DATA" if failures else "CONSISTENT_BUT_NOT_IDENTITY_PROVING")
            report["counts"] = {"configured": len(report["checks"]), "passed": len(report["checks"]) - len(failures), "failed": len(failures)}
    except Exception as exc:
        report["failure_reason"] = f"{type(exc).__name__}: {exc}"
    report["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
    raw_evidence = report["evidence"]
    output = {
        "capability": CAPABILITY,
        "input": {"arguments": list(sys.argv[1:] if argv is None else argv), "dataset_origin": raw_evidence.get("dataset_origin")},
        "raw_evidence": raw_evidence,
        "source": [{"url": item["url"], "http_status": item.get("http_status"), "error": item.get("error")} for item in raw_evidence.get("policy_fetches", [])],
        "latency_ms": report["latency_ms"],
        "result": {"evidence_state": report["evidence_state"], "counts": report.get("counts"), "synthetic_test_cases_passed": sum(c.get("case_passed", False) for c in report["checks"]) if raw_evidence.get("dataset_origin") == "synthetic_self_test" else None},
        "confidence_boundary": LIMITATIONS,
        "status": report["status"],
        "failure_reason": report["failure_reason"],
        "checks": report["checks"],
    }
    print(json.dumps(output, indent=2, ensure_ascii=True))
    return 0 if output["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
