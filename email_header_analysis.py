#!/usr/bin/env python3
"""Offline feasibility probe for receiver-reported SPF/DKIM/DMARC evidence.

Python 3.10+, standard library only. This does NOT perform authentication.
RFC 8601: https://www.rfc-editor.org/rfc/rfc8601.html
DMARC: https://www.rfc-editor.org/rfc/rfc7489.html
"""

import argparse
import base64
from email import policy
from email.parser import BytesHeaderParser
import hashlib
import json
from pathlib import Path
import re
import sys
import time


MAX_HEADER_BYTES = 262144
RESULTS = {
    "spf": {"none", "pass", "fail", "softfail", "neutral", "temperror", "permerror"},
    "dkim": {"none", "pass", "fail", "policy", "neutral", "temperror", "permerror"},
    "dmarc": {"none", "pass", "fail", "temperror", "permerror"},
}
LIMITATIONS = [
    "PASS means this input supplied complete, interpretable receiver-reported evidence; it does not mean the email is safe or authentic.",
    "No SPF DNS evaluation, DKIM cryptographic verification, DMARC policy lookup, or network requests are performed.",
    "Trust is a caller assertion: use an original export from a known receiver that strips spoofed Authentication-Results for its own authserv-id. An authserv-id match alone is forgeable.",
    "Only outer message headers are read. Forwarded/attached headers, screenshots, and copied sender-provided headers are not trusted exports.",
    "Conservative syntax subset: ASCII Authentication-Results, version 1, compact property names (header.from), exactly one matching trusted header, one SPF and DMARC result; multiple DKIM results are preserved. Other layouts fail closed.",
    "Receiver-reported DMARC is used; relaxed alignment and organizational domains are not independently calculated.",
    "A single message cannot establish population-level accuracy or reliability. Test a labeled set of real receiver exports separately.",
    "Organization names and official domains are caller configuration, not independently verified authoritative identities; display names never establish identity.",
    "Domains must be ASCII or explicit IDNA2008 A-labels (xn--). Unicode domains fail closed rather than using Python's older IDNA mapping.",
]


class ProbeError(ValueError):
    pass


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ProbeError("CLI usage: " + message)


def read_headers(path, evidence):
    """Read only the original outer header block, retaining bytes even on failure."""
    raw = bytearray()
    separated = False
    with Path(path).open("rb") as handle:
        while len(raw) <= MAX_HEADER_BYTES:
            line = handle.readline(MAX_HEADER_BYTES + 1 - len(raw))
            if not line:
                break
            raw.extend(line)
            if line in (b"\r\n", b"\n"):
                separated = True
                break
    data = bytes(raw)
    evidence.update({
        "input_path": str(Path(path).resolve()),
        "raw_headers": data.decode("latin-1"),
        "raw_headers_encoding": "latin-1 byte-preserving representation; base64 is exact",
        "raw_headers_base64": base64.b64encode(data).decode("ascii"),
        "header_sha256": hashlib.sha256(data).hexdigest(),
        "header_bytes": len(data),
        "header_body_separator_present": separated,
        "body_read": False,
        "raw_headers_complete": len(data) <= MAX_HEADER_BYTES,
    })
    if len(data) > MAX_HEADER_BYTES:
        raise ProbeError(f"Header block exceeds {MAX_HEADER_BYTES} bytes; evidence contains only the bounded prefix")
    if not data.strip():
        raise ProbeError("Input has no headers")
    # Reject bare CR, NUL/control bytes, malformed field names, and orphan folds.
    if b"\r" in data.replace(b"\r\n", b""):
        raise ProbeError("Bare CR in header block")
    if any(byte < 32 and byte not in (9, 10, 13) for byte in data) or b"\x7f" in data:
        raise ProbeError("Control character in header block")
    have_field = False
    for line in data.splitlines():
        if not line:
            break
        if line.startswith((b" ", b"\t")):
            if not have_field:
                raise ProbeError("Orphan header continuation")
        elif not re.match(rb"[!-9;-~]+:", line):
            raise ProbeError("Malformed header field (expected Field-Name: value)")
        else:
            have_field = True
    message = BytesHeaderParser(policy=policy.default).parsebytes(data)
    if message.defects:
        raise ProbeError("Email parser defects: " + repr(message.defects))
    return message


def tokenize_auth(value):
    """Tokenize comments and quoted strings without splitting embedded semicolons."""
    value = re.sub(r"\r?\n[ \t]+", " ", value)
    if any(ord(c) < 32 and c != "\t" or ord(c) > 126 for c in value):
        raise ProbeError("Unsupported non-ASCII/control character in Authentication-Results")
    tokens = []
    pos = 0
    while pos < len(value):
        char = value[pos]
        if char in " \t":
            pos += 1
            continue
        if char == "(":
            depth = 1
            pos += 1
            while pos < len(value) and depth:
                if value[pos] == "\\":
                    pos += 2
                    continue
                if value[pos] == "(":
                    depth += 1
                elif value[pos] == ")":
                    depth -= 1
                pos += 1
            if depth:
                raise ProbeError("Unclosed Authentication-Results comment")
            continue
        if char in ";=":
            tokens.append((char, char))
            pos += 1
            continue
        if char == '"':
            pos += 1
            parts = []
            while pos < len(value) and value[pos] != '"':
                if value[pos] == "\\":
                    pos += 1
                    if pos == len(value):
                        raise ProbeError("Dangling escape in quoted value")
                parts.append(value[pos])
                pos += 1
            if pos == len(value):
                raise ProbeError("Unclosed quoted Authentication-Results value")
            pos += 1
            tokens.append(("quoted", "".join(parts)))
            continue
        start = pos
        while pos < len(value) and value[pos] not in ' \t;=()"\\':
            pos += 1
        if pos == start:
            raise ProbeError("Unexpected character in Authentication-Results: " + repr(value[pos]))
        tokens.append(("atom", value[start:pos]))
    return tokens


def parse_auth(value):
    tokens = tokenize_auth(value)
    pos = 0

    def take(kinds):
        nonlocal pos
        if pos >= len(tokens) or tokens[pos][0] not in kinds:
            raise ProbeError(f"Unexpected Authentication-Results token at position {pos}")
        result = tokens[pos][1]
        pos += 1
        return result

    authserv_id = take({"atom", "quoted"})
    if not authserv_id or any(c.isspace() for c in authserv_id):
        raise ProbeError("Empty/unsupported authserv-id")
    version = "1"
    if pos < len(tokens) and tokens[pos][0] != ";":
        version = take({"atom"})
    if version != "1":
        raise ProbeError("Unsupported Authentication-Results version: " + version)
    take({";"})
    if tokens[pos:] == [("atom", "none")]:
        return {"authserv_id": authserv_id, "version": version, "results": []}
    results = []
    while pos < len(tokens):
        method_token = take({"atom"})
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*)(?:/(\d+))?", method_token)
        if not match:
            raise ProbeError("Malformed/unsupported authentication method: " + method_token)
        method, method_version = match.group(1).lower(), match.group(2) or "1"
        if method_version != "1":
            raise ProbeError("Unsupported method version: " + method_token)
        take({"="})
        result = take({"atom"}).lower()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", result):
            raise ProbeError("Malformed authentication result: " + result)
        props = {}
        while pos < len(tokens) and tokens[pos][0] != ";":
            name = take({"atom"}).lower()
            if name != "reason" and not re.fullmatch(r"[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*", name):
                raise ProbeError("Malformed/unsupported property: " + name)
            if name in props:
                raise ProbeError("Duplicate Authentication-Results property: " + name)
            take({"="})
            props[name] = take({"atom", "quoted"})
        results.append({"method": method, "version": method_version, "result": result, "properties": props})
        if pos < len(tokens):
            take({";"})
            if pos == len(tokens):
                raise ProbeError("Trailing semicolon without an authentication result")
    if not results:
        raise ProbeError("Authentication-Results has no results")
    return {"authserv_id": authserv_id, "version": version, "results": results}


def domain(value):
    if not isinstance(value, str) or not value.isascii():
        raise ProbeError("Supply an ASCII domain or explicit IDNA2008 A-label (xn--); Unicode domain conversion is not inferred")
    normalized = value.lower()
    if len(normalized) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in normalized.split(".")):
        raise ProbeError("Invalid domain: " + repr(value))
    return normalized


def analyze(args, report):
    evidence, checks = report["raw_evidence"], report["checks"]
    message = read_headers(args.eml, evidence)
    if any("SYNTHETIC" in str(value).upper() for value in message.get_all("X-Fixture-Notice", [])):
        report["source"]["kind"] = "SYNTHETIC_UNIT_TEST_FIXTURE"
        report["confidence_boundary"]["synthetic_input"] = True
    evidence["authentication_results"] = []
    evidence["related_headers"] = {
        name: [value for field, value in message.raw_items() if field.lower() == name.lower()]
        for name in ("From", "Reply-To", "Return-Path", "Received", "Received-SPF", "DKIM-Signature", "ARC-Authentication-Results")
    }
    parsed_headers = []
    parse_errors = []
    for field, value in message.raw_items():
        if field.lower() != "authentication-results":
            continue
        record = {"raw_value": value, "parsed": None, "parse_error": None}
        try:
            record["parsed"] = parse_auth(value)
            parsed_headers.append(record["parsed"])
        except ProbeError as error:
            record["parse_error"] = str(error)
            parse_errors.append(str(error))
        evidence["authentication_results"].append(record)
    evidence["trust_configuration"] = {
        "trusted_authserv_id": args.trusted_authserv_id,
        "trusted_receiver_export_asserted": args.assert_trusted_receiver_export,
        "provenance_verified_by_script": False,
    }
    checks.append({"name": "header_structure", "status": "PASS"})
    if not args.trusted_authserv_id or not args.assert_trusted_receiver_export:
        raise ProbeError("Trust boundary missing: supply --trusted-authserv-id and --assert-trusted-receiver-export only for a genuine export from that receiver")
    if parse_errors:
        raise ProbeError("Malformed/unsupported Authentication-Results: " + "; ".join(parse_errors))
    trusted = [item for item in parsed_headers if item["authserv_id"] == args.trusted_authserv_id]
    if len(trusted) != 1:
        raise ProbeError(f"Expected exactly one Authentication-Results for trusted authserv-id {args.trusted_authserv_id!r}; found {len(trusted)}")
    checks.append({"name": "receiver_trust", "status": "PASS", "basis": "Explicit caller assertion and exact authserv-id match; provenance not independently verified"})
    from_fields = message.get_all("From", [])
    if len(from_fields) != 1:
        raise ProbeError("Expected exactly one From header")
    from_header = from_fields[0]
    if from_header.defects or len(from_header.addresses) != 1:
        raise ProbeError("Malformed/ambiguous From mailbox: " + repr(from_header.defects))
    sender = from_header.addresses[0]
    if not sender.username or not sender.domain:
        raise ProbeError("From mailbox must have local part and domain")
    from_domain = domain(sender.domain)
    evidence["from_mailbox"] = sender.addr_spec
    evidence["from_domain"] = from_domain
    evidence["from_display_name"] = sender.display_name
    organization_claim = None
    if args.claimed_organization and not args.official_domain:
        raise ProbeError("--claimed-organization requires independently configured --official-domain for comparison")
    if args.official_domain:
        official_domain = domain(args.official_domain)
        domain_matches = from_domain == official_domain or from_domain.endswith("." + official_domain)
        name_matches = bool(args.claimed_organization and args.claimed_organization.casefold() in sender.display_name.casefold())
        organization_claim = {
            "claimed_organization": args.claimed_organization,
            "configured_official_domain": official_domain,
            "from_domain_matches_official_domain": domain_matches,
            "display_name_contains_claimed_organization": name_matches,
            "display_name_spoof_indicator": name_matches and not domain_matches,
            "finding": "domain_consistent_with_configuration" if domain_matches else "domain_conflicts_with_claimed_organization_configuration",
            "authority": "caller_configuration_only",
        }
        evidence["organization_claim_comparison"] = organization_claim
    methods = {name: [result for result in trusted[0]["results"] if result["method"] == name] for name in RESULTS}
    evidence["receiver_reported_results"] = methods
    for method, items in methods.items():
        if not items:
            raise ProbeError("Missing receiver-reported " + method.upper() + " result")
        if method != "dkim" and len(items) != 1:
            raise ProbeError("Ambiguous multiple " + method.upper() + " results")
        for item in items:
            if item["result"] not in RESULTS[method]:
                raise ProbeError("Unsupported " + method.upper() + " result: " + item["result"])
        checks.append({"name": method + "_result_available", "status": "PASS", "reported_results": [item["result"] for item in items]})
    operational_errors = [f"{name}={item['result']}" for name, items in methods.items() for item in items if item["result"] in {"temperror", "permerror"}]
    if operational_errors:
        raise ProbeError("Receiver reported authentication evaluation errors: " + ", ".join(operational_errors))
    spf = methods["spf"][0]
    if spf["result"] != "none" and not any(spf["properties"].get(key) for key in ("smtp.mailfrom", "smtp.helo")):
        raise ProbeError("SPF result omits evaluated smtp.mailfrom/smtp.helo identity")
    for item in methods["dkim"]:
        if item["result"] == "pass" and not any(item["properties"].get(key) for key in ("header.d", "header.i")):
            raise ProbeError("DKIM pass omits evaluated header.d/header.i identity")
    dmarc = methods["dmarc"][0]
    reported_from = dmarc["properties"].get("header.from")
    if not reported_from:
        raise ProbeError("DMARC result omits evaluated header.from domain")
    if domain(reported_from) != from_domain:
        raise ProbeError("Receiver DMARC header.from does not match the actual From domain")
    checks.append({"name": "dmarc_from_identity", "status": "PASS", "domain": from_domain})
    if dmarc["result"] == "pass" and not any(item["result"] == "pass" for name in ("spf", "dkim") for item in methods[name]):
        raise ProbeError("Contradictory results: DMARC pass with neither SPF nor DKIM pass")
    report["result"] = {
        "evidence_state": "CONSISTENT_BUT_NOT_IDENTITY_PROVING",
        "authentication_outcome": "receiver_reported_dmarc_" + dmarc["result"],
        "spf_outcome": spf["result"],
        "dkim_outcomes": [item["result"] for item in methods["dkim"]],
        "dmarc_outcome": dmarc["result"],
        "independent_authentication_performed": False,
        "organization_claim": organization_claim,
        "scam_verdict": "not_determined",
    }


def run_probe(args, synthetic=False):
    started = time.perf_counter()
    report = {
        "capability": "email_header_analysis",
        "input": {"eml": args.eml, "claimed_organization": args.claimed_organization, "official_domain": args.official_domain},
        "raw_evidence": {"network_requests": []},
        "source": {"kind": "SYNTHETIC_UNIT_TEST_FIXTURE" if synthetic else "USER_SUPPLIED_RECEIVER_EXPORT", "path": args.eml, "independently_authenticated": False},
        "latency_ms": None,
        "result": {"evidence_state": "NO_AUTHORITATIVE_DATA", "authentication_outcome": "unresolved"},
        "confidence_boundary": {"live_crypto_verified": False, "synthetic_input": synthetic, "limitations": LIMITATIONS},
        "status": "FAIL",
        "failure_reason": None,
        "checks": [],
    }
    try:
        analyze(args, report)
        report["status"] = "PASS"
    except (ProbeError, OSError, ValueError) as error:
        report["failure_reason"] = f"{type(error).__name__}: {error}"
        report["checks"].append({"name": "feasibility_gate", "status": "FAIL", "reason": str(error)})
    except Exception as error:
        # Unexpected local errors remain visible; never silently fabricate evidence.
        report["failure_reason"] = f"Unexpected {type(error).__name__}: {error}"
        report["checks"].append({"name": "unexpected_error", "status": "FAIL", "reason": str(error)})
    report["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return report


def self_test():
    started = time.perf_counter()
    fixtures = Path(__file__).resolve().parent / "fixtures" / "email"
    cases = [
        ("legitimate_aligned.eml", {"status": "PASS", "spf": "pass", "dmarc": "pass", "domain_match": True, "display_spoof": False}),
        ("display_name_spoof.eml", {"status": "PASS", "spf": "pass", "dmarc": "pass", "domain_match": False, "display_spoof": True}),
        ("wrong_from_domain.eml", {"status": "PASS", "spf": "fail", "dmarc": "fail", "domain_match": False, "display_spoof": False}),
        ("spf_pass_dmarc_misalignment.eml", {"status": "PASS", "spf": "pass", "dmarc": "fail", "domain_match": True, "display_spoof": False}),
        ("valid_multiline.eml", {"status": "PASS", "spf": "pass", "dmarc": "pass", "domain_match": True, "display_spoof": False}),
        ("malformed_headers.eml", {"status": "FAIL", "failure_contains": "Unclosed Authentication-Results comment"}),
    ]
    reports = []
    for filename, expected in cases:
        args = argparse.Namespace(eml=str(fixtures / filename), trusted_authserv_id="mx.receiver.example", assert_trusted_receiver_export=True, claimed_organization="Example Foundation", official_domain="example.org")
        report = run_probe(args, synthetic=True)
        claim = report["result"].get("organization_claim") or {}
        actual = {
            "status": report["status"],
            "spf": report["result"].get("spf_outcome"),
            "dmarc": report["result"].get("dmarc_outcome"),
            "domain_match": claim.get("from_domain_matches_official_domain"),
            "display_spoof": claim.get("display_name_spoof_indicator"),
        }
        assertions = []
        for key, value in expected.items():
            observed = report["failure_reason"] if key == "failure_contains" else actual[key]
            passed = value in (observed or "") if key == "failure_contains" else observed == value
            assertions.append({"field": key, "expected": value, "actual": observed, "passed": passed})
        report["test_expectation"] = {"case_passed": all(item["passed"] for item in assertions), "assertions": assertions}
        reports.append(report)
    passed = sum(item["test_expectation"]["case_passed"] for item in reports)
    return {
        "capability": "email_header_analysis_synthetic_fixture_suite",
        "input": {"mode": "synthetic_unit_tests", "fixture_directory": str(fixtures)},
        "raw_evidence": {"cases": reports},
        "source": {"kind": "SYNTHETIC_UNIT_TEST_FIXTURES", "authoritative": False},
        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "result": {"evidence_state": "CONSISTENT_BUT_NOT_IDENTITY_PROVING" if passed == len(cases) else "NO_AUTHORITATIVE_DATA", "case_passed": passed == len(cases), "passed_cases": passed, "total_cases": len(cases), "assessment_failures": sum(item["status"] == "FAIL" for item in reports), "real_email_feasibility": "UNTESTED"},
        "confidence_boundary": {"live_crypto_verified": False, "synthetic_input": True, "limitations": LIMITATIONS},
        "status": "PASS" if passed == len(cases) else "FAIL",
        "failure_reason": None if passed == len(cases) else "One or more synthetic fixture expectations failed; inspect individual cases",
    }


def main(argv=None):
    started = time.perf_counter()
    parser = JsonArgumentParser(description=__doc__ + "\nNo arguments runs the clearly labeled synthetic fixture suite.", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--eml", help="Path to original .eml or complete outer header export; message body is not read")
    parser.add_argument("--self-test", action="store_true", help="Run bundled synthetic parser fixtures (also the no-argument default)")
    parser.add_argument("--trusted-authserv-id", help="Exact, case-sensitive receiver identifier configured independently of the sender")
    parser.add_argument("--assert-trusted-receiver-export", action="store_true", help="Assert genuine export from that receiver, whose boundary strips forged results for its ID")
    parser.add_argument("--claimed-organization", help="Organization to compare with From display name and configured domain")
    parser.add_argument("--official-domain", help="Independently chosen official domain; exact domain and its subdomains are accepted for comparison")
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        args = parser.parse_args(arguments)
        if args.self_test and args.eml:
            raise ProbeError("--self-test and --eml are mutually exclusive")
        if args.eml:
            report = run_probe(args)
        elif not arguments or args.self_test:
            if args.self_test and len(arguments) != 1:
                raise ProbeError("--self-test cannot be combined with file-mode options")
            report = self_test()
        else:
            raise ProbeError("Specify --eml PATH or --self-test")
    except ProbeError as error:
        report = {"capability": "email_header_analysis", "input": {"arguments": list(sys.argv[1:] if argv is None else argv)}, "raw_evidence": {}, "source": {"kind": "CLI_INPUT"}, "latency_ms": round((time.perf_counter() - started) * 1000, 3), "result": {"evidence_state": "NO_AUTHORITATIVE_DATA"}, "confidence_boundary": {"live_crypto_verified": False, "limitations": LIMITATIONS}, "status": "FAIL", "failure_reason": str(error)}
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
