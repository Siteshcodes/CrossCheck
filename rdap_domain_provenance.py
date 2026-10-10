#!/usr/bin/env python3
"""Standalone RDAP feasibility probe. Python 3.10+, standard library only."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import re
import sys
import time
from urllib.error import HTTPError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
VERIFIED = "VERIFIED_BY_AUTHORITATIVE_SOURCE"
CONSISTENT = "CONSISTENT_BUT_NOT_IDENTITY_PROVING"
NO_DATA = "NO_AUTHORITATIVE_DATA"
DEFAULTS = [("microsoft.com", "Microsoft"), ("nvidia.com", "NVIDIA"), ("google.com", "Google")]


class ProbeError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ProbeError("CLI: " + message)


def domain_name(value):
    """Require ASCII/A-labels rather than silently use Python's older IDNA mapping."""
    value = (value[:-1] if value.endswith(".") else value).lower()
    if not value.isascii():
        raise ProbeError("Supply an ASCII domain or IDNA2008 A-label (xn--); Unicode conversion is not inferred")
    if len(value) > 253 or "." not in value:
        raise ProbeError("Supply a full domain, without a URL, path, email address or port")
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise ProbeError("Invalid DNS label in supplied domain")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ProbeError("An IP address is not a domain")


def compare_domain(domain, official):
    return {
        "official_domain_supplied": official,
        "exact_match": domain == official,
        "is_subdomain_of_official": domain.endswith("." + official),
        "evidence_state": CONSISTENT,
        "boundary": "Literal comparison with the supplied official domain; does not independently establish that organization's domain or sender identity.",
    }


class LoggedRedirects(HTTPRedirectHandler):
    def __init__(self, evidence):
        super().__init__()
        self.evidence = evidence

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urljoin(req.full_url, newurl)
        self.evidence.append({"from": req.full_url, "to": target, "http_status": code, "headers": list(headers.items())})
        parsed = urlsplit(target)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ProbeError("RDAP redirect is not credential-free HTTPS: " + target)
        return super().redirect_request(req, fp, code, msg, headers, target)


def fetch_json(url, evidence, timeout, max_bytes):
    started = time.perf_counter()
    item = {"requested_url": url, "retrieved_at_utc": datetime.now(timezone.utc).isoformat(), "redirects": [], "http_status": None, "response_headers": [], "raw_body": None, "error": None}
    evidence.append(item)
    try:
        request = Request(url, headers={"User-Agent": "FeasibilityProbe/1.0 (RDAP research)", "Accept": "application/rdap+json, application/json", "Accept-Encoding": "identity"})
        opener = build_opener(LoggedRedirects(item["redirects"]))
        try:
            response = opener.open(request, timeout=timeout)
        except HTTPError as exc:
            response = exc  # Keep the actual error response body and headers.
        with response:
            item["http_status"] = response.code
            item["final_url"] = response.geturl()
            item["response_headers"] = list(response.headers.items())
            raw = response.read(max_bytes + 1)
        item["body_truncated"] = len(raw) > max_bytes
        raw = raw[:max_bytes]
        item["captured_bytes"] = len(raw)
        item["captured_sha256"] = hashlib.sha256(raw).hexdigest()
        item["raw_body_base64"] = base64.b64encode(raw).decode("ascii")
        item["raw_body"] = raw.decode("utf-8", errors="replace")
        if item["http_status"] != 200:
            raise ProbeError("HTTP %s from %s" % (item["http_status"], url))
        if item["body_truncated"]:
            raise ProbeError("Response exceeded --max-bytes; evidence incomplete")
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise ProbeError("Invalid JSON response: " + str(exc)) from exc
        if not isinstance(parsed, dict):
            raise ProbeError("Expected a JSON object")
        return parsed
    except Exception as exc:
        item["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        item["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)


def select_service(bootstrap, domain):
    services = bootstrap.get("services")
    if not isinstance(services, list):
        raise ProbeError("IANA bootstrap is missing the services array")
    candidates = []
    for entry in services:
        if not isinstance(entry, list) or len(entry) != 2:
            raise ProbeError("Malformed service entry in IANA bootstrap")
        suffixes, urls = entry
        if not isinstance(suffixes, list) or not isinstance(urls, list):
            raise ProbeError("Malformed bootstrap suffixes or URLs")
        for suffix in suffixes:
            if not isinstance(suffix, str):
                raise ProbeError("Malformed bootstrap suffix")
            if domain == suffix or domain.endswith("." + suffix):
                for url in urls:
                    if not isinstance(url, str):
                        raise ProbeError("Malformed bootstrap URL")
                    p = urlsplit(url)
                    if p.scheme == "https" and p.hostname and not p.username and not p.password and not p.query and not p.fragment and url.endswith("/"):
                        candidates.append((len(suffix.split(".")), suffix, url))
    if not candidates:
        raise ProbeError("No HTTPS RDAP service in the IANA bootstrap for this domain")
    longest = max(c[0] for c in candidates)
    matches = [c for c in candidates if c[0] == longest]
    return {"matched_suffix": matches[0][1], "selected_base_url": matches[0][2], "available_https_services": list(dict.fromkeys(c[2] for c in matches))}


def entity_contacts(data):
    found = []
    entities = data.get("entities", [])
    if not isinstance(entities, list):
        raise ProbeError("RDAP entities must be an array")
    for entity in entities:
        if not isinstance(entity, dict):
            raise ProbeError("Malformed RDAP entity")
        roles = entity.get("roles", [])
        if not isinstance(roles, list) or any(not isinstance(role, str) or not role.strip() for role in roles):
            raise ProbeError("RDAP entity roles must be an array of nonempty strings")
        vcard = entity.get("vcardArray", [])
        fields = {}
        if vcard:
            if not isinstance(vcard, list) or len(vcard) != 2 or vcard[0] != "vcard" or not isinstance(vcard[1], list):
                raise ProbeError("Malformed RDAP entity vcardArray")
            for field in vcard[1]:
                if not isinstance(field, list) or len(field) != 4 or not isinstance(field[0], str):
                    raise ProbeError("Malformed RDAP entity vCard field")
                if field[0] in ("fn", "org", "email", "tel"):
                    values = field[3] if isinstance(field[3], list) else [field[3]]
                    if any(not isinstance(value, str) for value in values):
                        raise ProbeError("Nontextual RDAP contact field")
                    fields.setdefault(field[0], []).extend(value for value in values if value.strip())
        found.append({"handle": entity.get("handle"), "roles": roles, "public_ids": entity.get("publicIds", []), "contact_fields": fields})
    return found


def run_case(domain, organization, official, args):
    started = time.perf_counter()
    out = {
        "input": {"domain": domain, "claimed_organization": organization, "official_domain": official, "dataset_origin": "live_public_rdap"},
        "raw_evidence": [],
        "source": {"bootstrap_url": BOOTSTRAP},
        "latency_ms": None,
        "result": {"evidence_state": NO_DATA},
        "confidence_boundary": [
            "PASS requires a real domain RDAP record, usable registration date, and a named registrar. This is metadata feasibility, not a scam verdict.",
            "RDAP records current registration metadata; registration age is not proof of ownership continuity, sender identity, or legitimacy.",
            "Registry responses can redact registrants. Registrar identity is not registrant identity. No registrar referral or historical WHOIS lookup is performed.",
            "The exact supplied domain is queried. A subdomain is not silently replaced with a registrable parent.",
            "One selected HTTPS service, no cache/retries/hidden fallback. Timeout bounds each blocking socket operation, not total wall time.",
        ],
        "status": "FAIL", "failure_reason": None,
    }
    try:
        domain = domain_name(domain)
        out["input"]["normalized_domain"] = domain
        if official:
            out["result"]["organization_domain_comparison"] = compare_domain(domain, domain_name(official))
        bootstrap = fetch_json(BOOTSTRAP, out["raw_evidence"], args.timeout, args.max_bytes)
        selection = select_service(bootstrap, domain)
        out["source"].update(selection)
        rdap_url = selection["selected_base_url"] + "domain/" + quote(domain, safe="")
        out["source"]["queried_rdap_url"] = rdap_url
        record = fetch_json(rdap_url, out["raw_evidence"], args.timeout, args.max_bytes)
        if record.get("objectClassName") != "domain":
            raise ProbeError("RDAP response is not a domain object")
        returned = record.get("ldhName")
        if not isinstance(returned, str) or domain_name(returned) != domain:
            raise ProbeError("RDAP ldhName does not match the queried domain")
        events = record.get("events", [])
        if not isinstance(events, list):
            raise ProbeError("Malformed RDAP events")
        registered = [e.get("eventDate") for e in events if isinstance(e, dict) and e.get("eventAction") == "registration"]
        entities = entity_contacts(record)
        registrars = [e for e in entities if "registrar" in e["roles"]]
        registrants = [e for e in entities if "registrant" in e["roles"]]
        out["result"].update({"record_domain": returned, "registration_dates_raw": registered, "registrars": registrars, "registrants": registrants, "domain_status": record.get("status", []), "events": events, "nameservers": record.get("nameservers", []), "redacted": record.get("redacted", []), "registration_date": None, "age_days": None, "registrant_identity": "UNRESOLVED"})
        if len(set(registered)) != 1:
            raise ProbeError("Registration date missing or ambiguous")
        stamp = registered[0]
        if not isinstance(stamp, str):
            raise ProbeError("Registration date is not a string")
        registration = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if registration.tzinfo is None:
            raise ProbeError("Registration date has no timezone")
        now = datetime.now(timezone.utc)
        if registration > now:
            raise ProbeError("RDAP registration date is in the future")
        out["result"].update({"registration_date": registration.isoformat(), "age_as_of_utc": now.isoformat(), "age_days": (now - registration).days})
        if not registrars or not any(e["contact_fields"].get("fn") or e["contact_fields"].get("org") for e in registrars):
            raise ProbeError("Named registrar absent in registry RDAP response")
        out["result"]["evidence_state"] = VERIFIED
        if args.require_registrant:
            raise ProbeError("Registrant identity remains UNRESOLVED: a returned name cannot independently prove current ownership")
        out["status"] = "PASS"
    except Exception as exc:
        out["failure_reason"] = f"{type(exc).__name__}: {exc}"
    out["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return out


def fixture_cases():
    cases = [
        ("microsoft.com", "microsoft.com", True, False),
        ("micros0ft.example", "microsoft.com", False, False),
        ("nvidia.com.attacker.example", "nvidia.com", False, False),
        ("google-security.example", "google.com", False, False),
        ("careers.microsoft.com", "microsoft.com", False, True),
    ]
    outputs = []
    for domain, official, exact, subdomain in cases:
        started = time.perf_counter()
        result = compare_domain(domain_name(domain), domain_name(official))
        passed = result["exact_match"] == exact and result["is_subdomain_of_official"] == subdomain
        outputs.append({"input": {"domain": domain, "official_domain": official, "dataset_origin": "synthetic_local_comparison_fixture"}, "raw_evidence": {"domain_literal": domain, "official_domain_literal": official, "expected_exact_match": exact, "expected_subdomain": subdomain}, "source": "Local synthetic input; no network request and no fabricated RDAP response", "latency_ms": round((time.perf_counter() - started) * 1000, 3), "result": result, "confidence_boundary": "Tests only deterministic domain comparison. No registration date, registrar, or identity claim is made for synthetic domains.", "status": "PASS" if passed else "FAIL", "failure_reason": None if passed else "Comparison did not meet fixture expectation"})
    return outputs


def main():
    started = time.perf_counter()
    parser = Parser(description=__doc__ + " No arguments: 3 live RDAP cases plus 5 local comparison fixtures.")
    parser.add_argument("domain", nargs="?", help="Exact registered domain to query; no live lookalike defaults")
    parser.add_argument("--claimed-organization")
    parser.add_argument("--official-domain", help="Independently known official domain, used only for literal comparison")
    parser.add_argument("--require-registrant", action="store_true", help="Require independently proven registrant identity (this probe cannot provide it, so fails explicitly)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per socket operation timeout, seconds")
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    parser.add_argument("--self-test", action="store_true", help="Run only clearly synthetic local domain-comparison fixtures")
    try:
        args = parser.parse_args()
        if not math.isfinite(args.timeout) or args.timeout <= 0 or args.max_bytes < 1:
            raise ProbeError("--timeout must be positive and finite, --max-bytes must be positive")
        if not args.domain and (args.official_domain or args.claimed_organization or args.require_registrant):
            raise ProbeError("Custom organization/domain requirements need a positional domain")
        if args.self_test and args.domain:
            raise ProbeError("--self-test cannot be combined with a live domain")
        if args.self_test:
            results = fixture_cases()
        elif args.domain:
            results = [run_case(args.domain, args.claimed_organization, args.official_domain, args)]
        else:
            results = [run_case(domain, org, domain, args) for domain, org in DEFAULTS] + fixture_cases()
        passed = sum(r["status"] == "PASS" for r in results)
        out = {"capability": "RDAP domain provenance", "cases": results, "latency_ms": round((time.perf_counter() - started) * 1000, 3), "summary": {"passed": passed, "failed": len(results) - passed, "total": len(results)}, "status": "PASS" if passed == len(results) else "FAIL", "failure_reason": None if passed == len(results) else "One or more cases lacked required evidence; inspect each case failure_reason"}
    except Exception as exc:
        out = {"input": sys.argv[1:], "raw_evidence": [], "source": None, "latency_ms": round((time.perf_counter() - started) * 1000, 3), "result": {"evidence_state": NO_DATA}, "confidence_boundary": "No feasibility claim can be made", "status": "FAIL", "failure_reason": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out, ensure_ascii=True, indent=2))
    return 0 if out["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
