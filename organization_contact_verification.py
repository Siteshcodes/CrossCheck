#!/usr/bin/env python3
"""Isolated SEC EDGAR organization/contact feasibility probe (stdlib only).

No arguments tests Microsoft and NVIDIA using real SEC submissions responses.
Custom example:
  python organization_contact_verification.py --cik 789019 \
    --organization "MICROSOFT CORP" --domain microsoft.com --phone 425-882-8080 \
    --contact-url https://www.microsoft.com/en-us/worldwide \
    --authority-basis "Independently operator-designated official Microsoft site"

An EDGAR record corroborates a named filer and its listed contact. Missing
website fields leave domain ownership UNRESOLVED. There is no inferred trust
from a matching name, a reachable homepage, or an email-domain suffix.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from html.parser import HTMLParser
import json
import math
import os
import re
import sys
import time
import unicodedata
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


VERIFIED = "VERIFIED_BY_AUTHORITATIVE_SOURCE"
CONTRADICTED = "CONTRADICTED_BY_AUTHORITATIVE_SOURCE"
CONSISTENT = "CONSISTENT_BUT_NOT_IDENTITY_PROVING"
NO_DATA = "NO_AUTHORITATIVE_DATA"
DEFAULTS = (
    {"organization": "MICROSOFT CORP", "cik": "0000789019", "domain": "microsoft.com", "phone": "425-882-8080", "contact_url": "https://www.microsoft.com/en-us/worldwide", "authority_basis": "Default operator-designated Microsoft official office directory on www.microsoft.com; linkage to SEC filer is not independently established"},
    {"organization": "NVIDIA CORP", "cik": "0001045810", "domain": "nvidia.com", "phone": "408-486-2000", "contact_url": "https://www.nvidia.com/en-us/contact/", "authority_basis": "Default operator-designated NVIDIA official contact page on www.nvidia.com; linkage to SEC filer is not independently established"},
)
BOUNDARIES = [
    "Authority is scoped to the US SEC EDGAR submissions record obtained over certificate-validated HTTPS from data.sec.gov.",
    "An exact current filer name and CIK corroborate registry presence; this is not a certificate of incorporation or current legal good standing.",
    "A phone match verifies a contact listed in the same filer record, not present control, reachability, or a sender's identity.",
    "Official domain is verified only by an explicit website or investorWebsite field in that same identified SEC record; empty fields remain UNRESOLVED.",
    "A separate operator-designated official contact page is fetched and its visible contacts and matching domain links are reported. This is conditional on the explicit trust basis and cannot independently prove its relationship to the SEC filer.",
    "HTML extraction is static, excludes scripts/styles/templates/head and hidden attributes, and does not run JavaScript or evaluate CSS. Extracted contacts may serve different departments; context is preserved.",
    "A different phone/domain listing does not prove a claimed alternative is false: lists can be incomplete, so absence or mismatch remains UNRESOLVED.",
    "The requested organization name must match the current filer name after case and whitespace normalization; aliases are not guessed.",
    "Phone matching removes presentation separators only and requires equal digits. Country codes are not guessed.",
    "US SEC filer coverage is narrow; arbitrary organizations and unlisted entities need other authoritative registries.",
    "PASS requires registry identity, official domain, and requested phone all verified. FAIL/UNRESOLVED never means scam.",
    "There are no retries, redirects, cached answers, invented responses, alternate sources, or outbound contact attempts.",
]


class ProbeFailure(Exception):
    pass


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ProbeFailure("Invalid arguments: " + message)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def name_key(value):
    return " ".join(unicodedata.normalize("NFC", value).split()).casefold()


def domain_key(value):
    if not isinstance(value, str) or not value or any(c in value for c in "/:@?#\\"):
        raise ProbeFailure("Domain must be a bare DNS hostname without URL components")
    if not value.isascii():
        raise ProbeFailure("Use an ASCII domain or an explicitly supplied IDNA A-label; Unicode hostnames are not silently mapped")
    domain = value.removesuffix(".").lower()
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain):
        raise ProbeFailure("Domain must be a valid fully qualified DNS hostname")
    return domain


def phone_key(value):
    if not isinstance(value, str) or not re.fullmatch(r"\+?[0-9][0-9 .()\-]*[0-9]", value):
        raise ProbeFailure("Phone must contain digits with optional leading + and presentation separators only")
    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15:
        raise ProbeFailure("Phone must contain 7 to 15 digits")
    return digits


def field_host(value):
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    parts = urlsplit(candidate if "://" in candidate else "https://" + candidate)
    if parts.scheme.lower() not in ("http", "https") or parts.username is not None or parts.password is not None:
        raise ProbeFailure("Registry website field is not a supported HTTP(S) URL")
    return domain_key(parts.hostname or "")


def fetch_source(url, args, raw, kind="json"):
    started = time.perf_counter()
    raw.update({"request_url": url, "request_headers": {"User-Agent": args.user_agent, "Accept": "application/json" if kind == "json" else "text/html, application/xhtml+xml", "Accept-Encoding": "identity"}})
    try:
        opener = build_opener(NoRedirect())
        try:
            response = opener.open(Request(url, headers=raw["request_headers"]), timeout=args.timeout)
        except HTTPError as exc:
            response = exc
            raw["http_exception"] = {"type": type(exc).__name__, "message": str(exc)}
        with response:
            raw["http_status"] = response.status
            raw["http_reason"] = str(response.reason)
            raw["response_url"] = response.geturl()
            raw["response_headers"] = list(response.headers.items())
            # Read only a bounded body, and never interpret incomplete evidence.
            body = response.read(args.max_bytes + 1)
            raw["bytes_read"] = len(body)
            raw["body_truncated"] = len(body) > args.max_bytes
            raw["body_sha256"] = hashlib.sha256(body).hexdigest()
            raw["raw_body_base64"] = base64.b64encode(body).decode("ascii")
            encoding = response.headers.get_content_charset() or "utf-8"
            raw["body_encoding"] = encoding
            try:
                body_text = body.decode(encoding, errors="strict")
                raw["raw_body_text"] = body_text
            except (UnicodeError, LookupError) as exc:
                raise ProbeFailure(f"Body decode failed ({type(exc).__name__}: {exc}); exact bytes retained as base64") from exc
            if raw["body_truncated"]:
                raise ProbeFailure(f"HTTP body exceeded --max-bytes={args.max_bytes}; truncated evidence cannot pass")
            if response.status != 200:
                raise ProbeFailure(f"Source request returned HTTP {response.status} {response.reason}; no fallback or retry")
            if response.geturl() != url:
                raise ProbeFailure("Unexpected response URL; authoritative source changed")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ProbeFailure("Source ignored Accept-Encoding: identity; compressed data is unsupported")
            if kind == "html":
                if response.headers.get_content_type() not in ("text/html", "application/xhtml+xml"):
                    raise ProbeFailure(f"Expected HTML, got Content-Type {response.headers.get('Content-Type')!r}")
                return body_text
            if response.headers.get_content_type() not in ("application/json", "text/json"):
                raise ProbeFailure(f"Expected JSON, got Content-Type {response.headers.get('Content-Type')!r}")
            try:
                document = json.loads(body_text)
            except json.JSONDecodeError as exc:
                raise ProbeFailure(f"SEC response was not valid JSON: {exc}") from exc
            if not isinstance(document, dict):
                raise ProbeFailure("SEC JSON must be an object")
            return document
    except Exception as exc:
        raw["exception"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        raw["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)


def finding(outcome, state, reason, **evidence):
    return {"outcome": outcome, "evidence_state": state, "reason": reason, **evidence}


class ContactText(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
    BLOCK = {"address", "article", "br", "div", "h1", "h2", "h3", "h4", "li", "p", "section", "td", "tr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.text = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        hidden = bool(self.stack and self.stack[-1][1]) or tag in {"head", "script", "style", "template", "noscript"} or "hidden" in attrs or attrs.get("aria-hidden", "").lower() == "true"
        if not hidden:
            if tag in self.BLOCK:
                self.text.append("\n")
            if tag == "a" and attrs.get("href"):
                self.links.append(attrs["href"])
        if tag not in self.VOID:
            self.stack.append((tag, hidden))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break
        if tag in self.BLOCK and not (self.stack and self.stack[-1][1]):
            self.text.append("\n")

    def handle_data(self, data):
        if not self.stack or not self.stack[-1][1]:
            self.text.append(data)


def inspect_contact_page(case, args, report):
    url = case["contact_url"]
    record = report["raw_evidence"]["official_contact_page"] = {}
    report["source"]["official_contact_page"] = {"url": url, "authority_basis": case["authority_basis"], "trust_status": "OPERATOR_DESIGNATED_NOT_INDEPENDENTLY_ESTABLISHED"}
    try:
        page = fetch_source(url, args, record, "html")
        parser = ContactText()
        parser.feed(page)
        parser.close()
        lines = [" ".join(line.split()) for line in "".join(parser.text).splitlines() if line.strip()]
        emails, phones = [], []
        for line_number, line in enumerate(lines, 1):
            for match in re.finditer(r"(?<![\w@.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?![\w@.-])", line):
                emails.append({"raw_value": match.group(0), "line": line_number, "context": line})
            for match in re.finditer(r"(?<![\w+])\+?\(?[0-9][0-9 ()\-.]{5,35}[0-9](?![\w])", line):
                token = match.group(0)
                if 7 <= len(re.sub(r"\D", "", token)) <= 15:
                    phones.append({"raw_value": token, "line": line_number, "context": line, "classification": "PHONE_SHAPED_TOKEN_REQUIRES_CONTEXT_REVIEW"})
        domain_links = []
        for link in parser.links:
            if not link.startswith(("https://", "http://")):
                continue
            try:
                host = field_host(link)
            except (ProbeFailure, ValueError):
                continue
            if host in (case["domain"], "www." + case["domain"]):
                domain_links.append(link)
        record["extracted_visible_lines"] = lines
        record["published_email_tokens"] = emails
        record["published_phone_shaped_tokens"] = phones
        record["matching_domain_links"] = list(dict.fromkeys(domain_links))
        return finding("UNRESOLVED", CONSISTENT, "Fetched the operator-designated contact page and extracted published evidence; page authority and the SEC-to-domain identity link remain assumptions", published_email_count=len(emails), phone_shaped_token_count=len(phones), claimed_domain_link_count=len(domain_links), raw_evidence_path="official_contact_page")
    except Exception as exc:
        record.setdefault("exception", {"type": type(exc).__name__, "message": str(exc)})
        return finding("UNRESOLVED", NO_DATA, "Official contact-page fetch or extraction failed: " + str(exc), raw_evidence_path="official_contact_page")


def run_case(case, args):
    started = time.perf_counter()
    url = "https://data.sec.gov/submissions/CIK" + case["cik"] + ".json"
    report = {
        "input": case,
        "raw_evidence": {},
        "source": {"url": url, "authority": "US Securities and Exchange Commission EDGAR", "api_documentation": "https://www.sec.gov/search-filings/edgar-application-programming-interfaces", "scope": "The current filer identity and metadata listed in this CIK record"},
        "latency_ms": None,
        "result": {"outcome": "UNRESOLVED", "evidence_state": NO_DATA, "findings": {name: finding("UNRESOLVED", NO_DATA, "Authoritative evidence has not been obtained") for name in ("organization_existence", "official_domain", "listed_phone")}},
        "confidence_boundary": BOUNDARIES,
        "status": "FAIL",
        "failure_reason": None,
    }
    try:
        report["raw_evidence"]["sec_submissions"] = {}
        data = fetch_source(url, args, report["raw_evidence"]["sec_submissions"])
        facts = report["result"]["findings"]
        observed_cik = str(data.get("cik", ""))
        observed_name = data.get("name")
        if not observed_cik.isdigit() or not isinstance(observed_name, str) or not observed_name.strip():
            raise ProbeFailure("SEC record lacks a valid CIK or current name")
        if observed_cik.zfill(10) != case["cik"] or name_key(observed_name) != name_key(case["organization"]):
            facts["organization_existence"] = finding("CONTRADICTED", CONTRADICTED, "The requested exact current filer name/CIK pair differs from the authoritative record; this does not establish non-existence", field="name/cik", observed_name=observed_name, observed_cik=observed_cik)
            raise ProbeFailure("Authoritative record contradicts the requested exact current filer name/CIK pair; domain and contact are not attributed")
        facts["organization_existence"] = finding("VERIFIED", VERIFIED, "The requested name and CIK match an existing SEC filer record; legal good standing is outside this evidence", field="name/cik", observed_name=observed_name, observed_cik=observed_cik, tickers=data.get("tickers"))
        websites = {key: data.get(key) for key in ("website", "investorWebsite")}
        hosts = []
        field_errors = []
        for key, value in websites.items():
            try:
                host = field_host(value)
                if host:
                    hosts.append({"field": key, "raw_value": value, "hostname": host})
            except (ProbeFailure, ValueError) as exc:
                field_errors.append({"field": key, "raw_value": value, "error": str(exc)})
        expected = case["domain"]
        domain_matches = [item for item in hosts if item["hostname"] in (expected, "www." + expected)]
        if domain_matches:
            facts["official_domain"] = finding("VERIFIED", VERIFIED, "An explicit website field in the identified SEC record names the claimed hostname or its www host", matches=domain_matches, fields=websites, field_errors=field_errors)
        else:
            facts["official_domain"] = finding("UNRESOLVED", NO_DATA, "No explicit matching website field in this record; domain ownership is not inferred from the organization name", fields=websites, parsed_hosts=hosts, field_errors=field_errors)
        raw_phone = data.get("phone")
        try:
            observed_phone = phone_key(raw_phone)
        except ProbeFailure as exc:
            observed_phone = None
            phone_error = str(exc)
        else:
            phone_error = None
        if observed_phone == phone_key(case["phone"]):
            facts["listed_phone"] = finding("VERIFIED", VERIFIED, "Claimed phone digits exactly match the contact field in the same identified SEC filer record", field="phone", raw_value=raw_phone, normalized_digits=observed_phone)
        else:
            facts["listed_phone"] = finding("UNRESOLVED", NO_DATA, "This SEC record does not corroborate the claimed phone; it may not list every valid contact", field="phone", raw_value=raw_phone, normalized_digits=observed_phone, parse_error=phone_error)
        unresolved = [key for key, value in facts.items() if value["outcome"] != "VERIFIED"]
        if unresolved:
            raise ProbeFailure("Unresolved required dimension(s): " + ", ".join(unresolved))
        report["result"]["outcome"] = "VERIFIED"
        report["result"]["evidence_state"] = VERIFIED
        report["status"] = "PASS"
    except Exception as exc:
        report["failure_reason"] = str(exc) or type(exc).__name__
        report["result"]["exception"] = {"type": type(exc).__name__, "message": str(exc)}
        states = [item["evidence_state"] for item in report["result"]["findings"].values()]
        if CONTRADICTED in states:
            report["result"]["outcome"] = "CONTRADICTED"
            report["result"]["evidence_state"] = CONTRADICTED
        elif VERIFIED in states:
            report["result"]["evidence_state"] = CONSISTENT
    page_finding = inspect_contact_page(case, args, report)
    report["result"]["findings"]["official_contact_page"] = page_finding
    if page_finding["evidence_state"] == NO_DATA:
        report["status"] = "FAIL"
        report["failure_reason"] = "; ".join(filter(None, [report["failure_reason"], page_finding["reason"]]))
        if report["result"]["outcome"] == "VERIFIED":
            report["result"]["outcome"] = "UNRESOLVED"
            report["result"]["evidence_state"] = CONSISTENT
    report["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return report


def parse_args():
    parser = JsonArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cik", help="SEC Central Index Key, 1-10 digits; all six custom case options must be supplied together")
    parser.add_argument("--organization", help="Exact current SEC filer name")
    parser.add_argument("--domain", help="Claimed official bare domain")
    parser.add_argument("--phone", help="Claimed phone; include the same country-code convention as the source")
    parser.add_argument("--contact-url", help="HTTPS official contact-page URL for custom input (no credentials, fragments, nonstandard port, or redirects)")
    parser.add_argument("--authority-basis", help="Independent basis for designating that contact-page host as official; recorded as an assumption")
    parser.add_argument("--user-agent", default=os.environ.get("SEC_USER_AGENT", "ForgeFeasibilityProbe/1.0 organization capability evaluation"), help="HTTP User-Agent; optionally use SEC_USER_AGENT to provide your real application/contact information")
    parser.add_argument("--timeout", type=float, default=15, help="Socket timeout in seconds (default: 15); not a total wall-clock deadline")
    parser.add_argument("--max-bytes", type=int, default=2_097_152, help="Maximum complete response bytes (default: 2097152); truncation fails")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 120 or not 1 <= args.max_bytes <= 10_485_760:
        raise ProbeFailure("Require finite 0 < timeout <= 120 and 1 <= max-bytes <= 10485760")
    if not args.user_agent.strip() or any(ord(c) < 32 or ord(c) > 126 for c in args.user_agent):
        raise ProbeFailure("User-Agent must be nonempty printable ASCII")
    custom = (args.cik, args.organization, args.domain, args.phone, args.contact_url, args.authority_basis)
    if any(value is not None for value in custom):
        if not all(value is not None and value.strip() for value in custom):
            raise ProbeFailure("Custom input requires --cik, --organization, --domain, --phone, --contact-url, and --authority-basis together")
        if not re.fullmatch(r"[0-9]{1,10}", args.cik):
            raise ProbeFailure("CIK must contain 1 to 10 ASCII digits")
        phone_key(args.phone)
        parts = urlsplit(args.contact_url)
        if parts.scheme != "https" or parts.username is not None or parts.password is not None or parts.port not in (None, 443) or parts.fragment or "\\" in args.contact_url or any(ord(char) < 33 for char in args.contact_url):
            raise ProbeFailure("Contact URL must use credential-free HTTPS on port 443 without fragments, backslashes, spaces, or controls")
        domain_key(parts.hostname or "")
        cases = [{"organization": args.organization, "cik": args.cik.zfill(10), "domain": domain_key(args.domain), "phone": args.phone, "contact_url": args.contact_url, "authority_basis": args.authority_basis}]
    else:
        cases = [dict(case) for case in DEFAULTS]
    return args, cases


def main():
    started = time.perf_counter()
    try:
        args, cases = parse_args()
        reports = [run_case(case, args) for case in cases]
        passed = sum(case["status"] == "PASS" for case in reports)
        unresolved = sum(case["result"]["outcome"] == "UNRESOLVED" for case in reports)
        output = {"capability": "authoritative_organization_contact_verification", "cases": reports, "latency_ms": round((time.perf_counter() - started) * 1000, 3), "summary": {"cases": len(reports), "passed": passed, "failed": len(reports) - passed, "unresolved": unresolved}, "status": "PASS" if passed == len(reports) else "FAIL", "failure_reason": None if passed == len(reports) else "One or more required authoritative facts could not be verified; inspect per-case evidence and failures"}
    except Exception as exc:
        output = {"capability": "authoritative_organization_contact_verification", "input": sys.argv[1:], "raw_evidence": {"exception": {"type": type(exc).__name__, "message": str(exc)}}, "source": None, "latency_ms": round((time.perf_counter() - started) * 1000, 3), "result": {"outcome": "UNRESOLVED", "evidence_state": NO_DATA}, "confidence_boundary": BOUNDARIES, "status": "FAIL", "failure_reason": str(exc) or type(exc).__name__}
    print(json.dumps(output, indent=2, ensure_ascii=True, allow_nan=False))
    return 0 if output["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
