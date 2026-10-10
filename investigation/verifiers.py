"""V1 deterministic adapters. No LLM imports or user-selected policy sources."""

import argparse
import base64
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import time

import email_header_analysis as headers
import rdap_domain_provenance as rdap
import scam_process_contradictions as policy

from .models import Evidence, EvidenceState as State, sha256, strict_json


ROOT = Path(__file__).resolve().parent.parent
POLICY_URL = "https://www.nvidia.com/en-us/about-nvidia/careers/recruitment-scams/"
DOMAIN_QUOTE = "NVIDIA conducts its own recruitment and hiring, and all communications will come from an @nvidia.com or @career.nvidia.com email."
FEE_WARNING_QUOTE = "These individuals may offer fake job opportunities, request up-front fees, or claim that they're a third-party hiring supplier for NVIDIA."
SNAPSHOT_SHA256 = "f9db7320a0d134c47efd16ab83b2cb0c57919592594dc7681a1b80de96b57fe0"
ALLOWED_RECRUITING_DOMAINS = ("nvidia.com", "career.nvidia.com")
POLICY_BOUNDARIES = (
    "Authority is the curated NVIDIA recruiting page; V1 does not independently verify legal-entity identity.",
    "The recruiting-domain rule is organization/process specific and accepts only the two domains explicitly listed, not arbitrary subdomains.",
    "The upfront-fee passage describes a scam warning pattern; it is not an explicit universal prohibition, reimbursement decision or vendor-authorization record.",
    "Exact quotes are checked after whitespace normalization. Policy scope is reviewed configuration, not LLM inference.",
    "Snapshots establish what the source published at recorded retrieval time; they are not a fresh availability or historical-applicability check.",
)


def visible_text(raw):
    parser = policy.VisibleText()
    parser.feed(raw)
    parser.close()
    return policy.norm(" ".join(parser.parts))


class PolicyVerifier:
    def __init__(self, mode="snapshot", snapshot_path=None, timeout=15):
        if mode not in {"snapshot", "live"}:
            raise ValueError("Policy mode must be snapshot or live")
        self.mode, self.timeout = mode, timeout
        self.snapshot_path = Path(snapshot_path or ROOT / "fixtures/nvidia_recruiter/policy_capture.json")

    def verify(self, evidence_id):
        started = time.perf_counter()
        raw, observations, error = {}, {}, None
        source = {"url": POLICY_URL, "organization": "NVIDIA", "process": "recruitment", "mode": self.mode, "authority_basis": "Curated NVIDIA official recruiting policy host; independent legal-entity verification is out of V1 scope."}
        state = State.NO_DATA
        try:
            if self.mode == "live":
                raw, visible = policy.fetch_policy(POLICY_URL, {"www.nvidia.com", "nvidia.com"}, self.timeout)
                source["retrieved_at_utc"] = datetime.now(timezone.utc).isoformat()
                source["origin"] = "live_https"
                if raw["error"]:
                    raise ValueError(f"Policy fetch failed: {raw['error']}")
            else:
                raw = strict_json(self.snapshot_path.read_text(encoding="utf-8"))
                source.update({"origin": "real_http_capture", "snapshot_path": str(self.snapshot_path), "retrieved_at_utc": raw.get("retrieved_at_utc"), "original_http_latency_ms": raw.get("latency_ms")})
                if raw.get("origin") != "real_http_capture" or raw.get("url") != POLICY_URL or raw.get("http_status") != 200 or raw.get("error") or raw.get("response_truncated"):
                    raise ValueError("Snapshot is not a successful genuine capture of the configured source")
                body_bytes = base64.b64decode(raw["raw_body_base64"], validate=True)
                if sha256(body_bytes) != SNAPSHOT_SHA256 or raw.get("captured_sha256") != SNAPSHOT_SHA256:
                    raise ValueError("Policy snapshot hash differs from the pinned genuine capture")
                if body_bytes.decode("utf-8", errors="strict") != raw.get("raw_body"):
                    raise ValueError("Policy snapshot text differs from its captured bytes")
                visible = visible_text(raw["raw_body"])
            source["body_sha256"] = raw.get("captured_sha256")
            observations = {
                "recruiting_domain_quote": DOMAIN_QUOTE,
                "domain_rule_supported": policy.norm(DOMAIN_QUOTE) in visible,
                "allowed_recruiting_domains": list(ALLOWED_RECRUITING_DOMAINS),
                "fee_warning_quote": FEE_WARNING_QUOTE,
                "fee_warning_supported": policy.norm(FEE_WARNING_QUOTE) in visible,
                "explicit_no_fee_rule_supported": False,
            }
            if not observations["domain_rule_supported"]:
                raise ValueError("Configured recruiting-domain quote is absent; domain rule unavailable")
            state = State.VERIFIED
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
        return Evidence(evidence_id, "official_recruitment_policy", state, raw, source, observations, POLICY_BOUNDARIES, round((time.perf_counter() - started) * 1000, 3), error)


class DomainVerifier:
    def __init__(self, mode="unavailable", timeout=15):
        if mode not in {"unavailable", "live"}:
            raise ValueError("RDAP mode must be unavailable or live")
        self.mode, self.timeout = mode, timeout

    def verify(self, domain, evidence_id):
        if self.mode == "unavailable":
            return Evidence(evidence_id, "rdap_domain_provenance", State.NO_DATA, {"queried_domain": domain, "network_request_made": False},
                            {"origin": "not_queried", "bootstrap_url": rdap.BOOTSTRAP}, {},
                            ("Offline demo has no captured RDAP response for this synthetic-message contact domain. No registration date or registrar is invented.",), 0,
                            {"type": "EvidenceUnavailable", "message": "No domain-specific RDAP capture; use live RDAP explicitly if required"})
        args = argparse.Namespace(timeout=self.timeout, max_bytes=2_000_000, require_registrant=False)
        result = rdap.run_case(domain, None, None, args)
        return Evidence(evidence_id, "rdap_domain_provenance", State(result["result"]["evidence_state"]), result["raw_evidence"],
                        {**result["source"], "origin": "live_https"}, result["result"], tuple(result["confidence_boundary"]), result["latency_ms"],
                        None if result["status"] == "PASS" else {"type": "RDAPFailure", "message": result["failure_reason"]})


class ReceiverHeaderVerifier:
    def __init__(self, trusted_authserv_id=None):
        self.trusted_authserv_id = trusted_authserv_id

    def verify(self, eml_bytes, original_receiver_export, evidence_id):
        if eml_bytes is None:
            return Evidence(evidence_id, "receiver_reported_spf_dkim_dmarc", State.NO_DATA,
                            {"eml_supplied": False}, {"origin": "missing_original_eml"}, {},
                            ("No original .eml supplied. Text, an email address or a display name cannot establish SPF/DKIM/DMARC results.",), 0,
                            {"type": "EvidenceUnavailable", "message": "Original .eml required"})
        started = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="investigation-eml-") as directory:
            path = Path(directory) / "original.eml"
            path.write_bytes(eml_bytes)
            args = argparse.Namespace(eml=str(path), trusted_authserv_id=self.trusted_authserv_id,
                assert_trusted_receiver_export=original_receiver_export, claimed_organization=None, official_domain=None)
            result = headers.run_probe(args)
        raw = result["raw_evidence"]
        raw.pop("input_path", None)
        source = {"origin": result["source"]["kind"], "format": "original_eml", "file_sha256": sha256(eml_bytes),
                  "trusted_authserv_id": self.trusted_authserv_id, "original_receiver_export_asserted": original_receiver_export,
                  "export_provenance_independently_verified": False, "independent_crypto_or_dns_verification": False}
        return Evidence(evidence_id, "receiver_reported_spf_dkim_dmarc", State(result["result"]["evidence_state"]), raw, source,
                        result["result"], tuple(headers.LIMITATIONS), round((time.perf_counter() - started) * 1000, 3),
                        None if result["status"] == "PASS" else {"type": "HeaderAnalysisFailure", "message": result["failure_reason"]})


def official_domain_comparison(domain, policy_evidence, evidence_id):
    started = time.perf_counter()
    # Reuse exact boundary-aware matching; a brand substring is never association evidence.
    matches = [rdap.compare_domain(rdap.domain_name(domain), official) for official in ALLOWED_RECRUITING_DOMAINS]
    available = policy_evidence.evidence_state == State.VERIFIED and policy_evidence.observations.get("domain_rule_supported")
    exact = any(item["exact_match"] for item in matches)
    state = (State.CONSISTENT if exact else State.CONTRADICTED) if available else State.NO_DATA
    return Evidence(evidence_id, "official_recruiting_domain_comparison", state,
                    {"contact_domain": domain, "literal_comparisons": matches, "exact_policy_quote": DOMAIN_QUOTE},
                    {"policy_evidence_id": policy_evidence.id, "url": POLICY_URL, "scope": "NVIDIA official recruiting communication email domain"},
                    {"domain_matches_published_recruiting_domains": exact if available else None},
                    ("A match only establishes consistency with NVIDIA's published recruiting domains; it does not prove this sender's identity or message authenticity.",
                     "A mismatch contradicts the official recruiting-domain claim only; it does not establish every possible relationship or domain ownership."),
                    round((time.perf_counter() - started) * 1000, 3),
                    None if available else {"type": "PolicyUnavailable", "message": "No usable authoritative recruiting-domain rule"})
