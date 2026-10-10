"""Extraction -> fixed routing -> deterministic evidence -> correlation -> result."""

from collections import Counter
from dataclasses import replace
import time

from .llm import AnnotationExtractor, LLMExtractor, LLMFailure
from .models import Evidence, EvidenceState as State, InvalidInput, sha256, critical_claims, grounding_issue, evidence_group
from .verifiers import DomainVerifier, PolicyVerifier, ReceiverHeaderVerifier, official_domain_comparison


GLOBAL_LIMITATIONS = [
    "This is a V1 evidence investigation, not a numerical scam probability or a binary identity verdict.",
    "LLM extraction can misinterpret language despite exact input spans; extracted claims remain untrusted assertions.",
    "Only NVIDIA recruitment is configured for official policy/domain rules. Unknown organizations and unsupported claims remain NO_AUTHORITATIVE_DATA.",
    "RDAP registration, an official-looking domain, and receiver-reported authentication cannot independently prove an individual's affiliation.",
    "Correlation uses explicit same-organization/same-domain links; missing evidence and source failures are never treated as contradictions.",
    "The relationship between supplied message text and any uploaded .eml is asserted by the submitter; V1 does not cryptographically bind them.",
]


class InvestigationEngine:
    def __init__(self, extractor=None, policy_verifier=None, domain_verifier=None, header_verifier=None, explainer=None):
        self.extractor = extractor or LLMExtractor()
        self.policy = policy_verifier or PolicyVerifier("live")
        self.domain = domain_verifier or DomainVerifier("live")
        self.headers = header_verifier or ReceiverHeaderVerifier()
        self.explainer = explainer

    def investigate(self, message, eml_bytes=None, original_receiver_export=False, input_origin="user_supplied"):
        started = time.perf_counter()
        if not isinstance(message, str) or not message.strip() or len(message) > 64000:
            raise InvalidInput("message must contain 1 to 64000 characters")
        if eml_bytes is not None and (not isinstance(eml_bytes, bytes) or len(eml_bytes) > 2_000_000 or not eml_bytes):
            raise InvalidInput("Original .eml must be nonempty bytes, at most 2000000 bytes")
        if type(original_receiver_export) is not bool:
            raise InvalidInput("original_receiver_export must be boolean")
        extraction = self.extractor.extract(message)
        from .clone_firm import CLONE_KINDS, CloneFirmInvestigation
        if any(c.kind in CLONE_KINDS for c in extraction.claims):
            result = CloneFirmInvestigation(domain=self.domain).investigate_extracted(message, extraction, input_origin)
            result["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
            if eml_bytes is not None:
                result["input"]["eml_supplied"] = True
                result["limitations"].append("Supplied email bytes are not analysed or counted by the clone-firm slice.")
            return result
        claims, omitted = critical_claims(extraction.claims)
        grounding = {c.id: grounding_issue(c, message) for c in claims}
        evidence, domains, comparisons = [], {}, {}

        def add(item):
            item = replace(item, evidence_group_id=evidence_group(item, evidence))
            evidence.append(item)
            return item

        def next_id():
            return f"e{len(evidence) + 1}"

        def attempt(method, verifier):
            attempt_started = time.perf_counter()
            evidence_id = next_id()
            try:
                item = verifier(evidence_id)
                if not isinstance(item, Evidence) or item.id != evidence_id or not isinstance(item.evidence_state, State):
                    raise ValueError("Verifier returned an invalid deterministic evidence contract")
            except Exception as exc:
                item = Evidence(evidence_id, method, State.NO_DATA, {"exception_type": type(exc).__name__, "exception_message": str(exc)},
                                {"origin": "verifier_failure"}, {}, ("Verifier failure is a data gap, not a contradiction.",), round((time.perf_counter() - attempt_started) * 1000, 3),
                                {"type": type(exc).__name__, "message": str(exc)})
            return add(item)

        known = any(claim.organization and claim.organization.casefold() == "nvidia" for claim in claims)
        policy = attempt("official_recruitment_policy", self.policy.verify) if known else None
        header = attempt("receiver_reported_spf_dkim_dmarc", lambda ident: self.headers.verify(eml_bytes, original_receiver_export, ident))
        for claim in claims:
            if grounding[claim.id] or claim.kind not in {"domain_association", "domain_registration"} or not claim.domain:
                continue
            if claim.domain not in domains:
                domains[claim.domain] = attempt("rdap_domain_provenance", lambda ident: self.domain.verify(claim.domain, ident))
            if claim.kind == "domain_association" and claim.organization and claim.organization.casefold() == "nvidia" and claim.domain not in comparisons:
                comparisons[claim.domain] = attempt("official_recruiting_domain_comparison", lambda ident: official_domain_comparison(claim.domain, policy, ident))

        results = []
        for claim in claims:
            state, method, used, limitations, finding = State.NO_DATA, "unsupported_claim", [], [], "No V1 verifier establishes this assertion."
            nvidia = bool(claim.organization and claim.organization.casefold() == "nvidia")
            if grounding[claim.id]:
                method, finding = "candidate_grounding_guard", grounding[claim.id]
                limitations = ["Rejected candidate predicate cannot be verified by unrelated authoritative facts."]
            elif claim.kind == "domain_association" and claim.domain in comparisons and nvidia:
                compare = comparisons[claim.domain]
                state, method, used = compare.evidence_state, compare.method, [compare.id, domains[claim.domain].id, policy.id]
                limitations = list(compare.limitations)
                finding = {
                    State.CONTRADICTED: "The contact domain does not match either official NVIDIA recruiting email domain in the captured policy.",
                    State.CONSISTENT: "The contact domain matches a published NVIDIA recruiting domain; sender identity remains unproven.",
                    State.NO_DATA: "The official recruiting-domain comparison could not be established because policy evidence is unavailable.",
                }[state]
            elif claim.kind == "domain_registration" and claim.domain in domains:
                item = domains[claim.domain]
                state, method, used, limitations = item.evidence_state, item.method, [item.id], list(item.limitations)
                finding = "RDAP provides current registration metadata for this domain." if state == State.VERIFIED else "No usable RDAP registration evidence is available for this domain."
            elif claim.kind == "email_authentication":
                state, method, used, limitations = header.evidence_state, header.method, [header.id], list(header.limitations)
                finding = "The receiver reports DMARC=" + header.observations.get("dmarc_outcome", "unresolved") + "; no independent authentication was performed."
            elif claim.kind in {"equipment_fee", "reimbursement"} and nvidia:
                method, used, limitations = "official_policy_fee_warning_scope_check", [policy.id], list(policy.limitations)
                finding = "NVIDIA's captured warning mentions upfront-fee requests, but does not explicitly establish the asserted equipment fee, vendor authorization or reimbursement. The fee claim remains unresolved."
                if policy.evidence_state == State.NO_DATA:
                    finding = "NVIDIA policy could not be obtained; the fee claim remains unresolved."
            elif claim.kind == "representation":
                method, used = "identity_evidence_boundary", [header.id]
                limitations = ["V1 has no authoritative employee or recruiter-affiliation verifier. Process contradictions do not directly prove who the sender is."]
                finding = "The sender's claimed affiliation is not independently established."
            elif claim.kind == "official_communication":
                method = "deterministic_official_process_correlation"
                relevant = [item for domain, item in comparisons.items() if nvidia and (claim.domain is None or claim.domain == domain) and any(c.organization and c.organization.casefold() == "nvidia" and c.domain == domain and c.kind == "domain_association" for c in claims)]
                ambiguous = claim.domain is None and len(relevant) > 1
                used = [item.id for item in relevant] + [header.id]
                if ambiguous:
                    finding = "Multiple contact domains are present; this unscoped communication claim cannot be correlated unambiguously."
                elif any(item.evidence_state == State.CONTRADICTED for item in relevant):
                    state = State.CONTRADICTED
                    finding = "The claimed official NVIDIA recruiting communication conflicts with its published recruiting-domain requirement."
                elif relevant and all(item.evidence_state == State.CONSISTENT for item in relevant):
                    state = State.CONSISTENT
                    finding = "The supplied recruiting domain is consistent with policy; this does not establish official message status."
                else:
                    finding = "No usable official-channel evidence establishes this communication as official."
                limitations = ["Correlation establishes compliance/conflict with a published channel requirement, not sender identity.", "A missing .eml is a data gap and is not a failed authentication result."]
            else:
                limitations = ["V1 does not verify job selection, personal deadlines, vendor authorization or reimbursement promises; these claims are preserved as unresolved."]
            scopes = {
                "representation": "Independent affiliation of the sender with the claimed organization",
                "domain_association": "Whether the contact domain meets the published official NVIDIA recruiting email-domain requirement; not arbitrary domain ownership or business association",
                "equipment_fee": "Whether an official NVIDIA policy establishes the requested candidate equipment-payment obligation",
                "official_communication": "Compliance with an established official recruiting-channel requirement; not proof of human identity",
                "domain_registration": "Availability of current authoritative RDAP registration metadata; not a verification of arbitrary asserted dates or ownership history",
                "email_authentication": "Availability and interpretation of receiver-reported SPF/DKIM/DMARC results; not independent cryptographic authentication",
            }
            results.append({**claim.to_dict(), "verification_scope": scopes.get(claim.kind, "No implemented V1 verification scope"), "verification_method": method, "evidence_ids": list(dict.fromkeys(used)),
                            "evidence_state": state.value, "finding": finding, "limitations": limitations})

        # Link identity assertions to related findings without upgrading their terminal state.
        for result in results:
            related = [item["id"] for item in results if item["id"] != result["id"] and item["organization"] == result["organization"] and item["kind"] == "domain_association"]
            result["correlated_claim_ids"] = related if result["kind"] in {"representation", "official_communication"} else []
        contradictions = [{"claim_id": item["id"], "finding": item["finding"], "evidence_ids": item["evidence_ids"]}
                          for item in results if item["evidence_state"] == State.CONTRADICTED.value]
        paragraphs = [f"{item['id']}: {item['finding']}" for item in results]
        explanation, explanation_provenance = "\n\n".join(paragraphs), {"mode": "deterministic_templates", "authoritative": False, "error": None}
        if self.explainer:
            # Only an immutable-by-value finding summary reaches the model. It cannot mutate verifications.
            established = [{"claim_id": item["id"], "evidence_state": item["evidence_state"], "finding": item["finding"], "limitations": item["limitations"]} for item in results]
            try:
                narration, provenance = self.explainer.explain(established)
                explanation_provenance = {"mode": "llm_supplement", "authoritative": False, "error": None, "provider": provenance,
                                          "paragraphs": narration, "boundary": "Supplementary model narration is not verification evidence; deterministic findings above remain canonical."}
            except Exception as exc:
                explanation_provenance["error"] = {"type": type(exc).__name__, "message": str(exc), "provider": getattr(exc, "evidence", {})}
        from .evaluation import summarize
        summary = summarize(results, evidence, extraction.provenance)
        all_limitations = list(dict.fromkeys(GLOBAL_LIMITATIONS + [limit for item in evidence for limit in item.limitations]))
        return {
            "schema_version": "1.0", "status": "completed_with_gaps" if any(item["evidence_state"] == State.NO_DATA.value for item in results) else "completed",
            "input": {"message": message, "message_sha256": sha256(message.encode()), "origin": input_origin, "eml_supplied": eml_bytes is not None},
            "extraction": {**extraction.provenance, "omitted_candidates": omitted},
            "summary": summary,
            "claims": results,
            "evidence": [item.to_dict() for item in evidence],
            "contradiction_summary": {"count": len(contradictions), "items": contradictions,
                                      "independent_evidence_group_ids": sorted({e.evidence_group_id for e in evidence if e.evidence_state == State.CONTRADICTED and e.evidence_group_id}),
                                      "independent_evidence_ids": sorted({e for item in contradictions for e in item["evidence_ids"] if e in {x.id for x in comparisons.values()}}),
                                      "boundary": "Multiple claims may share one underlying contradiction. Counts are not independent risk signals or a probability."},
            "evidence_state_counts": dict(Counter(item["evidence_state"] for item in results)),
            "limitations": all_limitations, "explanation": explanation, "explanation_provenance": explanation_provenance,
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }
