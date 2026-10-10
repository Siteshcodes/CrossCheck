"""Validated extraction contracts. Evidence states belong to deterministic code."""

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json


class EvidenceState(str, Enum):
    VERIFIED = "VERIFIED_BY_AUTHORITATIVE_SOURCE"
    CONTRADICTED = "CONTRADICTED_BY_AUTHORITATIVE_SOURCE"
    CONSISTENT = "CONSISTENT_BUT_NOT_IDENTITY_PROVING"
    NO_DATA = "NO_AUTHORITATIVE_DATA"


CLAIM_KINDS = (
    "representation", "domain_association", "equipment_fee", "official_communication",
    "selection", "onboarding_deadline", "vendor_authorization", "reimbursement",
    "email_authentication", "domain_registration", "unsupported",
    "regulated_firm", "regulated_contact", "legal_entity", "clone_affiliation",
)
ROUTES = {
    "regulated_firm": "regulator_record_lookup", "regulated_contact": "regulator_contact_comparison",
    "legal_entity": "legal_entity_registry", "clone_affiliation": "regulator_clone_warning",
    "representation": "identity_boundary", "domain_association": "official_domain_comparison",
    "equipment_fee": "official_policy_process", "reimbursement": "official_policy_process",
    "email_authentication": "receiver_reported_email_authentication", "domain_registration": "rdap_domain_provenance",
    "official_communication": "official_policy_process", "vendor_authorization": "official_policy_process",
    "selection": "unsupported", "onboarding_deadline": "unsupported", "unsupported": "unsupported",
}
CRITICAL_KINDS = {"regulated_firm", "regulated_contact", "legal_entity", "clone_affiliation", "representation", "domain_association", "equipment_fee", "reimbursement", "email_authentication", "domain_registration", "unsupported"}
CLAIM_KEYS = {"id", "kind", "statement", "organization", "source_quote", "start", "end", "domain", "basis", "verification_route", "polarity"}


class InvalidInput(ValueError):
    pass


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidInput(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(InvalidInput(f"Invalid JSON constant: {value}")))


@dataclass(frozen=True)
class Claim:
    id: str
    kind: str
    statement: str
    organization: str | None
    source_quote: str
    start: int
    end: int
    domain: str | None
    basis: str
    verification_route: str
    polarity: str

    def to_dict(self):
        return asdict(self)


def validate_claims(data, message: str) -> list[Claim]:
    if not isinstance(message, str) or not message.strip() or len(message) > 64000:
        raise InvalidInput("message must contain 1 to 64000 characters")
    if not isinstance(data, dict) or set(data) != {"claims"}:
        raise InvalidInput("Extraction must contain only claims; evidence states and verdicts are forbidden")
    values = data["claims"]
    if not isinstance(values, list) or not 0 <= len(values) <= 32:
        raise InvalidInput("Extraction requires 0 to 32 candidate claims")
    claims, seen = [], set()
    for value in values:
        if not isinstance(value, dict) or set(value) != CLAIM_KEYS:
            raise InvalidInput("Each extracted claim must match the claim schema exactly; verdict fields are forbidden")
        for name in ("id", "kind", "statement", "source_quote", "basis"):
            if not isinstance(value[name], str) or not value[name].strip() or len(value[name]) > 2000:
                raise InvalidInput(f"Invalid claim {name}")
        if value["id"] in seen:
            raise InvalidInput("Duplicate claim id")
        seen.add(value["id"])
        if value["kind"] not in CLAIM_KINDS or value["basis"] not in {"explicit", "implied"}:
            raise InvalidInput("Unsupported claim kind or extraction basis")
        if value["verification_route"] != ROUTES[value["kind"]]:
            raise InvalidInput("Invalid routing: candidate kind and verification_route do not match the backend allowlist")
        if value["polarity"] not in {"positive", "negative"}:
            raise InvalidInput("Candidate polarity must be positive or negative")
        start, end = value["start"], value["end"]
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(message):
            raise InvalidInput("Claim offsets must reference the original input")
        if message[start:end] != value["source_quote"]:
            raise InvalidInput("Claim source_quote does not exactly match its original-input span")
        for name in ("organization", "domain"):
            if value[name] is not None and (not isinstance(value[name], str) or not value[name].strip() or len(value[name]) > 253):
                raise InvalidInput(f"Invalid claim {name}")
        if value["domain"] is not None:
            from rdap_domain_provenance import domain_name
            try:
                normalized = domain_name(value["domain"])
            except ValueError as exc:
                raise InvalidInput(str(exc)) from exc
            if normalized not in value["source_quote"].lower():
                raise InvalidInput("Claim domain must occur literally in its source excerpt")
            value = dict(value, domain=normalized)
        claims.append(Claim(**value))
    return claims


def critical_claims(claims):
    """Decision-relevant projection. Report removals; never truncate to manufacture a gate pass."""
    selected, omitted, signatures = [], [], set()
    for claim in claims:
        signature = (claim.kind, (claim.organization or "").casefold(), claim.domain, claim.polarity)
        if claim.kind not in CRITICAL_KINDS:
            omitted.append({"claim_id": claim.id, "reason": "Incidental, unimplemented or duplicate official-status assertion; retained in candidate provenance"})
        elif signature in signatures:
            omitted.append({"claim_id": claim.id, "reason": "Duplicate critical predicate for the same organization/domain/polarity"})
        else:
            signatures.add(signature)
            selected.append(claim)
    return selected, omitted


def grounding_issue(claim, message):
    """Conservative predicate checks before verification; a literal domain alone is not a registration assertion."""
    import re
    quote = claim.source_quote.casefold()
    if claim.organization and not re.search(r"(?<!\w)" + re.escape(claim.organization.casefold()) + r"(?!\w)", message.casefold()):
        return "Candidate organization is not present in the input"
    if claim.kind == "domain_registration":
        if claim.polarity != "positive" or re.search(r"\b(?:19|20)\d{2}\b|\b(not|never|unregistered)\b", quote) or not re.search(r"\b(?:is|was|has been)\s+registered\b", quote):
            return "Unsupported registration predicate: require an explicit positive registration assertion without claimed historical dates"
    if claim.kind == "email_authentication" and not re.search(r"\b(spf|dkim|dmarc|authentication-results)\b", quote):
        return "Authentication candidate is not supported by any literal authentication assertion"
    if claim.kind == "equipment_fee" and not re.search(r"\b(pay|payment|fee|deposit|charge|charged)\b", quote):
        return "Equipment-payment candidate is not grounded in a literal payment assertion"
    if claim.kind == "reimbursement" and not re.search(r"\b(reimburse\w*|refund\w*|pay back)\b", quote):
        return "Reimbursement candidate is not grounded in a reimbursement assertion"
    if claim.kind == "domain_association" and claim.polarity != "positive":
        return "Negative broad association predicates cannot be established by an official-domain list alone"
    return None


def claim_schema():
    properties = {name: {"type": "string"} for name in ("id", "statement", "source_quote")}
    properties.update({
        "kind": {"type": "string", "enum": list(CLAIM_KINDS)},
        "organization": {"type": ["string", "null"]},
        "domain": {"type": ["string", "null"]},
        "start": {"type": "integer"}, "end": {"type": "integer"},
        "basis": {"type": "string", "enum": ["explicit", "implied"]},
        "verification_route": {"type": "string", "enum": sorted(set(ROUTES.values()))},
        "polarity": {"type": "string", "enum": ["positive", "negative"]},
    })
    return {"type": "object", "properties": {"claims": {"type": "array", "items": {
        "type": "object", "properties": properties, "required": list(properties), "additionalProperties": False,
    }}}, "required": ["claims"], "additionalProperties": False}


@dataclass(frozen=True)
class Evidence:
    id: str
    method: str
    evidence_state: EvidenceState
    raw_evidence: object
    source_provenance: dict
    observations: dict
    limitations: tuple[str, ...]
    latency_ms: float
    error: object = None
    evidence_group_id: str | None = None

    def to_dict(self):
        result = asdict(self)
        result["evidence_state"] = self.evidence_state.value
        return result


def evidence_group(item, existing):
    """Stable underlying record identity, independent of local IDs, clauses, timestamps or repeated requests."""
    source = item.source_provenance
    parent_id = source.get("policy_evidence_id")
    if parent_id:
        return next((e.evidence_group_id for e in existing if e.id == parent_id), None)
    if item.method == "official_recruitment_policy":
        identity = "official_policy:" + source.get("url", "")
    elif item.method == "rdap_domain_provenance" and source.get("queried_rdap_url"):
        identity = "rdap_record:" + source["queried_rdap_url"]
    elif item.method == "receiver_reported_spf_dkim_dmarc" and source.get("file_sha256"):
        identity = "receiver_report:" + source["file_sha256"]
    else:
        return None
    return "eg_" + sha256(identity.encode())[:24]
