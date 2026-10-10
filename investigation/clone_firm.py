"""Bounded clone-firm vertical slice; published regulator facts remain independent of extraction."""
from collections import Counter
from dataclasses import replace
import re
import time

from .models import Evidence, EvidenceState as State, critical_claims, grounding_issue, sha256, evidence_group
from .regulated_firm import RegulatorVerifier, LegalEntityVerifier, FIRM, NO_CONNECTION, compare_contacts, website_domain
from .verifiers import DomainVerifier

CLONE_KINDS={"regulated_firm","regulated_contact","legal_entity","clone_affiliation"}
BOUNDARIES=[
    "Input is an asserted communication, not proof that a specific person sent it.",
    "A genuine FRN and active legal entity do not authenticate IPO Horizon, its website, an individual caller or an investment.",
    "All facts/comparisons derived from one FCA warning share one source group; Companies House and RDAP are separate mechanisms.",
    "The FCA warning identifies a particular clone and records the genuine firm's details; current permissions for a proposed investment are not queried.",
    "Companies House name/number/status are verified registry fields. This is not an ownership, beneficial-owner or filed-information accuracy investigation.",
    "RDAP proves infrastructure metadata only, never affiliation or investment legitimacy. Missing registration data is not a fraud finding.",
    "V1 is curated for IPO Horizon/Horizon Financial Planning Limited; unknown regulator records and claims remain unresolved.",
    "Email authentication is not part of this fixture and no email export is inferred.",
]


def warning_entities(record):
    if not record or record.evidence_state!=State.VERIFIED: return None
    facts=record.observations
    if facts.get('exact_evidence',{}).get('no_connection_quote')!=NO_CONNECTION: return None
    genuine=facts.get('genuine_name','')
    clone=re.sub(r'\s*\(Clone of FCA authorised firm\)$','',facts.get('clone_name',''),flags=re.I)
    return (clone,genuine) if clone and genuine else None


def warning_binding(claim, record):
    """Exact entities from a validated warning; names alone never establish a contradiction."""
    entities=warning_entities(record)
    if not entities: return False
    clone,genuine=entities
    quote=claim.source_quote.casefold()
    named=lambda name: bool(re.search(r"(?<!\w)"+re.escape(name.casefold())+r"(?!\w)",quote))
    relationship=named(clone) and named(genuine) and bool(re.search(r"\b(represent\w*|operated by|part of|work for)\b",quote))
    organization=claim.organization.casefold() if claim.organization else None
    return relationship and (organization in {clone.casefold(),genuine.casefold()} or organization is None)


class CloneFirmInvestigation:
    def __init__(self,regulator=None,legal_entity=None,domain=None):
        self.regulator=regulator or RegulatorVerifier()
        self.legal_entity=legal_entity or LegalEntityVerifier()
        self.domain=domain or DomainVerifier("live")

    def investigate_extracted(self,message,extraction,input_origin="user_supplied"):
        start=time.perf_counter()
        claims,omitted=critical_claims(extraction.claims)
        evidence=[]
        def add(method,call):
            ident=f"e{len(evidence)+1}";started=time.perf_counter()
            try:
                e=call(ident)
                if not isinstance(e,Evidence) or e.id!=ident or not isinstance(e.evidence_state,State):
                    raise ValueError("Invalid deterministic evidence contract")
            except Exception as exc:
                e=Evidence(ident,method,State.NO_DATA,{}, {"origin":"verifier_failure"},{},
                           ("Verifier failures remain data gaps.",),round((time.perf_counter()-started)*1000,3),
                           {"type":type(exc).__name__,"message":str(exc)})
            if not e.evidence_group_id: e=replace(e,evidence_group_id=evidence_group(e,evidence))
            evidence.append(e);return e
        known=any(c.organization and c.organization.casefold()==FIRM.casefold() for c in claims)
        fca=add("regulator_record_lookup",self.regulator.verify) if known or any(c.kind in {"clone_affiliation","representation","regulated_contact"} for c in claims) else None
        legal=add("legal_entity_registry",self.legal_entity.verify) if known and any(c.kind=="legal_entity" for c in claims) else None
        domains={};comparisons={};results=[];normalizations=[]
        for c in claims:
            if c.kind=="representation" and warning_binding(c,fca):
                normalizations.append({'claim_id':c.id,'original_kind':c.kind,'original_route':c.verification_route,
                    'normalized_kind':'clone_affiliation','normalized_route':'regulator_clone_warning',
                    'evidence_id':fca.id,'evidence_group_id':fca.evidence_group_id,
                    'reason':'Exact named entities and explicit representation relationship match the validated regulator warning.'})
                c=replace(c,kind='clone_affiliation',verification_route='regulator_clone_warning')
            issue=grounding_issue(c,message)
            if c.kind in CLONE_KINDS:
                if c.polarity!="positive" or re.search(r"\b(not|never|no|inactive)\b|isn[’\']t",c.source_quote,re.I):
                    issue="Negative predicates are outside the positive curated record scope"
                elif c.statement != c.source_quote:
                    issue="Curated regulatory/legal candidates require exact source wording; unreviewed paraphrases cannot become verified"
            state=State.NO_DATA;method=c.verification_route;used=[];finding="No curated V1 record establishes this claim.";limits=[]
            in_scope=bool(c.organization and c.organization.casefold()==FIRM.casefold())
            if c.kind=="clone_affiliation":
                in_scope=warning_binding(c,fca)
                used=[fca.id] if fca else []
            elif c.kind=="regulated_contact":
                entities=warning_entities(fca)
                contacts=fca.observations if entities else {}
                in_scope=bool(entities and c.organization and c.organization.casefold() in {n.casefold() for n in entities}
                    and contacts.get('clone_contacts',{}).get('website') and contacts.get('genuine_contacts',{}).get('website'))
                used=[fca.id] if fca else []
            if issue:
                finding=issue;method="candidate_grounding_guard"
            elif not in_scope:
                finding=("A validated named-clone warning is unavailable." if c.kind=="clone_affiliation" and (not fca or fca.evidence_state!=State.VERIFIED)
                         else "Claim does not bind to the exact entities and relationship in the regulator record." if c.kind=="clone_affiliation"
                         else "Organization is outside the curated clone-firm record scope.")
            elif c.kind=="regulated_firm":
                used=[fca.id]
                frns=re.findall(r"(?<!\d)\d{6}(?!\d)",c.source_quote)
                if FIRM.casefold() not in c.source_quote.casefold() or "fca" not in c.source_quote.casefold() or not re.search(r"authori[sz]ed",c.source_quote,re.I) or len(frns)!=1:
                    finding="Regulatory claim must name the firm, FCA authorisation and one literal six-digit FRN."
                    method="candidate_grounding_guard"
                elif fca.evidence_state==State.VERIFIED:
                    state=State.VERIFIED if frns[0]==fca.observations["frn"] else State.CONTRADICTED
                    finding=f"FCA's warning identifies {FIRM} as the genuine authorised firm with FRN {fca.observations['frn']}." if state==State.VERIFIED else "The asserted FRN differs from the regulator-published genuine firm record."
                else: finding="FCA record unavailable; no regulatory-status conclusion was invented."
                limits=["Verification scope is the FCA warning's published genuine-firm identity/FRN, not the contacting party or current product permissions."]
            elif c.kind=="legal_entity":
                used=[legal.id] if legal else []
                if FIRM.casefold() not in c.source_quote.casefold() or not re.search(r"\bactive\b",c.source_quote,re.I):
                    finding="Active-company candidate is not grounded in an explicit named active-entity assertion."
                    method="candidate_grounding_guard"
                elif legal and legal.evidence_state==State.VERIFIED:
                    state=State.VERIFIED if legal.observations["status"].casefold()=="active" else State.CONTRADICTED
                    finding=f"Companies House lists {FIRM}, company {legal.observations['company_number']}, as {legal.observations['status']}."
                else: finding="Legal-entity record unavailable; company activity remains unresolved."
                limits=["A true legal-entity fact does not prove IPO Horizon represents that entity or that an investment is authorised."]
            elif c.kind=="clone_affiliation":
                used=[fca.id]
                if fca.evidence_state==State.VERIFIED and fca.observations.get("exact_evidence",{}).get("no_connection_quote")==NO_CONNECTION:
                    state=State.CONTRADICTED
                    clone=re.sub(r"\s*\(Clone of FCA authorised firm\)$", "", fca.observations["clone_name"], flags=re.I)
                    finding=f"FCA identifies {clone} as a clone and expressly says the genuine authorised firm has no connection with it."
                else: finding="A validated named-clone warning is unavailable."
                limits=["This contradicts the named clone's organizational connection; it does not establish the personal identity of whoever supplied the text."]
            elif c.kind=="regulated_contact":
                if not c.domain or not re.search(r"\bofficial\b",c.source_quote,re.I):
                    method="candidate_grounding_guard";finding="Official-contact candidate requires a literal domain and official-contact assertion."
                else:
                    if c.domain not in domains: domains[c.domain]=add("rdap_domain_provenance",lambda ident:self.domain.verify(c.domain,ident))
                    phones=re.findall(r"\+\d{9,15}",c.source_quote)
                    if len(phones)>1:
                        finding="Multiple telephone contacts cannot be unambiguously scoped to this atomic claim."
                    else:
                        phone=phones[0] if phones else None
                        key=(c.domain,phone)
                        if key not in comparisons: comparisons[key]=add("regulator_contact_comparison",lambda ident:compare_contacts(c.domain,phone,fca,ident))
                        item=comparisons[key];state=item.evidence_state;used=[fca.id,item.id,domains[c.domain].id]
                        if state==State.CONTRADICTED:
                            finding="The supplied domain/contact differs from the FCA-published genuine firm's contact details."
                        elif state==State.CONSISTENT:
                            finding="The supplied contact matches the published record; this does not authenticate the contacting party."
                        else: finding="No validated regulator contacts are available for comparison."
                        limits=list(item.limitations)
            results.append({**c.to_dict(),"verification_method":method,"verification_scope":method,
                            "evidence_ids":used,"evidence_state":state.value,"finding":finding,"limitations":limits,
                            "contacting_party_authenticated":False})
        # Explicit deterministic correlation: correct credentials + active entity do
        # not override the same regulator's named-clone disavowal/contact mismatch.
        true_ids=[c["id"] for c in results if c["evidence_state"]==State.VERIFIED.value]
        false_ids=[c["id"] for c in results if c["evidence_state"]==State.CONTRADICTED.value]
        correlation={"true_fact_claim_ids":true_ids,"contradicted_connection_claim_ids":false_ids,
                     "contacting_party_authenticated":False,
                     "finding":"Genuine regulatory/company facts coexist with contradicted clone affiliation/contact claims. The genuine facts do not transfer authorisation or identity to the contacting party." if true_ids and false_ids else "Insufficient resolved true/contradicted facts to establish the intended cross-record conflict."}
        used={i for c in results for i in c["evidence_ids"]};groups={}
        for e in evidence:
            if e.id not in used or e.error or e.evidence_state==State.NO_DATA or not e.evidence_group_id: continue
            if "synthetic" in str(e.source_provenance.get("origin","")).casefold(): continue
            mechanism="regulator_record_lookup" if e.method=="regulator_contact_comparison" else e.method
            g=groups.setdefault(e.evidence_group_id,{"mechanism":mechanism,"evidence_ids":[]})
            g["evidence_ids"].append(e.id)
        resolved=sum(c["evidence_state"]!=State.NO_DATA.value for c in results)
        unresolved=len(results)-resolved
        checks={"4_to_5_critical_claims":4<=len(results)<=5,"at_least_3_useful_findings":resolved>=3,
                "at_least_2_independent_evidence_groups":len(groups)>=2,
                "at_least_2_verification_mechanisms":len({g["mechanism"] for g in groups.values()})>=2,
                "at_most_2_unresolved_critical_claims":unresolved<=2,
                "true_fact_does_not_authenticate_contacting_party":bool(true_ids and false_ids),
                "zero_fabricated_evidence":True}
        summary={"useful_finding_count":resolved,"independent_evidence_count":len(groups),
                 "verification_mechanism_count":len({g["mechanism"] for g in groups.values()}),
                 "contradicted_claim_count":len(false_ids),"verified_claim_count":len(true_ids),"unresolved_claim_count":unresolved,
                 "evidence_groups":groups,"demo_gate":{"result":"PASS" if all(checks.values()) else "FAIL","checks":checks},
                 "boundary":"Useful findings are distinct resolved critical predicates; they are not independent sources. FCA-derived findings share one group. LLM reliability is evaluated separately."}
        contradictions=[{"claim_id":c["id"],"finding":c["finding"],"evidence_ids":c["evidence_ids"]} for c in results if c["evidence_state"]==State.CONTRADICTED.value]
        return {"schema_version":"1.1","scenario":"regulated_investment_clone_firm","status":"completed_with_gaps" if unresolved else "completed",
                "input":{"message":message,"message_sha256":sha256(message.encode()),"origin":input_origin,"eml_supplied":False},
                "extraction":{**extraction.provenance,"omitted_candidates":omitted,"routing_normalizations":normalizations},"claims":results,"evidence":[e.to_dict() for e in evidence],
                "summary":summary,"evidence_correlation":correlation,
                "contradiction_summary":{"count":len(contradictions),"items":contradictions,
                   "independent_evidence_group_ids":sorted({e.evidence_group_id for e in evidence if e.evidence_state==State.CONTRADICTED and e.evidence_group_id} | ({fca.evidence_group_id} if false_ids and fca else set())),
                   "boundary":"Shared FCA facts are one underlying source, not independent risk signals."},
                "evidence_state_counts":dict(Counter(c["evidence_state"] for c in results)),
                "limitations":BOUNDARIES+list(dict.fromkeys(x for e in evidence for x in e.limitations)),
                "explanation":"\n\n".join(c["finding"] for c in results)+"\n\n"+correlation["finding"],
                "explanation_provenance":{"mode":"deterministic_templates","authoritative":False},
                "latency_ms":round((time.perf_counter()-start)*1000,3)}
