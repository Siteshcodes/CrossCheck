"""Offline regression tests use actual captures or explicitly labelled failure doubles."""
import base64
import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from investigation.api import investigate_request
from investigation.clone_firm import CloneFirmInvestigation
from investigation.engine import InvestigationEngine
from investigation.llm import AnnotationExtractor
from investigation.models import Evidence, EvidenceState as State, sha256
from investigation.regulated_firm import RegulatorVerifier, LegalEntityVerifier, parse_fca, parse_company, compare_contacts, FIRM
from investigation.verifiers import DomainVerifier, ROOT

FIXTURE=ROOT/"fixtures/clone_firm"
MESSAGE=(FIXTURE/"message.txt").read_text(encoding="utf-8")
ANNOTATION=json.loads((FIXTURE/"claims.json").read_text(encoding="utf-8"))


class CaptureReplay:
    """Actual saved HTTPS bytes, explicitly labelled unit replay, never live transport."""
    def __init__(self,verifier,path): self.verifier,self.path=verifier,path
    def verify(self,ident):
        raw=json.loads(self.path.read_text(encoding="utf-8"))
        with patch("investigation.regulated_firm.fetch_policy",return_value=(raw,None)):
            result=self.verifier.verify(ident)
        return replace(result,source_provenance={**result.source_provenance,"origin":"real_http_capture_unit_replay", "network_request_made":False,"retrieved_at_utc":raw["retrieved_at_utc"]})


def core(regulator=None,legal=None,domain=None):
    return CloneFirmInvestigation(regulator or CaptureReplay(RegulatorVerifier(),FIXTURE/"fca_capture.json"),
        legal or CaptureReplay(LegalEntityVerifier(),FIXTURE/"companies-house_capture.json"),domain or DomainVerifier("unavailable"))


def run(annotation=None,backend=None,message=MESSAGE):
    extraction=AnnotationExtractor(annotation or ANNOTATION).extract(message)
    return (backend or core()).investigate_extracted(message,extraction,"synthetic_test_input")


class CloneFirmTests(unittest.TestCase):
    def test_both_affiliation_routes_and_entity_bindings(self):
        for kind,route in [('representation','identity_boundary'),('clone_affiliation','regulator_clone_warning')]:
            for organization in ['IPO Horizon',FIRM]:
                with self.subTest(kind=kind,organization=organization):
                    a=copy.deepcopy(ANNOTATION);a['claims'][0].update(kind=kind,verification_route=route,organization=organization)
                    r=run(a);c=r['claims'][0]
                    self.assertEqual(c['verification_method'],'regulator_clone_warning')
                    self.assertEqual(c['evidence_state'],State.CONTRADICTED.value)
                    self.assertEqual(bool(r['extraction']['routing_normalizations']),kind=='representation')

    def test_contact_binds_both_record_entities(self):
        for organization in ['IPO Horizon',FIRM]:
            with self.subTest(organization=organization):
                a=copy.deepcopy(ANNOTATION);a['claims'][3]['organization']=organization
                r=run(a);c=r['claims'][3]
                self.assertEqual(c['evidence_state'],State.CONTRADICTED.value)
                self.assertEqual(c['verification_method'],'regulator_contact_comparison')
                self.assertEqual(r['evidence'][0]['evidence_group_id'],next(e for e in r['evidence'] if e['method']=='regulator_contact_comparison')['evidence_group_id'])

    def test_unrelated_and_similar_contacts_remain_unresolved(self):
        for organization in ['Other Investments','IPO Horizons']:
            a=copy.deepcopy(ANNOTATION);message=MESSAGE+' '+organization
            a['message_sha256']=sha256(message.encode());a['claims'][3]['organization']=organization
            self.assertEqual(run(a,message=message)['claims'][3]['evidence_state'],State.NO_DATA.value)

    def test_representation_not_normalized_without_warning(self):
        class Missing:
            def verify(self,ident): raise TimeoutError('SYNTHETIC TEST missing warning')
        a=copy.deepcopy(ANNOTATION);a['claims'][0].update(kind='representation',verification_route='identity_boundary',organization='IPO Horizon')
        r=run(a,backend=core(regulator=Missing()))
        self.assertEqual(r['extraction']['routing_normalizations'],[])
        self.assertEqual(r['claims'][0]['evidence_state'],State.NO_DATA.value)

    def clone_claim(self,organization,message=None,backend=None):
        message=message or ANNOTATION['claims'][0]['source_quote']
        claim=copy.deepcopy(ANNOTATION['claims'][0])
        claim.update(organization=organization,statement=message,source_quote=message,start=0,end=len(message))
        annotation={'origin':'analyst_annotation','message_sha256':sha256(message.encode()),'claims':[claim]}
        return run(annotation,backend,message)['claims'][0]

    def test_warning_binds_genuine_organization(self):
        self.assertEqual(self.clone_claim(FIRM)['evidence_state'],State.CONTRADICTED.value)

    def test_warning_binds_exact_clone_organization(self):
        self.assertEqual(self.clone_claim('IPO Horizon')['evidence_state'],State.CONTRADICTED.value)

    def test_warning_binds_explicit_relationship_without_organization(self):
        self.assertEqual(self.clone_claim(None)['evidence_state'],State.CONTRADICTED.value)

    def test_warning_does_not_bind_unrelated_organization(self):
        message='Other Investments says we are IPO Horizon, representing '+FIRM+'.'
        self.assertEqual(self.clone_claim('Other Investments',message)['evidence_state'],State.NO_DATA.value)

    def test_warning_does_not_bind_similar_clone_name(self):
        message='We are IPO Horizons, representing '+FIRM+'.'
        self.assertEqual(self.clone_claim('IPO Horizons',message)['evidence_state'],State.NO_DATA.value)

    def test_missing_warning_cannot_bind_clone(self):
        class Missing:
            def verify(self,ident): raise TimeoutError('SYNTHETIC TEST warning unavailable')
        self.assertEqual(self.clone_claim('IPO Horizon',backend=core(regulator=Missing()))['evidence_state'],State.NO_DATA.value)

    def test_bound_names_without_explicit_disavowal_are_not_contradiction(self):
        class NoDisavowal:
            def verify(self,ident):
                e=core().regulator.verify(ident)
                observations=copy.deepcopy(e.observations);observations['exact_evidence'].pop('no_connection_quote')
                return replace(e,observations=observations)
        self.assertEqual(self.clone_claim('IPO Horizon',backend=core(regulator=NoDisavowal()))['evidence_state'],State.NO_DATA.value)

    def test_clone_name_alone_does_not_assert_impersonation(self):
        self.assertEqual(self.clone_claim('IPO Horizon','We are IPO Horizon.')['evidence_state'],State.NO_DATA.value)

    def test_four_claims_and_true_facts_do_not_authenticate_clone(self):
        result=run()
        self.assertEqual(len(result["claims"]),4)
        self.assertEqual(result["summary"]["verified_claim_count"],2)
        self.assertEqual(result["summary"]["contradicted_claim_count"],2)
        self.assertEqual(result["summary"]["unresolved_claim_count"],0)
        self.assertEqual(result["summary"]["demo_gate"]["result"],"PASS")
        self.assertFalse(result["evidence_correlation"]["contacting_party_authenticated"])
        self.assertEqual(len(result["evidence_correlation"]["true_fact_claim_ids"]),2)
    def test_multiple_fca_facts_share_one_group(self):
        r=run();items={e["method"]:e for e in r["evidence"]}
        self.assertEqual(items["regulator_record_lookup"]["evidence_group_id"],items["regulator_contact_comparison"]["evidence_group_id"])
        self.assertEqual(r["summary"]["independent_evidence_count"],2)
        self.assertEqual(r["summary"]["verification_mechanism_count"],2)
        self.assertEqual(len(r["contradiction_summary"]["independent_evidence_group_ids"]),1)
    def test_contact_match_is_consistency_not_identity(self):
        fca=core().regulator.verify("e1")
        e=compare_contacts("horizonfp.co.uk","+4401214279009",fca,"e2")
        self.assertEqual(e.evidence_state,State.CONSISTENT)
        self.assertIn("does not authenticate",e.limitations[0])
    def test_lookalike_and_subdomain_are_not_exact_regulator_contacts(self):
        fca=core().regulator.verify("e1")
        for domain in ["ipohorizon.com","horizonfp.co.uk.attacker.example","jobs.horizonfp.co.uk"]:
            with self.subTest(domain=domain):
                self.assertEqual(compare_contacts(domain,None,fca,"e2").evidence_state,State.CONTRADICTED)
    def test_both_contact_fields_really_differ(self):
        r=run();compare=next(e for e in r["evidence"] if e["method"]=="regulator_contact_comparison")
        self.assertFalse(compare["observations"]["domain_match"])
        self.assertFalse(compare["observations"]["phone_match"])
        self.assertEqual(compare["observations"]["regulator_domain"],"horizonfp.co.uk")
    def test_regulator_failure_creates_gaps_not_contradictions(self):
        class Broken:
            def verify(self,ident): raise TimeoutError("SYNTHETIC TEST timeout")
        r=run(backend=core(regulator=Broken()))
        self.assertEqual(r["summary"]["contradicted_claim_count"],0)
        self.assertEqual(r["summary"]["unresolved_claim_count"],3)
        self.assertEqual(r["summary"]["demo_gate"]["result"],"FAIL")
        self.assertEqual(r["evidence"][0]["error"]["type"],"TimeoutError")
    def test_company_failure_is_not_company_inactivity(self):
        class Broken:
            def verify(self,ident): raise ValueError("SYNTHETIC TEST company unavailable")
        r=run(backend=core(legal=Broken()))
        c=next(c for c in r["claims"] if c["kind"]=="legal_entity")
        self.assertEqual(c["evidence_state"],State.NO_DATA.value)
    def test_changed_source_structure_fails_closed(self):
        raw=json.loads((FIXTURE/"fca_capture.json").read_text(encoding="utf-8"))
        with self.assertRaises(ValueError): parse_fca(raw["raw_body"].replace("section-fca-authorised-firm-details","missing-section"))
        with self.assertRaises(ValueError): parse_fca(raw["raw_body"].replace("It has no connection with the clone firm.","unreviewed replacement"))
        company=json.loads((FIXTURE/"companies-house_capture.json").read_text(encoding="utf-8"))
        with self.assertRaises(ValueError): parse_company(company["raw_body"].replace('id="company-status"','id="missing"'))
    def test_source_byte_tampering_is_visible(self):
        raw=json.loads((FIXTURE/"fca_capture.json").read_text(encoding="utf-8"));raw["raw_body"]+="invented text"
        with patch("investigation.regulated_firm.fetch_policy",return_value=(raw,None)):
            e=RegulatorVerifier().verify("e1")
        self.assertEqual(e.evidence_state,State.NO_DATA)
        self.assertIn("differ",e.error["message"])
    def test_hallucinated_statement_never_becomes_verified(self):
        a=copy.deepcopy(ANNOTATION);a["claims"][1]["statement"]="Horizon Financial Planning Limited guarantees a safe investment."
        r=run(a)
        self.assertEqual(r["claims"][1]["evidence_state"],State.NO_DATA.value)
        self.assertEqual(r["claims"][1]["verification_method"],"candidate_grounding_guard")
    def test_negative_predicate_mislabeled_positive_not_verified(self):
        message="Horizon Financial Planning Limited is not FCA authorised with Firm Reference Number 307222."
        c=copy.deepcopy(ANNOTATION["claims"][1]);c.update(source_quote=message,statement=message,start=0,end=len(message))
        a={"origin":"analyst_annotation","message_sha256":sha256(message.encode()),"claims":[c]}
        r=run(a,message=message)
        self.assertEqual(r["claims"][0]["evidence_state"],State.NO_DATA.value)
    def test_changed_company_status_is_compared_not_forced_active(self):
        raw=json.loads((FIXTURE/"companies-house_capture.json").read_text(encoding="utf-8"))
        parsed=parse_company(raw["raw_body"].replace('Active\n','Dissolved\n'))
        # Test altered HTML parser facts only; never present as live authoritative evidence.
        self.assertEqual(parsed["status"],"Dissolved")
    def test_actual_captures_integrity(self):
        for name in ["fca_capture.json","companies-house_capture.json"]:
            raw=json.loads((FIXTURE/name).read_text(encoding="utf-8"))
            self.assertEqual(raw["http_status"],200)
            body=base64.b64decode(raw["raw_body_base64"],validate=True)
            self.assertEqual(sha256(body),raw["captured_sha256"])
            self.assertEqual(body.decode("utf-8"),raw["raw_body"])
    def test_api_dispatches_new_claims_to_same_deterministic_slice(self):
        engine=InvestigationEngine(domain_verifier=DomainVerifier("unavailable"))
        with patch("investigation.clone_firm.CloneFirmInvestigation",return_value=core()):
            r=investigate_request({"message":MESSAGE,"claims_annotation":ANNOTATION},engine,True)
        self.assertEqual(r["scenario"],"regulated_investment_clone_firm")
        self.assertEqual(r["summary"]["unresolved_claim_count"],0)
    def test_unknown_organization_not_upgraded_from_known_record(self):
        message="Unconfigured Firm is an active UK company."
        c=copy.deepcopy(ANNOTATION["claims"][2]);c.update(organization="Unconfigured Firm",source_quote=message,statement=message,start=0,end=len(message))
        a={"origin":"analyst_annotation","message_sha256":sha256(message.encode()),"claims":[c]}
        r=run(a,message=message)
        self.assertEqual(r["claims"][0]["evidence_state"],State.NO_DATA.value)
        self.assertEqual(r["evidence"],[])

if __name__=="__main__": unittest.main()
