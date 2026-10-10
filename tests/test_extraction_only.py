"""Focused extractor/metric checks only; no NVIDIA or other evidence tests."""
import json
import unittest
from unittest.mock import patch
from investigation.llm import (LLMExtractor, LLMFailure, OpenAIClient, expand_candidates, extraction_schema, compact_schema_errors)
from investigation.models import InvalidInput, validate_claims
from investigation.benchmark import score_output, summarize


def candidate(kind="representation",quote="I am an NVIDIA recruiter.",org="NVIDIA",route="id",domain=None,polarity="+"):
    return {"k":kind,"o":org,"q":quote,"d":domain,"p":polarity,"b":"e","r":route}


def case():
    return {"message":"I am an NVIDIA recruiter.","expected_critical_claims":[{"kind":"representation","organization":"NVIDIA","domain":None,"polarity":"positive"}]}


class ExtractionOnlyTests(unittest.TestCase):
    def test_no_evidence_state_in_wire_schema(self):
        s=extraction_schema();self.assertNotIn("evidence_state",json.dumps(s));self.assertFalse(s["additionalProperties"])
    def test_exact_quotes_derive_unicode_offsets(self):
        message="Hi, I’m an NVIDIA recruiter."
        c=candidate(quote="I’m an NVIDIA recruiter.")
        expanded=expand_candidates({"claims":[c]},message)
        claim=validate_claims(expanded,message)[0]
        self.assertEqual(message[claim.start:claim.end],claim.source_quote)
        self.assertEqual(claim.statement,claim.source_quote)
    def test_nonexistent_and_ambiguous_quotes_rejected(self):
        for message in ["Other text", "I am an NVIDIA recruiter. I am an NVIDIA recruiter."]:
            with self.assertRaises(InvalidInput): expand_candidates({"claims":[candidate()]},message)
    def test_final_state_injection_rejected(self):
        for data in [{"claims":[dict(candidate(),evidence_state="VERIFIED_BY_AUTHORITATIVE_SOURCE")]},{"claims":[],"evidence_state":"VERIFIED_BY_AUTHORITATIVE_SOURCE"}]:
            self.assertTrue(compact_schema_errors(data))
    def test_invalid_route_never_enters_extraction(self):
        class Double:
            def structured(self,*args): return {"claims":[candidate(route="rdap")]},{"origin":"SYNTHETIC_TEST_DOUBLE"}
        with self.assertRaises(LLMFailure): LLMExtractor(Double()).extract(case()["message"])
    def test_metric_route_error_not_false_hallucination(self):
        score=score_output(case(),{"claims":[candidate(route="rdap")]})
        self.assertEqual(score["recalled"],1)
        self.assertEqual(score["invalid_routing"],1)
        self.assertEqual(score["unsupported_hallucinated_claims"],0)
    def test_hallucinated_quote_counts_as_unsupported(self):
        score=score_output(case(),{"claims":[candidate(quote="invented") ]})
        self.assertEqual(score["recalled"],0)
        self.assertEqual(score["unsupported_hallucinated_claims"],1)
    def test_unlabeled_critical_claim_counts_as_unsupported(self):
        message="I am an NVIDIA recruiter. NVIDIA will reimburse you."
        c=case();c["message"]=message
        score=score_output(c,{"claims":[candidate(),candidate("reimbursement","NVIDIA will reimburse you.",route="policy")]})
        self.assertEqual(score["unsupported_hallucinated_claims"],1)
    def test_cap_not_silent_truncation(self):
        with self.assertRaises(InvalidInput): expand_candidates({"claims":[candidate()]*6},case()["message"])
    def test_invalid_schema_types_not_python_crash(self):
        self.assertTrue(compact_schema_errors({"claims":[dict(candidate(),k={})]}))
    def test_failure_cases_stay_in_recall_denominator(self):
        r=summarize([{"expected_count":1,"recalled":1,"model_output_received":True,"schema_valid":True,"emitted_claim_count":1,"unsupported_hallucinated_claims":0,"invalid_routing":0,"status":"PASS","network_request_made":True,"latency_ms":1000},
                    {"expected_count":1,"recalled":0,"model_output_received":False,"status":"FAIL","network_request_made":True,"latency_ms":2000}])
        self.assertEqual(r["critical_claim_recall"],.5)
        self.assertEqual(r["median_latency_ms"],1500)
        self.assertEqual(r["p95_latency_ms"],2000)
    def test_no_key_does_not_fabricate_latency_or_accuracy(self):
        r=summarize([{"expected_count":1,"recalled":0,"model_output_received":False,"status":"FAIL","network_request_made":False,"latency_ms":None}])
        self.assertIsNone(r["critical_claim_recall"])
        self.assertIsNone(r["median_latency_ms"])
        self.assertEqual(r["result"],"FAIL")
    def test_request_uses_low_effort_and_bounded_output(self):
        class Response:
            status=200;headers={}
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,*args): return json.dumps({"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":'{"claims":[]}'}]}]}).encode()
        class Opener:
            def open(self,request,timeout):
                payload=json.loads(request.data)
                self.payload=payload
                return Response()
        opener=Opener()
        with patch("investigation.llm.build_opener",return_value=opener):
            OpenAIClient(api_key="SYNTHETIC_NONSECRET_TEST_TOKEN").structured("test","hi",extraction_schema(),"atomic_claims")
        self.assertEqual(opener.payload["reasoning"],{"effort":"low"})
        self.assertEqual(opener.payload["max_output_tokens"],1600)
        self.assertNotIn("tools",opener.payload)

if __name__=="__main__": unittest.main()
