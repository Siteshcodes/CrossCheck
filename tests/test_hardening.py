import unittest
from unittest.mock import patch
from investigation.models import ROUTES, InvalidInput, validate_claims, claim_schema
from investigation.benchmark import run_benchmark
from test_investigation import engine, MESSAGE, annotation_for, one_claim

class HardeningTests(unittest.TestCase):
    def test_shared_policy_is_one_group(self):
        r=engine().investigate(MESSAGE)
        policy,comparison=[e for e in r["evidence"] if e["method"] in {"official_recruitment_policy","official_recruiting_domain_comparison"}]
        self.assertEqual(policy["evidence_group_id"],comparison["evidence_group_id"])
        self.assertEqual(r["summary"]["independent_evidence_count"],1)
        self.assertEqual(r["summary"]["unresolved_claim_count"],3)
        self.assertEqual(r["summary"]["demo_gate"]["result"],"FAIL")
    def test_group_stable_across_runs(self):
        self.assertEqual(engine().investigate(MESSAGE)["summary"],engine().investigate(MESSAGE)["summary"])
    def test_hallucinated_registration_cannot_trigger_lookup(self):
        message="Contact me at recruiter@example.com"
        claim=one_claim("domain_registration",message,"example.com",None)
        with patch("investigation.verifiers.DomainVerifier.verify") as lookup:
            r=engine(annotation_for(message,[claim])).investigate(message)
            lookup.assert_not_called()
        self.assertEqual(r["claims"][0]["evidence_state"],"NO_AUTHORITATIVE_DATA")
    def test_wrong_route_rejected(self):
        c=one_claim();c["verification_route"]="rdap_domain_provenance"
        with self.assertRaises(InvalidInput): validate_claims({"claims":[c]},"NVIDIA")
    def test_schema_forbids_states(self):
        props=claim_schema()["properties"]["claims"]["items"]["properties"]
        self.assertNotIn("evidence_state",props)
    def test_duplicates_not_extra_critical_claims(self):
        c=one_claim()
        r=engine(annotation_for("NVIDIA",[c,dict(c,id="c2")])).investigate("NVIDIA")
        self.assertEqual(len(r["claims"]),1)
        self.assertEqual(len(r["extraction"]["omitted_candidates"]),1)
    def test_missing_key_has_unavailable_metrics(self):
        with patch("investigation.llm.local_settings",return_value={}), patch.dict("os.environ",{},clear=True):
            r=run_benchmark()
        self.assertGreaterEqual(r["summary"]["case_count"],10)
        self.assertEqual(r["summary"]["network_requests"],0)
        self.assertIsNone(r["summary"]["unsupported_hallucinated_claims"])
