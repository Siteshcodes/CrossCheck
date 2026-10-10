"""Deterministic unit/integration tests. All doubles and email fixtures are synthetic."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from investigation.api import investigate_request, make_server
from investigation.engine import InvestigationEngine
from investigation.llm import AnnotationExtractor, LLMExplainer, LLMExtractor, LLMFailure, OpenAIClient
from investigation.models import EvidenceState as State, InvalidInput, sha256, strict_json, validate_claims, ROUTES
from investigation.verifiers import DomainVerifier, PolicyVerifier, ReceiverHeaderVerifier, ROOT, official_domain_comparison


FIXTURE = ROOT / "fixtures/nvidia_recruiter"
MESSAGE = (FIXTURE / "message.txt").read_text(encoding="utf-8")
ANNOTATION = strict_json((FIXTURE / "claims.json").read_text(encoding="utf-8"))


def annotation_for(message, claims):
    return {"origin": "analyst_annotation", "message_sha256": sha256(message.encode()), "claims": claims}


def one_claim(kind="representation", message="NVIDIA", domain=None, organization="NVIDIA"):
    return {"id": "c1", "kind": kind, "statement": "Synthetic test assertion", "organization": organization,
            "source_quote": message, "start": 0, "end": len(message), "domain": domain, "basis": "explicit", "verification_route": ROUTES[kind], "polarity": "positive"}


def engine(annotation=None, **kwargs):
    return InvestigationEngine(extractor=AnnotationExtractor(annotation or ANNOTATION),
        policy_verifier=kwargs.pop("policy_verifier", PolicyVerifier("snapshot")),
        domain_verifier=kwargs.pop("domain_verifier", DomainVerifier("unavailable")),
        header_verifier=kwargs.pop("header_verifier", ReceiverHeaderVerifier("mx.receiver.example")), **kwargs)


class EngineTests(unittest.TestCase):
    def test_complete_nvidia_vertical_slice(self):
        result = engine().investigate(MESSAGE, input_origin="synthetic_test")
        self.assertEqual(len(result["claims"]), 4)
        claims = {item["id"]: item for item in result["claims"]}
        self.assertEqual(claims["c2"]["evidence_state"], State.CONTRADICTED.value)
        self.assertEqual(claims["c4"]["evidence_state"], State.NO_DATA.value)
        self.assertEqual(claims["c1"]["evidence_state"], State.NO_DATA.value)
        self.assertEqual(claims["c3"]["evidence_state"], State.NO_DATA.value)
        self.assertEqual(result["contradiction_summary"]["count"], 1)
        self.assertEqual(len(result["contradiction_summary"]["independent_evidence_ids"]), 1)
        self.assertEqual(result["extraction"]["mode"], "fixture_annotation")
        self.assertFalse(result["extraction"]["used_llm"])
        for item in result["claims"]:
            self.assertIn(item["evidence_state"], [state.value for state in State])
            self.assertEqual(MESSAGE[item["start"]:item["end"]], item["source_quote"])
            self.assertTrue(item["verification_method"])
        encoded = json.dumps(result)
        self.assertNotIn('"scam_probability"', encoded)
        self.assertNotIn('"risk_score"', encoded)

    def test_missing_eml_and_rdap_are_explicit_gaps(self):
        result = engine().investigate(MESSAGE)
        evidence = {item["method"]: item for item in result["evidence"]}
        for method in ("receiver_reported_spf_dkim_dmarc", "rdap_domain_provenance"):
            self.assertEqual(evidence[method]["evidence_state"], State.NO_DATA.value)
            self.assertTrue(evidence[method]["error"])
        rdap = evidence["rdap_domain_provenance"]
        self.assertFalse(rdap["raw_evidence"]["network_request_made"])
        self.assertNotIn("registration_date", rdap["observations"])

    def test_fee_warning_never_becomes_invented_prohibition(self):
        result = engine().investigate(MESSAGE)
        self.assertFalse(result["evidence"][0]["observations"]["explicit_no_fee_rule_supported"])
        fee = next(item for item in result["claims"] if item["kind"] == "equipment_fee")
        self.assertEqual(fee["evidence_state"], State.NO_DATA.value)
        self.assertNotIn(fee["id"], [item["claim_id"] for item in result["contradiction_summary"]["items"]])

    def test_policy_failure_does_not_turn_mismatch_into_contradiction(self):
        with tempfile.TemporaryDirectory() as directory:
            failed_policy = PolicyVerifier("snapshot", Path(directory) / "missing.json")
            result = engine(policy_verifier=failed_policy).investigate(MESSAGE)
        self.assertEqual(result["contradiction_summary"]["count"], 0)
        self.assertTrue(result["evidence"][0]["error"])
        self.assertEqual(result["evidence"][0]["evidence_state"], State.NO_DATA.value)

    def test_unexpected_verifier_exception_preserves_claim_completion(self):
        class BrokenPolicy:
            def verify(self, ident):
                raise TimeoutError("SYNTHETIC TEST verifier timeout")
        result = engine(policy_verifier=BrokenPolicy()).investigate(MESSAGE)
        self.assertEqual(len(result["claims"]), 4)
        self.assertEqual(result["contradiction_summary"]["count"], 0)
        self.assertEqual(result["evidence"][0]["error"]["type"], "TimeoutError")

    def test_unknown_organization_and_unsupported_claims_stay_unresolved(self):
        message = "Unconfigured organization requires an OTP"
        claim = one_claim("unsupported", message, organization="Unconfigured")
        result = engine(annotation_for(message, [claim])).investigate(message)
        self.assertEqual(result["claims"][0]["evidence_state"], State.NO_DATA.value)
        self.assertEqual(result["claims"][0]["verification_method"], "unsupported_claim")
        self.assertNotIn("official_recruitment_policy", [item["method"] for item in result["evidence"]])

    def test_passing_attacker_authentication_never_proves_affiliation(self):
        eml = (ROOT / "fixtures/email/display_name_spoof.eml").read_bytes()
        result = engine().investigate(MESSAGE, eml, True)
        affiliation = next(item for item in result["claims"] if item["kind"] == "representation")
        self.assertEqual(affiliation["evidence_state"], State.NO_DATA.value)
        self.assertEqual(result["contradiction_summary"]["count"], 1)
        header = next(item for item in result["evidence"] if item["method"] == "receiver_reported_spf_dkim_dmarc")
        self.assertEqual(header["observations"]["dmarc_outcome"], "pass")
        self.assertFalse(header["source_provenance"]["independent_crypto_or_dns_verification"])

    def test_ambiguous_contact_domains_do_not_correlate_official_claim(self):
        message = "NVIDIA contact recruiter@nvidia.com and recruiter@other.example"
        claims = [one_claim("domain_association", message, "nvidia.com"),
                  dict(one_claim("domain_association", message, "other.example"), id="c2"),
                  dict(one_claim("official_communication", message), id="c3")]
        result = engine(annotation_for(message, claims)).investigate(message)
        self.assertEqual(len(result["claims"]), 2)
        self.assertEqual(result["extraction"]["omitted_candidates"][0]["claim_id"], "c3")

    def test_explanation_failure_keeps_frozen_verdicts_and_error_visible(self):
        class BrokenExplainer:
            def explain(self, findings):
                findings[0]["evidence_state"] = State.VERIFIED.value
                raise LLMFailure("SYNTHETIC TEST API 429", {"http_status": 429})
        baseline = engine().investigate(MESSAGE)
        result = engine(explainer=BrokenExplainer()).investigate(MESSAGE)
        self.assertEqual(result["claims"], baseline["claims"])
        self.assertEqual(result["explanation"], baseline["explanation"])
        self.assertEqual(result["explanation_provenance"]["error"]["provider"]["http_status"], 429)

    def test_one_command_demo(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "result.json"
            run = subprocess.run([sys.executable, "-m", "investigation", "demo", "--output", str(target)], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = strict_json(target.read_text(encoding="utf-8"))
            self.assertEqual(len(result["claims"]), 4)
            self.assertEqual(result["status"], "completed_with_gaps")


class PrimitiveTests(unittest.TestCase):
    def test_real_source_capture_integrity_and_provenance(self):
        item = PolicyVerifier("snapshot").verify("e1")
        self.assertEqual(item.evidence_state, State.VERIFIED)
        self.assertEqual(item.raw_evidence["http_status"], 200)
        self.assertEqual(item.source_provenance["origin"], "real_http_capture")
        self.assertTrue(item.source_provenance["retrieved_at_utc"])

    def test_tampered_capture_fails_closed(self):
        capture = strict_json((FIXTURE / "policy_capture.json").read_text(encoding="utf-8"))
        capture["raw_body"] += " fabricated text"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            path.write_text(json.dumps(capture), encoding="utf-8")
            item = PolicyVerifier("snapshot", path).verify("e1")
        self.assertEqual(item.evidence_state, State.NO_DATA)
        self.assertIn("differs", item.error["message"])

    def test_live_policy_http_failure_is_preserved(self):
        # Clearly synthetic transport double; never recorded as a genuine HTTP capture.
        failure = {"url": "https://www.nvidia.com", "http_status": 403, "raw_body": "SYNTHETIC TEST 403", "error": {"type": "HTTPError", "message": "403"}}
        with patch("investigation.verifiers.policy.fetch_policy", return_value=(failure, None)):
            item = PolicyVerifier("live").verify("e1")
        self.assertEqual(item.evidence_state, State.NO_DATA)
        self.assertEqual(item.raw_evidence["http_status"], 403)
        self.assertTrue(item.error)

    def test_exact_official_domains_and_lookalikes(self):
        source = PolicyVerifier("snapshot").verify("e1")
        cases = {"nvidia.com": State.CONSISTENT, "career.nvidia.com": State.CONSISTENT,
                 "jobs.nvidia.com": State.CONTRADICTED, "nvidia-careers-team.com": State.CONTRADICTED,
                 "nvidia.com.attacker.example": State.CONTRADICTED}
        for domain, state in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(official_domain_comparison(domain, source, "e2").evidence_state, state)

    def test_missing_policy_cannot_produce_domain_contradiction(self):
        missing = PolicyVerifier("snapshot", ROOT / "not-a-real-policy.json").verify("e1")
        self.assertEqual(official_domain_comparison("nvidia-careers-team.com", missing, "e2").evidence_state, State.NO_DATA)

    def test_header_requires_original_export_assertion_and_receiver(self):
        eml = (ROOT / "fixtures/email/legitimate_aligned.eml").read_bytes()
        for verifier, asserted in [(ReceiverHeaderVerifier(), True), (ReceiverHeaderVerifier("mx.receiver.example"), False)]:
            with self.subTest(asserted=asserted, receiver=verifier.trusted_authserv_id):
                result = verifier.verify(eml, asserted, "e1")
                self.assertEqual(result.evidence_state, State.NO_DATA)
                self.assertTrue(result.error)

    def test_header_parser_preserves_receiver_results_without_crypto_claims(self):
        for name, expected in [("legitimate_aligned", "pass"), ("spf_pass_dmarc_misalignment", "fail"), ("valid_multiline", "pass")]:
            with self.subTest(name=name):
                result = ReceiverHeaderVerifier("mx.receiver.example").verify((ROOT / f"fixtures/email/{name}.eml").read_bytes(), True, "e1")
                self.assertEqual(result.evidence_state, State.CONSISTENT)
                self.assertEqual(result.observations["dmarc_outcome"], expected)
                self.assertFalse(result.observations["independent_authentication_performed"])
                self.assertIn("SYNTHETIC", result.source_provenance["origin"])

    def test_forged_receiver_identifier_and_malformed_headers_fail(self):
        valid = (ROOT / "fixtures/email/legitimate_aligned.eml").read_bytes()
        forged = valid.replace(b"mx.receiver.example", b"untrusted.attacker.example")
        malformed = (ROOT / "fixtures/email/malformed_headers.eml").read_bytes()
        for content in (forged, malformed):
            item = ReceiverHeaderVerifier("mx.receiver.example").verify(content, True, "e1")
            self.assertEqual(item.evidence_state, State.NO_DATA)
            self.assertTrue(item.error)
            self.assertIn("raw_headers_base64", item.raw_evidence)


class ExtractionTests(unittest.TestCase):
    def test_state_injection_rejected_at_top_and_per_claim(self):
        for data in [dict(claims=ANNOTATION["claims"], evidence_state=State.VERIFIED.value),
                     {"claims": [dict(ANNOTATION["claims"][0], evidence_state=State.VERIFIED.value)]}]:
            with self.assertRaises(InvalidInput):
                validate_claims(data, MESSAGE)

    def test_spans_and_duplicate_ids_validated(self):
        for mutate in (lambda c: c.update(start=1), lambda c: c.update(source_quote="invented")):
            claim = copy.deepcopy(ANNOTATION["claims"][0]);mutate(claim)
            with self.assertRaises(InvalidInput):
                validate_claims({"claims": [claim]}, MESSAGE)
        with self.assertRaises(InvalidInput):
            validate_claims({"claims": [ANNOTATION["claims"][0]] * 2}, MESSAGE)

    def test_hallucinated_domain_rejected(self):
        claim = dict(ANNOTATION["claims"][1], domain="nvidia.com")
        with self.assertRaises(InvalidInput):
            validate_claims({"claims": [claim]}, MESSAGE)

    def test_annotations_bound_to_exact_message(self):
        with self.assertRaises(InvalidInput):
            AnnotationExtractor(ANNOTATION).extract(MESSAGE + " extra")

    def test_no_key_is_visible_failure_without_fake_response(self):
        with patch.dict("os.environ", {}, clear=True), patch("investigation.llm.build_opener") as opener:
            with self.assertRaises(LLMFailure) as failure:
                OpenAIClient(api_key="").structured("test", "test", {}, "test")
            opener.assert_not_called()
        self.assertFalse(failure.exception.evidence["network_request_made"])

    def test_llm_cannot_set_truth_and_invalid_output_is_provider_error(self):
        class SyntheticClient:
            def structured(self, *args):
                return {"claims": [dict(ANNOTATION["claims"][0], evidence_state=State.VERIFIED.value)]}, {"origin": "SYNTHETIC TEST DOUBLE"}
        with self.assertRaises(LLMFailure):
            LLMExtractor(SyntheticClient()).extract(MESSAGE)

    def test_numerical_scam_probability_in_explanation_rejected(self):
        class SyntheticClient:
            def structured(self, *args):
                return {"paragraphs": [{"claim_id": "c1", "text": "99% probability of scam"}]}, {"origin": "SYNTHETIC TEST DOUBLE"}
        with self.assertRaises(LLMFailure):
            LLMExplainer(SyntheticClient()).explain([{"claim_id": "c1", "finding": "Unresolved"}])

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(InvalidInput):
            strict_json('{"message":"first","message":"second"}')


class APITests(unittest.TestCase):
    def setUp(self):
        self.server = make_server(engine(), port=0, allow_annotations=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/investigate"

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)

    def post(self, payload):
        data = json.dumps(payload).encode()
        request = Request(self.url, data=data, headers={"Content-Type": "application/json"})
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, strict_json(response.read().decode())

    def test_real_http_endpoint_vertical_slice(self):
        status, result = self.post({"message": MESSAGE, "claims_annotation": ANNOTATION})
        self.assertEqual(status, 200)
        self.assertEqual(len(result["claims"]), 4)
        self.assertEqual(result["contradiction_summary"]["count"], 1)
        self.assertTrue(result["evidence"][0]["raw_evidence"]["raw_body_base64"])

    def test_source_override_and_filesystem_paths_rejected(self):
        for field in ("source_url", "eml_path", "evidence_state"):
            status, result = self.post({"message": MESSAGE, field: "untrusted"})
            self.assertEqual(status, 400)
            self.assertEqual(result["status"], "invalid_input")

    def test_invalid_base64_rejected(self):
        status, _ = self.post({"message": MESSAGE, "eml_base64": "not@@base64"})
        self.assertEqual(status, 400)

    def test_annotations_require_explicit_server_option(self):
        with self.assertRaises(InvalidInput):
            investigate_request({"message": MESSAGE, "claims_annotation": ANNOTATION}, engine(), False)


if __name__ == "__main__":
    unittest.main()
