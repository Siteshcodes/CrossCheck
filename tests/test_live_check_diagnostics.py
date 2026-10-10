"""Diagnostic privacy tests; no live model or verifier calls."""
import unittest
from check_product_live import claim_diagnostics, safe_text


class DiagnosticTests(unittest.TestCase):
    def test_credentials_email_and_contact_numbers_are_redacted(self):
        private='SYNTHETIC_PRIVATE_KEY'
        result=safe_text('person@example.com '+private+' Authorization: Bearer abc password=abc sk-test-value +447721904036',(private,))
        for secret in ['person@example.com',private,'abc','sk-test-value','447721904036']:
            self.assertNotIn(secret,result)

    def test_only_safe_claim_diagnostics_and_provenance_are_recorded(self):
        result={'provider_payload':{'Authorization':'SECRET'},'claims':[{
            'statement':'Claim by person@example.com','source_quote':'person@example.com',
            'organization':'  Sample   Firm ', 'verification_route':'regulator_clone_warning',
            'evidence_state':'NO_AUTHORITATIVE_DATA','evidence_ids':['e1'], 'finding':'Unavailable'}],
            'evidence':[{'id':'e1','source_provenance':{'url':'https://www.fca.org.uk/warning?token=secret'},
                         'raw_evidence':'SECRET','evidence_group_id':'eg_test'}]}
        rows=claim_diagnostics(result)
        self.assertEqual(rows[0]['normalized_organization'],'sample firm')
        self.assertEqual(rows[0]['evidence_sources'][0]['title'],'Financial Conduct Authority')
        self.assertIsNone(rows[0]['evidence_sources'][0]['url'])
        self.assertEqual(rows[0]['evidence_sources'][0]['evidence_group'],'eg_test')
        self.assertNotIn('SECRET',str(rows))
        self.assertNotIn('person@example.com',str(rows))
