import json
from pathlib import Path
import unittest

from check_product_live import release_issues
from investigation.models import EvidenceState as State


class ReleaseGateTests(unittest.TestCase):
    def result(self):
        # Historical public capture, explicitly replayed. This test never calls a model.
        r=json.loads(Path('results/clone-investigation-3.json').read_text(encoding='utf-8'))
        r['extraction']['used_llm']=True
        return r

    def test_good_captured_evidence_contract(self):
        self.assertEqual(release_issues(self.result(),flagship=True),[])

    def test_all_unknown_cannot_pass_flagship_release(self):
        r=self.result()
        for c in r['claims']: c['evidence_state']=State.NO_DATA.value
        self.assertTrue(release_issues(r,flagship=True))

    def test_annotations_cannot_pass_live_release(self):
        r=self.result();r['extraction']['used_llm']=False
        self.assertIn('Live extraction did not run',release_issues(r,flagship=True))

    def test_dangling_source_and_ungrounded_quote_fail_release(self):
        r=self.result();r['claims'][0]['evidence_ids']=['missing'];r['claims'][0]['source_quote']='Invented'
        issues=release_issues(r,flagship=True)
        self.assertIn('Dangling evidence reference',issues)
        self.assertIn('Claim quotation is not grounded',issues)

    def test_repeated_fca_findings_do_not_become_independent(self):
        r=self.result();next(e for e in r['evidence'] if e['method']=='regulator_contact_comparison')['evidence_group_id']='invented-independent-group'
        self.assertIn('FCA findings must share one source group',release_issues(r,flagship=True))


if __name__=='__main__': unittest.main()
