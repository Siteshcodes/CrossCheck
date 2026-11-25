"""Compose existing verification slices without extracting twice or losing claims."""
from collections import Counter
from copy import deepcopy

from .evaluation import summarize
from .models import Evidence, EvidenceState as State


def merge_investigations(first, second, candidates):
    result = deepcopy(first)
    other = deepcopy(second)
    remap = {e['id']: f"e{len(result['evidence'])+i}" for i,e in enumerate(other['evidence'], 1)}
    for e in other['evidence']:
        e['id'] = remap[e['id']]
        for key in ('parent_evidence_id', 'policy_evidence_id'):
            if key in e['source_provenance']:
                e['source_provenance'][key] = remap[e['source_provenance'][key]]
    for c in other['claims']:
        c['evidence_ids'] = [remap[i] for i in c['evidence_ids']]
    result['evidence'].extend(other['evidence'])
    order = {c.id: i for i,c in enumerate(candidates)}
    result['claims'] = sorted(result['claims']+other['claims'], key=lambda c: order[c['id']])
    result['scenario'] = 'mixed_authoritative_investigation'
    result['input']['eml_supplied'] = other['input']['eml_supplied']
    result['extraction']['omitted_candidates'] += other['extraction']['omitted_candidates']
    result['limitations'] = list(dict.fromkeys(result['limitations']+other['limitations']))
    records = [Evidence(**{**e, 'evidence_state': State(e['evidence_state'])}) for e in result['evidence']]
    result['summary'] = summarize(result['claims'], records, result['extraction'])
    result['summary']['demo_gate'] = {'result':'NOT_APPLICABLE', 'checks':{}, 'boundary':'A mixed input is not the curated flagship benchmark.'}
    contradictions = [c for c in result['claims'] if c['evidence_state'] == State.CONTRADICTED.value]
    groups = set(first['contradiction_summary']['independent_evidence_group_ids']) | set(second['contradiction_summary']['independent_evidence_group_ids'])
    result['contradiction_summary'] = {
        'count':len(contradictions), 'items':[{k:c[k] for k in ('finding','evidence_ids')} | {'claim_id':c['id']} for c in contradictions],
        'independent_evidence_group_ids':sorted(groups), 'boundary':'Shared source groups remain shared across routes.'}
    result['evidence_state_counts'] = dict(Counter(c['evidence_state'] for c in result['claims']))
    result['status'] = 'completed_with_gaps' if result['summary']['unresolved_claim_count'] else 'completed'
    result['explanation'] = '\n\n'.join(c['finding'] for c in result['claims'])
    result['evidence_correlation'] = {'contacting_party_authenticated':False,
        'finding':'Each claim retains its own scoped evidence. Matching company, domain or receiver records do not authenticate the contacting party.'}
    if other['explanation_provenance'].get('mode') == 'llm_supplement':
        result['limitations'].append('Supplementary narration is omitted for mixed investigations; deterministic findings remain canonical.')
    return result
