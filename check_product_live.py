"""Actual-provider end-to-end release check. No annotations or model response mocks."""
import json
import re
from pathlib import Path
import threading
import time
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from investigation.api import make_server
from run_product import make_live_engine, make_product_server


def safe_text(value, secrets=()):
    text=str(value) if value is not None else None
    if text is None: return None
    for secret in secrets:
        if secret: text=text.replace(secret,'[REDACTED]')
    text=re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[REDACTED EMAIL]', text)
    text=re.sub(r'(?i)\b(?:Bearer\s+\S+|sk-[\w-]+)', '[REDACTED CREDENTIAL]',text)
    text=re.sub(r'(?i)\b(?:password|api[_ -]?key|authorization|token|secret)\s*[:=]\s*\S+', '[REDACTED CREDENTIAL]',text)
    text=re.sub(r'(?<!\w)\+?\d[\d ()-]{8,}\d(?!\w)', '[REDACTED NUMBER]',text)
    return text


def claim_diagnostics(result,secrets=()):
    # Deliberately omit provider payloads, headers, raw source pages and input metadata.
    from urllib.parse import urlsplit
    records={e['id']:e for e in result.get('evidence',[])}
    output=[]
    for c in result.get('claims',[]):
        sources=[]
        for ident in c.get('evidence_ids',[]):
            e=records.get(ident,{})
            url=e.get('source_provenance',{}).get('url') or e.get('source_provenance',{}).get('queried_rdap_url')
            parsed=urlsplit(url or '')
            safe_url=url if parsed.scheme=='https' and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment else None
            title={'www.fca.org.uk':'Financial Conduct Authority','find-and-update.company-information.service.gov.uk':'Companies House'}.get(parsed.hostname,'Authoritative RDAP' if e.get('method')=='rdap_domain_provenance' else 'Source unavailable')
            sources.append({'title':title,'url':safe_text(safe_url,secrets),'evidence_group':e.get('evidence_group_id')})
        output.append({'extracted_claim':safe_text(c.get('statement'),secrets),
            'supporting_quote':safe_text(c.get('source_quote'),secrets),
            'normalized_organization':safe_text(' '.join(c['organization'].split()).casefold() if c.get('organization') else None,secrets),
            'route':c.get('verification_route'),'evidence_state':c.get('evidence_state'),
            'evidence_sources':sources,'assignment_reason':safe_text(c.get('finding'),secrets)})
    return output


def release_issues(result, flagship=False):
    """Validate the returned evidence, not just HTTP 200 and a nonempty claim list."""
    from collections import Counter
    from investigation.models import EvidenceState as State
    issues=[]
    claims=result.get('claims',[])
    evidence=result.get('evidence',[])
    records={e['id']:e for e in evidence}
    if len(records)!=len(evidence): issues.append('Duplicate evidence IDs')
    if not claims or len({c['id'] for c in claims})!=len(claims): issues.append('Missing or duplicate claims')
    if result.get('extraction',{}).get('used_llm') is not True: issues.append('Live extraction did not run')
    message=result.get('input',{}).get('message','')
    for c in claims:
        if c.get('evidence_state') not in {s.value for s in State} or not c.get('verification_method'):
            issues.append('Invalid verification contract')
        if not c.get('source_quote') or message[c.get('start',0):c.get('end',0)]!=c['source_quote']:
            issues.append('Claim quotation is not grounded')
        ids=c.get('evidence_ids',[])
        if any(i not in records for i in ids): issues.append('Dangling evidence reference')
        if c.get('evidence_state') in {State.VERIFIED.value,State.CONTRADICTED.value}:
            if not any(i in records and records[i].get('evidence_group_id') and not records[i].get('error')
                       and records[i].get('evidence_state')!=State.NO_DATA.value for i in ids):
                issues.append('Decisive claim lacks successful source evidence')
    if flagship:
        counts=Counter(c.get('evidence_state') for c in claims)
        if counts!={State.VERIFIED.value:2,State.CONTRADICTED.value:2}:
            issues.append('Flagship must return two verified and two contradicted claims without gaps')
        fca_groups={e.get('evidence_group_id') for e in evidence if e.get('method','').startswith('regulator_')}
        if len(fca_groups)!=1 or None in fca_groups: issues.append('FCA findings must share one source group')
        if result.get('summary',{}).get('independent_evidence_count',0)<2: issues.append('Fewer than two useful source groups')
    return list(dict.fromkeys(issues))


def main():
    engine=make_live_engine()
    print('OPENAI_API_KEY available: '+str(bool(engine.extractor.client.api_key)).lower())
    if not engine.extractor.client.api_key:
        print('SKIPPED: live-provider testing requires an available API key.')
        Path('results/product-live-extraction-check.json').write_text(json.dumps({
            'status':'SKIPPED','checked_at_utc':datetime.now(timezone.utc).isoformat(),
            'live_model_ran':False,'network_request_made':False,
            'reason':'OPENAI_API_KEY is unavailable in the launching environment and repository .env.'},indent=2)+'\n',encoding='utf-8')
        return 1
    api=make_server(engine,port=0,allow_annotations=False)
    product=make_product_server(api,port=0,annotated_example=False)
    workers=[threading.Thread(target=s.serve_forever,daemon=True) for s in (api,product)]
    for worker in workers: worker.start()
    cases={
        'flagship':Path('fixtures/clone_firm/message.txt').read_text(encoding='utf-8'),
        'manual':'Horizon Financial Planning Limited is an active UK company. I represent IPO Horizon and our official website is ipohorizon.com.',
    }
    report={}
    try:
        for name,message in cases.items():
            started=time.perf_counter()
            request=Request(f'http://127.0.0.1:{product.server_port}/investigate',
                data=json.dumps({'message':message}).encode(),headers={'Content-Type':'application/json'})
            try:
                try: response=urlopen(request,timeout=130)
                except HTTPError as exc: response=exc
                with response: status=response.status;result=json.load(response)
                claims=result.get('claims',[])
                live=result.get('extraction',{}).get('used_llm') is True
                issues=release_issues(result,flagship=name=='flagship') if status==200 else ['Non-success HTTP status']
                passed=status==200 and not issues
                report[name]={'result':'PASS' if passed else 'FAIL','http_status':status,
                    'live_model_ran':live,'claim_count':len(claims),
                    'verification_methods':[c.get('verification_method') for c in claims],
                    'evidence_states':[c.get('evidence_state') for c in claims],
                    'claims':claim_diagnostics(result,(engine.extractor.client.api_key,)),
                    'validation_issues':issues,
                    'failure_reason':None if passed else safe_text(result.get('error',{}).get('message','Live extraction or verification contract missing'),(engine.extractor.client.api_key,))}
            except Exception as exc:
                report[name]={'result':'FAIL','failure_reason':type(exc).__name__}
            report[name]['latency_seconds']=round(time.perf_counter()-started,3)
        Path('results/product-live-extraction-check.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2))
    finally:
        for server in (product,api): server.shutdown();server.server_close()
        for worker in workers: worker.join(timeout=3)
    return 0 if all(r['result']=='PASS' for r in report.values()) else 1


if __name__=='__main__': raise SystemExit(main())
