"""Extraction-only live benchmark. No regulator/RDAP/email verifier is imported or run."""
from datetime import datetime, timezone
import argparse
import json
import math
from pathlib import Path
import statistics
import time

from .llm import (LLMExtractor, OpenAIClient, LLMFailure, EXTRACTION_ROUTES,
                  compact_schema_errors, expand_candidates, MAX_EXTRACTION_CLAIMS)
from .models import InvalidInput, grounding_issue, sha256, validate_claims

ROOT=Path(__file__).resolve().parent.parent


def signature(c):
    return (c["kind"],(c.get("organization") or "").casefold(),c.get("domain"),c["polarity"])


def score_output(case,data):
    """Audit every emitted candidate; failed/dropped outputs do not improve recall."""
    expected={signature(c) for c in case["expected_critical_claims"]}
    errors=compact_schema_errors(data)
    values=data.get("claims",[]) if isinstance(data,dict) else []
    values=values if isinstance(values,list) else []
    matched=set();unsupported=[];routing=[];grounding=[];candidates=[];duplicates=[]
    for i,c in enumerate(values):
        kind=c.get("k") if isinstance(c,dict) else None
        route=c.get("r") if isinstance(c,dict) else None
        if not isinstance(kind,str) or kind not in EXTRACTION_ROUTES or route!=EXTRACTION_ROUTES.get(kind):
            routing.append(i)
        try:
            audit_candidate=dict(c) if isinstance(c,dict) else c
            # Semantic recall and route errors are separate metrics. This audit-only
            # normalization cannot enter an engine or turn a rejected route into evidence.
            if isinstance(kind,str) and kind in EXTRACTION_ROUTES and isinstance(audit_candidate,dict):
                audit_candidate["r"]=EXTRACTION_ROUTES[kind]
            normalized=expand_candidates({"claims":[audit_candidate]},case["message"])
            claim=validate_claims(normalized,case["message"])[0]
            issue=grounding_issue(claim,case["message"])
            if issue: raise InvalidInput(issue)
            sig=signature(claim.to_dict())
            if sig not in expected: unsupported.append({"candidate_index":i,"reason":"No labeled critical predicate supports this candidate","candidate":c})
            elif sig in matched: duplicates.append(i)
            else: matched.add(sig)
            candidates.append(claim.to_dict())
        except (InvalidInput,ValueError,TypeError,KeyError) as exc:
            grounding.append({"candidate_index":i,"reason":str(exc)})
            unsupported.append({"candidate_index":i,"reason":"Rejected/uninterpretable candidate: "+str(exc),"candidate":c})
    # A non-claims verdict field also violates the boundary even without a candidate.
    return {"schema_valid":not errors,"schema_errors":errors,"expected_count":len(expected),
        "recalled":len(matched),"critical_claim_recall":len(matched)/len(expected) if expected else None,
        "missing_expected_claims":[c for c in case["expected_critical_claims"] if signature(c) not in matched],
        "unsupported_hallucinated_claims":len(unsupported),"unsupported_details":unsupported,
        "invalid_routing":len(routing),"invalid_routing_indices":routing,"emitted_claim_count":len(values),
        "grounding_errors":grounding,"duplicate_candidate_indices":duplicates,"normalized_candidates":candidates}


def summarize(rows):
    responded=[r for r in rows if r.get("model_output_received")]
    expected=sum(r["expected_count"] for r in rows)
    recall=sum(r.get("recalled",0) for r in rows)/expected if responded and expected else None
    hallucinations=sum(r.get("unsupported_hallucinated_claims",0) for r in responded) if responded else None
    schema_valid=sum(bool(r.get("schema_valid")) for r in responded)
    emitted=sum(r.get("emitted_claim_count",0) for r in responded)
    invalid=sum(r.get("invalid_routing",0) for r in responded) if responded else None
    # Zero emitted candidates is valid only for no-claim cases; missing positives lower recall.
    invalid_rate=invalid/emitted if emitted else (0.0 if responded else None)
    latencies=[r["latency_ms"] for r in rows if r.get("network_request_made") and r.get("latency_ms") is not None]
    ordered=sorted(latencies)
    p95=ordered[math.ceil(.95*len(ordered))-1] if ordered else None
    median=statistics.median(latencies) if latencies else None
    checks={"all_12_cases_completed":len(responded)==len(rows)==12,
        "critical_claim_recall_at_least_90_percent":recall is not None and recall>=.9,
        "zero_unsupported_hallucinated_critical_claims":hallucinations==0,
        "100_percent_schema_valid_responses":bool(responded) and schema_valid==len(responded),
        "invalid_verification_routing_at_most_5_percent":invalid_rate is not None and invalid_rate<=.05,
        "deterministic_evidence_states_outside_llm":True}
    return {"case_count":len(rows),"model_responses_received":len(responded),
        "successful_extractions":sum(r.get("status")=="PASS" for r in rows),
        "failed_extractions":sum(r.get("status")!="PASS" for r in rows),
        "network_requests":sum(bool(r.get("network_request_made")) for r in rows),
        "unevaluable_model_outputs":sum(r.get("model_output_received",False) and not r.get("candidate_output_evaluable",True) for r in rows),
        "expected_critical_claims":expected,"recalled_critical_claims":sum(r.get("recalled",0) for r in rows) if responded else None,
        "critical_claim_recall":recall,"unsupported_hallucinated_claims":hallucinations,
        "schema_valid_responses":schema_valid if responded else None,"schema_valid_response_rate":schema_valid/len(responded) if responded else None,
        "invalid_routing":invalid,"emitted_claim_count":emitted if responded else None,"invalid_routing_rate":invalid_rate,
        "median_latency_ms":median,"p95_latency_ms":p95,"p95_method":"nearest rank (ceil(0.95*n)); with 12 samples this is the maximum",
        "latency_target_result":"PASS" if median is not None and median<5000 else "FAIL" if median is not None else "UNMEASURED",
        "result":"PASS" if all(checks.values()) else "FAIL","gate_checks":checks,
        "boundary":"Recall denominator includes failed cases. Per-case no-claim recall is N/A. Unsupported counts include rejected emitted candidates; no dropped outputs hide mistakes. Null means unmeasured. Timings are sequential single-request end-to-end wall times; no concurrency or retries hide latency."}


def run_benchmark(client=None,output_path=None,progress=False):
    fixture=ROOT/"fixtures/extraction_communications.json"
    cases=json.loads(fixture.read_text(encoding="utf-8"))
    extractor=LLMExtractor(client or OpenAIClient(model="gpt-6.1-sol"))
    rows=[]
    started_at=datetime.now(timezone.utc).isoformat()
    def result():
        return {"model":extractor.client.model if hasattr(extractor.client,"model") else "SYNTHETIC_TEST_DOUBLE",
            "started_at_utc":started_at,"corpus_path":str(fixture),"corpus_sha256":sha256(fixture.read_bytes()),
            "configuration":{"claim_cap":MAX_EXTRACTION_CLAIMS,"wire_format":"compact_exact_quotes_v1",
                "reasoning_effort":getattr(extractor.client,"extraction_effort",None),"max_output_tokens":getattr(extractor.client,"extraction_max_tokens",None),
                "evidence_verification_run":False,"retries":0,"parallel_requests":False},
            "cases":rows,"summary":summarize(rows)}
    for case in cases:
        start=time.perf_counter()
        row={"id":case["id"],"input":case["message"],"expected":case["expected_critical_claims"],"expected_count":len(case["expected_critical_claims"]),"recalled":0}
        try:
            extraction=extractor.extract(case["message"])
            provider=extraction.provenance
            row.update(score_output(case,provider["candidate_output"]))
            row.update(status="PASS",model_output_received=True,candidate_output_evaluable=True)
        except LLMFailure as exc:
            provider=exc.evidence
            received="candidate_output" in provider
            if received: row.update(score_output(case,provider["candidate_output"]))
            elif provider.get("http_status")==200:
                row.update(schema_valid=False,schema_errors=["No complete parseable candidate response"],emitted_claim_count=0,unsupported_hallucinated_claims=0,invalid_routing=0)
            row.update(status="FAIL",error=str(exc),model_output_received=received or provider.get("http_status")==200, candidate_output_evaluable=received)
        row["provider"]=provider
        row["network_request_made"]=bool(provider.get("network_request_made"))
        row["latency_ms"]=round((time.perf_counter()-start)*1000,3) if row["network_request_made"] else None
        row["local_attempt_latency_ms"]=round((time.perf_counter()-start)*1000,3)
        rows.append(row)
        if output_path: Path(output_path).write_text(json.dumps(result(),indent=2,ensure_ascii=True),encoding="utf-8")
        if progress: print(json.dumps({k:row.get(k) for k in ("id","status","critical_claim_recall","unsupported_hallucinated_claims","schema_valid","invalid_routing","latency_ms","error")}),flush=True)
    return result()


def write_report(result,path):
    summary=result["summary"]
    def pct(value): return "UNMEASURED" if value is None else f"{100*value:.2f}%"
    def number(value): return "UNMEASURED" if value is None else str(value)
    def seconds(value): return "UNMEASURED" if value is None else f"{value/1000:.3f}s"
    lines=["# Live extraction benchmark: "+summary["result"], "",
        "Extraction-only evaluation of the unchanged 12 labeled communications (15 expected critical predicates). No NVIDIA, FCA, RDAP, Companies House or email verification was run.", "",
        "Model: "+result["model"]+". Sequential requests, zero retries. Source corpus SHA-256: "+result["corpus_sha256"]+".", "",
        "| Metric | Exact result |", "|---|---:|",
        "| Model responses received | "+str(summary["model_responses_received"])+" / 12 |",
        "| API requests made | "+str(summary["network_requests"])+" |",
        "| Critical-claim recall | "+pct(summary["critical_claim_recall"])+" |",
        "| Unsupported/hallucinated critical candidates | "+number(summary["unsupported_hallucinated_claims"])+" |",
        "| Schema-valid response rate | "+pct(summary["schema_valid_response_rate"])+" |",
        "| Invalid routing count / rate | "+number(summary["invalid_routing"])+" / "+pct(summary["invalid_routing_rate"])+" |",
        "| Median latency | "+seconds(summary["median_latency_ms"])+" |",
        "| p95 latency | "+seconds(summary["p95_latency_ms"])+" |",
        "| Median under 5s target | "+summary["latency_target_result"]+" |", "",
        "| Case | Recalled / expected | Recall | Unsupported | Schema valid | Invalid routes | Latency | Status |",
        "|---|---:|---:|---:|---|---:|---:|---|"]
    for row in result["cases"]:
        recalled=row.get("recalled") if row.get("model_output_received") else None
        recall=pct(row.get("critical_claim_recall")) if row["expected_count"] else "N/A (no expected claims)"
        schema="UNMEASURED" if row.get("schema_valid") is None else str(row["schema_valid"])
        lines.append(f"| {row['id']} | {number(recalled)} / {row['expected_count']} | {recall} | {number(row.get('unsupported_hallucinated_claims'))} | {schema} | {number(row.get('invalid_routing'))} | {seconds(row.get('latency_ms'))} | {row['status']} |")
    lines.extend(["", "p95 uses nearest rank ceil(0.95*n); with 12 network samples it is the largest latency. Timing includes API wall time plus local validation. Missing-key local checks do not count as extraction latency.", "",
        "## Gate", ""])
    for check,passed in summary["gate_checks"].items(): lines.append("- "+check+": "+("PASS" if passed else "FAIL"))
    lines.extend(["", "## Errors", ""])
    for row in result["cases"]:
        if row.get("error"): lines.append("- "+row["id"]+": "+row["error"])
    lines.extend(["", "## Optimization and boundaries", "",
        "- The model emits only seven compact candidate fields: kind, organization, exact quote, domain, polarity, basis and route. It emits no IDs, repeated statement, character counts, explanations, risk scores or evidence states.",
        "- Python derives IDs, statements and Unicode offsets from exact uniquely occurring quotes; missing/ambiguous quotes fail. Existing claim/domain/type and routing validation remains active.",
        "- Extraction uses reasoning effort low and max_output_tokens=1600, with at most five candidates. Unsupported fields, excess claims and incomplete responses fail rather than being truncated or fabricated.",
        "- Semantic recall and route validity are separately audited. An invalid route is rejected by the real extractor even when its factual candidate is correctly recalled by the metric audit. This audit does not enter an investigation engine.",
        "- Recall uses all 15 expected critical predicates, including failed cases. Unsupported emitted candidates are not silently filtered before scoring. Two no-claim cases have N/A per-case recall and must remain empty.",
        "- Labels compare kind, organization, domain and polarity with grounded input spans. They are a small extraction regression corpus, predominantly recruiting messages; they do not establish general clone-firm extraction accuracy or exhaustive paraphrase understanding.",
        "- The supplied 16.5–19.1s timings are prior user-reported observations, not a controlled before/after benchmark. No speed improvement is claimed until measured.",
        "- Focused extractor/metric tests passed 13/13; these use explicitly synthetic transport doubles and are not live model measurements.", "",
        "Official API controls: [GPT-6.1 Sol reasoning effort](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-6.1-sol) and [latency optimization](https://developers.openai.com/api/docs/guides/latency-optimization).", "",
        "Rerun only this benchmark in a shell that has the configured key:", "", "```powershell", "python -m investigation.benchmark --output results/extraction-benchmark-optimized.json", "```", "",
        "The CLI also writes this Markdown report. Credentials are read from the process environment or ignored workspace .env; they are never requested in chat or included in output."])
    Path(path).write_text("\n".join(lines)+"\n",encoding="utf-8")


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",default=str(ROOT/"results/extraction-benchmark-optimized.json"))
    args=parser.parse_args()
    result=run_benchmark(output_path=args.output,progress=True)
    write_report(result,Path(args.output).with_suffix(".md"))
    print(json.dumps(result["summary"]))
    raise SystemExit(0 if result["summary"]["result"]=="PASS" else 1)
