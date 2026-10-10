"""One-command live clone-firm feasibility gate; extraction benchmark is separate."""
import json
import subprocess
import sys
import time
from investigation.benchmark import run_benchmark
from investigation.engine import InvestigationEngine
from investigation.llm import AnnotationExtractor, OpenAIClient
from investigation.verifiers import ROOT, DomainVerifier


def main():
    out=ROOT/"results";out.mkdir(exist_ok=True)
    report={"scenario":"IPO Horizon / Horizon Financial Planning Limited","tests":[],"investigations":[]}
    start=time.perf_counter()
    suite=subprocess.run([sys.executable,"-m","unittest","discover","-s","tests","-q"],cwd=ROOT,capture_output=True,text=True)
    report["tests"].append({"exit_code":suite.returncode,"latency_ms":round((time.perf_counter()-start)*1000,3),"output":suite.stdout+suite.stderr})
    message=(ROOT/"fixtures/clone_firm/message.txt").read_text(encoding="utf-8")
    for i in range(1,4):
        engine=InvestigationEngine(AnnotationExtractor.from_path(ROOT/"fixtures/clone_firm/claims.json"),domain_verifier=DomainVerifier("live"))
        result=engine.investigate(message,input_origin="synthetic_clone_firm_fixture")
        path=out/f"clone-investigation-{i}.json"
        path.write_text(json.dumps(result,indent=2),encoding="utf-8")
        row={"run":i,"latency_ms":result["latency_ms"],"summary":result["summary"],"result_file":str(path),
             "source_failures":[{"method":e["method"],"error":e["error"]} for e in result["evidence"] if e["error"]]}
        report["investigations"].append(row)
        print(json.dumps(row),flush=True)
    if OpenAIClient(model="gpt-6.1-sol").api_key:
        benchmark=run_benchmark()
        (out/"extraction-benchmark.json").write_text(json.dumps(benchmark,indent=2),encoding="utf-8")
        report["separate_live_extraction_benchmark"]=benchmark["summary"]
    else:
        report["separate_live_extraction_benchmark"]={"status":"BLOCKED","reason":"OPENAI_API_KEY is not configured locally; no requests or fabricated responses", "model":"gpt-6.1-sol", "case_count":12, "critical_claim_recall":None, "unsupported_hallucinated_claims":None,"invalid_routing":None,"latency_ms":None}
    report["deterministic_demo_gate"]="PASS" if suite.returncode==0 and all(r["summary"]["demo_gate"]["result"]=="PASS" for r in report["investigations"]) else "FAIL"
    report["boundary"]="Synthetic annotated communication; all investigation source evidence is live. Live LLM accuracy is a separate measurement and never changes deterministic evidence states."
    (out/"clone-feasibility-report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(json.dumps({"deterministic_demo_gate":report["deterministic_demo_gate"],"llm_benchmark":report["separate_live_extraction_benchmark"]}))
    return 0 if report["deterministic_demo_gate"]=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
