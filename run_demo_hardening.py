"""One command reruns the suite, live sources, live extraction and honest gate."""
import json
import subprocess
import sys
import time
from investigation.benchmark import run_benchmark
from investigation.engine import InvestigationEngine
from investigation.llm import AnnotationExtractor, LLMExtractor, OpenAIClient, LLMFailure
from investigation.verifiers import ROOT, PolicyVerifier, DomainVerifier


def main():
    output=ROOT/"results"
    output.mkdir(exist_ok=True)
    message=(ROOT/"fixtures/nvidia_recruiter/message.txt").read_text(encoding="utf-8")
    report={"tests":[],"flagship":[],"live_llm_flagship":[],"benchmark":run_benchmark()}
    for i in range(1,4):
        started=time.perf_counter()
        test=subprocess.run([sys.executable,"-m","unittest","discover","-s","tests","-q"],cwd=ROOT,capture_output=True,text=True)
        report["tests"].append({"run":i,"exit_code":test.returncode,"latency_ms":round((time.perf_counter()-started)*1000,3),"output":test.stdout+test.stderr})
        for live in (False,True):
            extractor=LLMExtractor(OpenAIClient(model="gpt-6.1-sol")) if live else AnnotationExtractor.from_path(ROOT/"fixtures/nvidia_recruiter/claims.json")
            try:
                result=InvestigationEngine(extractor,PolicyVerifier("live"),DomainVerifier("live")).investigate(message,input_origin="synthetic_nvidia_recruiter_fixture")
                path=output/f"hardened-{'llm-' if live else ''}flagship-{i}.json"
                path.write_text(json.dumps(result,indent=2),encoding="utf-8")
                row={"run":i,"latency_ms":result["latency_ms"],"summary":result["summary"],"result_file":str(path),"failures":[{"method":e["method"],"error":e["error"]} for e in result["evidence"] if e["error"]]}
            except LLMFailure as exc:
                row={"run":i,"status":"FAIL","error":str(exc),"provider":exc.evidence}
            report["live_llm_flagship" if live else "flagship"].append(row)
            print(json.dumps(row),flush=True)
    report["result"]="PASS" if all(r["exit_code"]==0 for r in report["tests"]) and report["benchmark"]["summary"]["result"]=="PASS" and all(r.get("summary",{}).get("demo_gate",{}).get("result")=="PASS" for r in report["live_llm_flagship"]) else "FAIL"
    (output/"hardening-rerun.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    return 0 if report["result"]=="PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
