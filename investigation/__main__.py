"""python -m investigation demo | investigate | serve"""

import argparse
import json
from pathlib import Path
import sys

from .api import make_server
from .engine import InvestigationEngine
from .llm import AnnotationExtractor, LLMExplainer, LLMFailure, LLMExtractor
from .models import InvalidInput
from .verifiers import DomainVerifier, PolicyVerifier, ReceiverHeaderVerifier, ROOT


def build_engine(args, extractor=None):
    return InvestigationEngine(extractor=extractor,
        policy_verifier=PolicyVerifier(args.source_mode), domain_verifier=DomainVerifier(args.rdap_mode),
        header_verifier=ReceiverHeaderVerifier(args.trusted_authserv_id), explainer=LLMExplainer() if args.llm_explanation else None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("demo", "clone-demo", "investigate", "serve"):
        command = sub.add_parser(name)
        command.add_argument("--source-mode", choices=("snapshot", "live"), default="snapshot" if name == "demo" else "live")
        command.add_argument("--rdap-mode", choices=("unavailable", "live"), default="unavailable" if name == "demo" else "live")
        command.add_argument("--trusted-authserv-id", help="Independently configured receiver ID; matching it is not sufficient to prove export provenance")
        command.add_argument("--llm-explanation", action="store_true", help="Add non-authoritative LLM narration of frozen findings; canonical explanation remains deterministic")
        if name != "serve":
            command.add_argument("--output", type=Path, help="Save the complete API-shaped JSON response; defaults to stdout")
            command.add_argument("--eml", type=Path, help="Original .eml file; original export provenance must be asserted separately")
            command.add_argument("--assert-original-receiver-export", action="store_true")
        if name in {"demo", "clone-demo"}:
            command.add_argument("--extractor", choices=("annotation", "llm"), default="annotation")
        if name == "investigate":
            command.add_argument("--message-file", type=Path, required=True)
            command.add_argument("--claims-file", type=Path, help="Explicit analyst annotation JSON for offline/manual extraction; otherwise uses live LLM")
        if name == "serve":
            command.add_argument("--port", type=int, default=8000)
            command.add_argument("--allow-annotations", action="store_true", help="Explicit local demo/test mode accepting analyst annotations; default uses LLM extraction")
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            if not 0 <= args.port <= 65535:
                raise InvalidInput("port must be between 0 and 65535")
            server = make_server(build_engine(args), port=args.port, allow_annotations=args.allow_annotations)
            print(f"POST http://127.0.0.1:{server.server_port}/investigate", file=sys.stderr)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        if args.command in {"demo", "clone-demo"}:
            fixture = "clone_firm" if args.command == "clone-demo" else "nvidia_recruiter"
            message = (ROOT / f"fixtures/{fixture}/message.txt").read_text(encoding="utf-8")
            extractor = LLMExtractor() if args.extractor == "llm" else AnnotationExtractor.from_path(ROOT / f"fixtures/{fixture}/claims.json")
        else:
            message = args.message_file.read_text(encoding="utf-8")
            extractor = AnnotationExtractor.from_path(args.claims_file) if args.claims_file else None
        eml = args.eml.read_bytes() if args.eml else None
        result = build_engine(args, extractor).investigate(message, eml, args.assert_original_receiver_export,
                     input_origin="synthetic_clone_firm_fixture" if args.command == "clone-demo" else "synthetic_nvidia_recruiter_fixture" if args.command == "demo" else "user_supplied")
        rendered = json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
            print(json.dumps({"output": str(args.output.resolve()), "status": result["status"], "claims": len(result["claims"]), "contradicted_claims": result["contradiction_summary"]["count"], "evidence_state_counts": result["evidence_state_counts"], "summary": result["summary"]}))
        else:
            print(rendered, end="")
        return 0
    except (LLMFailure, InvalidInput, OSError, ValueError) as exc:
        print(json.dumps({"status": "extraction_failed" if isinstance(exc, LLMFailure) else "invalid_input",
                          "claims": [], "error": {"type": type(exc).__name__, "message": str(exc), "provider_evidence": getattr(exc, "evidence", {})}}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
