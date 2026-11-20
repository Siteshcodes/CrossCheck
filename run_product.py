"""Serve the built workbench and proxy the frozen investigation API on the same origin."""
import argparse
from http.server import SimpleHTTPRequestHandler
import json
import logging
import os
from pathlib import Path
import threading
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from investigation.api import make_server
from investigation.engine import InvestigationEngine
from investigation.verifiers import DomainVerifier, PolicyVerifier
from investigation.llm import LLMExtractor, OpenAIClient
from investigation.http_support import BoundedHTTPServer, HTTPProblem, read_body, send_json, error_payload

ROOT=Path(__file__).resolve().parent
DIST=ROOT/"web/dist"


def make_live_engine():
    # The backend runs in this process: threads share the launching environment.
    # Use the exact extractor/client also used by investigation.benchmark.
    client=OpenAIClient()
    return InvestigationEngine(extractor=LLMExtractor(client),
        policy_verifier=PolicyVerifier("live"),domain_verifier=DomainVerifier("live"))


def make_product_server(api_server,port=8080,annotated_example=False,dist=DIST,host="127.0.0.1"):
    fixture=json.loads((ROOT/"fixtures/clone_firm/request.json").read_text(encoding="utf-8"))
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self,*args,**kwargs): super().__init__(*args,directory=str(dist),**kwargs)
        def send_json(self,status,body):
            send_json(self,status,body)
        def end_headers(self):
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            super().end_headers()
        def do_GET(self):
            path=urlsplit(self.path).path
            if path=="/fixture":
                return self.send_json(200,{"message":fixture["message"],"origin":"synthetic_clone_firm_fixture",
                    "annotation_mode":annotated_example,
                    **({"claims_annotation":fixture["claims_annotation"]} if annotated_example else {})})
            if path=="/health": return self.send_json(200,{"status":"ready"})
            if path not in {"/","/index.html","/favicon.svg"} and not path.startswith("/assets/"):
                return self.send_error(404,"Not found")
            return super().do_GET()
        def do_POST(self):
            if self.path!="/investigate": return self.send_json(404,error_payload('not_found','UnknownEndpoint','Use POST /investigate'))
            try:
                body=read_body(self)
            except HTTPProblem as exc:
                return self.send_json(exc.code,error_payload('invalid_input','InvalidRequest',str(exc)))
            except TimeoutError:
                return self.send_json(408,error_payload('request_timeout','RequestTimeout','Request body timed out'))
            except (BrokenPipeError,ConnectionResetError):
                return
            try:
                req=Request(f"http://127.0.0.1:{api_server.server_port}/investigate",data=body,headers={"Content-Type":"application/json"},method="POST")
                try: response=urlopen(req,timeout=120)
                except HTTPError as exc: response=exc
                with response:
                    status=response.status;data=response.read()
                self.send_response(status);self.send_header("Content-Type","application/json")
                for name in ('X-Request-ID','Retry-After'):
                    if response.headers.get(name): self.send_header(name,response.headers[name])
                self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
            except (BrokenPipeError,ConnectionResetError): pass
            except Exception:
                self.send_json(502,error_payload('backend_unavailable','BackendUnavailable','The investigation backend is unavailable or timed out. Retry later.'))
        def log_message(self,*args): pass
    return BoundedHTTPServer((host,port),Handler)


def parse_args(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port",type=int,default=os.environ.get("PORT",8080))
    parser.add_argument("--host",default=os.environ.get("HOST","127.0.0.1"))
    parser.add_argument("--annotated-example",action="store_true",help="Explicit manual extraction for the exact example; evidence checks still run live. No silent fallback.")
    args=parser.parse_args(argv)
    if not 0<=args.port<=65535: parser.error("Port must be between 0 and 65535")
    return args


def main():
    args=parse_args()
    logging.basicConfig(level=logging.INFO,format='%(levelname)s %(name)s %(message)s')
    if not (DIST/"index.html").is_file(): raise SystemExit("Build frontend first: npm --prefix web run build")
    engine=make_live_engine()
    print("OPENAI_API_KEY available: "+str(bool(engine.extractor.client.api_key)).lower(),flush=True)
    api=make_server(engine,port=0,allow_annotations=args.annotated_example)
    worker=threading.Thread(target=api.serve_forever,daemon=True);worker.start()
    app=make_product_server(api,args.port,args.annotated_example,host=args.host)
    print(f"CrossCheck workbench: http://{args.host}:{app.server_port}",flush=True)
    print("Extraction: "+("explicit analyst annotations for the example; custom text uses live LLM" if args.annotated_example else "live LLM"),flush=True)
    try: app.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        app.server_close();api.shutdown();api.server_close();worker.join(timeout=3)

if __name__=="__main__": main()
