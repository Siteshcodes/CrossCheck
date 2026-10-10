"""Serve the built workbench and proxy the frozen investigation API on the same origin."""
import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from investigation.api import make_server, MAX_REQUEST_BYTES
from investigation.engine import InvestigationEngine
from investigation.verifiers import DomainVerifier, PolicyVerifier
from investigation.llm import LLMExtractor, OpenAIClient

ROOT=Path(__file__).resolve().parent
DIST=ROOT/"web/dist"


def make_live_engine():
    # The backend runs in this process: threads share the launching environment.
    # Use the exact extractor/client also used by investigation.benchmark.
    client=OpenAIClient()
    return InvestigationEngine(extractor=LLMExtractor(client),
        policy_verifier=PolicyVerifier("live"),domain_verifier=DomainVerifier("live"))


def make_product_server(api_server,port=8080,annotated_example=False,dist=DIST):
    fixture=json.loads((ROOT/"fixtures/clone_firm/request.json").read_text(encoding="utf-8"))
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self,*args,**kwargs): super().__init__(*args,directory=str(dist),**kwargs)
        def send_json(self,status,body):
            data=json.dumps(body,ensure_ascii=True).encode()
            self.send_response(status);self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
        def end_headers(self):
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Referrer-Policy","no-referrer")
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
            if self.path!="/investigate": return self.send_json(404,{"error":"Unknown endpoint"})
            lengths=self.headers.get_all("Content-Length",[])
            if self.headers.get("Transfer-Encoding") or len(lengths)!=1 or not lengths[0].isdigit():
                return self.send_json(400,{"status":"invalid_input","error":{"message":"Exactly one numeric Content-Length required"}})
            size=int(lengths[0])
            if not 0<size<=MAX_REQUEST_BYTES:
                return self.send_json(413,{"error":{"message":"Request body too large or empty"}})
            if self.headers.get_content_type()!="application/json":
                return self.send_json(415,{"error":{"message":"Content-Type must be application/json"}})
            self.connection.settimeout(15)
            body=self.rfile.read(size)
            if len(body)!=size: return self.send_json(400,{"error":{"message":"Incomplete request body"}})
            try:
                req=Request(f"http://127.0.0.1:{api_server.server_port}/investigate",data=body,headers={"Content-Type":"application/json"},method="POST")
                try: response=urlopen(req,timeout=120)
                except HTTPError as exc: response=exc
                with response:
                    status=response.status;data=response.read()
                self.send_response(status);self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
            except (BrokenPipeError,ConnectionResetError): pass
            except Exception as exc:
                self.send_json(502,{"status":"backend_unavailable","error":{"type":type(exc).__name__,"message":str(exc)}})
        def log_message(self,*args): pass
    return ThreadingHTTPServer(("127.0.0.1",port),Handler)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port",type=int,default=8080)
    parser.add_argument("--annotated-example",action="store_true",help="Explicit manual extraction for the exact example; evidence checks still run live. No silent fallback.")
    args=parser.parse_args()
    if not (DIST/"index.html").is_file(): parser.error("Build frontend first: npm --prefix web run build")
    engine=make_live_engine()
    print("OPENAI_API_KEY available: "+str(bool(engine.extractor.client.api_key)).lower(),flush=True)
    api=make_server(engine,port=0,allow_annotations=args.annotated_example)
    worker=threading.Thread(target=api.serve_forever,daemon=True);worker.start()
    app=make_product_server(api,args.port,args.annotated_example)
    print(f"CrossCheck workbench: http://127.0.0.1:{app.server_port}",flush=True)
    print("Extraction: "+("explicit analyst annotations for the example; custom text uses live LLM" if args.annotated_example else "live LLM"),flush=True)
    try: app.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        app.server_close();api.shutdown();api.server_close();worker.join(timeout=3)

if __name__=="__main__": main()
