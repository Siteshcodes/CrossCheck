"""Real local HTTP tests for the frontend adapter; no new verification semantics."""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import threading
import unittest
import os
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from investigation.api import make_server
from investigation.engine import InvestigationEngine
from run_product import make_product_server, make_live_engine
from investigation.llm import LLMExtractor, OpenAIClient
from investigation.verifiers import DomainVerifier


@contextmanager
def server_pair(annotation=False,engine=None):
    api=make_server(engine or InvestigationEngine(),port=0)
    a=threading.Thread(target=api.serve_forever,daemon=True);a.start()
    with tempfile.TemporaryDirectory() as directory:
        Path(directory,"index.html").write_text("<!doctype html><title>UNIT TEST static shell</title>",encoding="utf-8")
        product=make_product_server(api,port=0,annotated_example=annotation,dist=Path(directory))
        b=threading.Thread(target=product.serve_forever,daemon=True);b.start()
        try: yield f"http://127.0.0.1:{product.server_port}"
        finally: product.shutdown();product.server_close();b.join(timeout=2)
    api.shutdown();api.server_close();a.join(timeout=2)


def http(url,payload=None):
    req=Request(url,data=json.dumps(payload).encode() if payload is not None else None,headers={"Content-Type":"application/json"})
    try: response=urlopen(req,timeout=10)
    except HTTPError as exc: response=exc
    with response: return response.status,response.read(),dict(response.headers)


class ProductServerTests(unittest.TestCase):
    def test_launch_environment_reaches_benchmark_extractor(self):
        with patch.dict(os.environ,{'OPENAI_API_KEY':'SYNTHETIC_TEST_KEY','OPENAI_MODEL':'SYNTHETIC_TEST_MODEL'}),patch('investigation.llm.local_settings',return_value={}):
            engine=make_live_engine()
        self.assertIsInstance(engine.extractor,LLMExtractor)
        self.assertIsInstance(engine.extractor.client,OpenAIClient)
        self.assertEqual(engine.extractor.client.api_key,'SYNTHETIC_TEST_KEY')
        self.assertEqual(engine.extractor.client.model,'SYNTHETIC_TEST_MODEL')

    def test_manual_text_uses_model_adapter_then_deterministic_verification(self):
        # Offline integration regression: provider transport is mocked, never a live success claim.
        message='The domain example.com is registered.'
        candidate={'claims':[{'k':'domain_registration','o':None,'q':message,'d':'example.com','p':'+','b':'e','r':'rdap'}]}
        engine=make_live_engine();engine.domain=DomainVerifier('unavailable')
        with patch.object(OpenAIClient,'structured',return_value=(candidate,{'origin':'SYNTHETIC_TEST_PROVIDER_TRANSPORT'})) as provider:
            with server_pair(engine=engine) as url:
                status,body,_=http(url+'/investigate',{'message':message})
        data=json.loads(body)
        self.assertEqual(status,200)
        provider.assert_called_once()
        self.assertEqual(provider.call_args.args[1],message)
        self.assertTrue(data['extraction']['used_llm'])
        self.assertEqual(data['input']['origin'],'user_supplied')
        self.assertEqual(data['claims'][0]['verification_method'],'rdap_domain_provenance')
        self.assertEqual(data['claims'][0]['evidence_state'],'NO_AUTHORITATIVE_DATA')

    def test_missing_key_fails_closed_without_annotations(self):
        with patch.dict(os.environ,{'OPENAI_API_KEY':''}),patch('investigation.llm.local_settings',return_value={}):
            engine=make_live_engine()
        with server_pair(engine=engine) as url:
            status,body,_=http(url+'/investigate',{'message':'I represent Horizon Financial Planning Limited.'})
        self.assertEqual(status,502)
        self.assertEqual(json.loads(body)['claims'],[])
    def test_example_is_actual_fixture_with_annotations_hidden_by_default(self):
        with server_pair() as url:
            status,body,_=http(url+"/fixture")
            data=json.loads(body)
        self.assertEqual(status,200)
        self.assertFalse(data["annotation_mode"])
        self.assertNotIn("claims_annotation",data)
        original=Path("fixtures/clone_firm/message.txt").read_text(encoding="utf-8")
        self.assertEqual(data["message"],original)
    def test_explicit_annotation_example_is_labelled(self):
        with server_pair(True) as url:
            _,body,_=http(url+"/fixture")
        data=json.loads(body)
        self.assertTrue(data["annotation_mode"])
        self.assertEqual(data["claims_annotation"]["origin"],"fixture_annotation")
    def test_proxy_preserves_real_backend_validation_error(self):
        with server_pair() as url:
            status,body,_=http(url+"/investigate",{"message":"unit test","source_url":"https://untrusted.example"})
        self.assertEqual(status,400)
        self.assertEqual(json.loads(body)["status"],"invalid_input")
    def test_workspace_files_are_not_served(self):
        with server_pair() as url:
            for path in ["/.env","/investigation/llm.py","/results/clone-investigation-3.json"]:
                self.assertEqual(http(url+path)[0],404)
    def test_static_shell_and_same_origin_headers(self):
        with server_pair() as url:
            status,body,headers=http(url+"/")
        self.assertEqual(status,200)
        self.assertIn(b"UNIT TEST static shell",body)
        self.assertEqual(headers["X-Content-Type-Options"],"nosniff")
        self.assertEqual(headers["Cache-Control"],"no-store")

if __name__=="__main__": unittest.main()
