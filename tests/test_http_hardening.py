"""Adversarial transport regressions; no requests to real private services."""
from email.message import Message
from io import BytesIO
import json
import socket
import ssl
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError
from urllib.request import Request, urlopen

import safe_http
from investigation.api import make_server
from investigation.http_support import BoundedHTTPServer, MAX_REQUEST_BYTES
from investigation.llm import LLMFailure, OpenAIClient, extraction_schema
from rdap_domain_provenance import LoggedRedirects, select_service, fetch_json
from test_product_server import server_pair
from test_investigation import engine, MESSAGE


class Response(BytesIO):
    def __init__(self, body=b'{}', status=200):
        super().__init__(body)
        self.status = self.code = status
        self.headers = Message()
    def geturl(self): return 'https://registry.example/domain/example.com'


class OutboundTests(unittest.TestCase):
    def test_private_and_unsafe_urls_rejected(self):
        for url in ['http://example.com', 'https://127.0.0.1/', 'https://[::1]/', 'https://169.254.169.254/',
                    'https://10.0.0.1/', 'https://192.168.1.1/', 'https://example.com:444/', 'https://u:p@example.com/',
                    'https://example.local/', 'https://example.com/\nheader', 'https://example.com\\@127.0.0.1/']:
            with self.subTest(url=url), self.assertRaises(ValueError): safe_http.checked_https_url(url)

    def test_rdap_redirect_cannot_change_authority(self):
        req=Request('https://registry.example/domain/example.com')
        for url in ['https://127.0.0.1/admin','https://other.example/domain/example.com','https://registry.example:444/']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                LoggedRedirects([]).redirect_request(req,None,302,'',Message(),url)
        redirect=LoggedRedirects([]).redirect_request(req,None,302,'',Message(),'/new')
        self.assertEqual(redirect.full_url,'https://registry.example/new')

    def test_bootstrap_rejects_private_service(self):
        with self.assertRaises(ValueError): select_service({'services':[[['com'],['https://127.0.0.1/']]]},'example.com')

    def test_dns_private_or_mixed_answers_block_before_socket(self):
        for addresses in [['127.0.0.1'], ['::1'], ['93.184.216.34','10.0.0.1']]:
            answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(a,443)) for a in addresses]
            with patch('safe_http.socket.getaddrinfo',return_value=answers),patch('safe_http.socket.socket') as connect:
                with self.assertRaises(safe_http.UnsafeURL): safe_http.public_connection(('registry.example',443),1)
                connect.assert_not_called()

    def test_connect_uses_checked_address_without_second_dns_lookup(self):
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))]
        with patch('safe_http.socket.getaddrinfo',return_value=addresses) as resolve,patch('safe_http.socket.socket') as factory:
            self.assertIs(safe_http.public_connection(('registry.example',443),2),factory.return_value)
            resolve.assert_called_once()
            factory.return_value.connect.assert_called_once_with(('93.184.216.34',443))

    def test_transient_get_retries_once_and_closes_first_response(self):
        first=Response(status=503);last=Response()
        opener=Mock();opener.open.side_effect=[first,last]
        attempts=[]
        with patch('safe_http.time.sleep') as sleep:
            self.assertIs(safe_http.open_get(opener,Request('https://example.com'),2,attempts),last)
        self.assertTrue(first.closed);self.assertEqual(opener.open.call_count,2)
        sleep.assert_called_once_with(.25)
        self.assertEqual([a['http_status'] for a in attempts],[503,200])

    def test_timeout_retry_is_bounded_and_no_retry_on_404(self):
        opener=Mock();opener.open.side_effect=URLError(TimeoutError())
        attempts=[]
        with patch('safe_http.time.sleep'),self.assertRaises(URLError):
            safe_http.open_get(opener,Request('https://example.com'),1,attempts)
        self.assertEqual(opener.open.call_count,2)
        opener=Mock();opener.open.return_value=Response(status=404)
        with patch('safe_http.time.sleep') as sleep:
            self.assertEqual(safe_http.open_get(opener,Request('https://example.com'),1,[]).status,404)
            sleep.assert_not_called()

    def test_certificate_errors_are_not_retried(self):
        opener=Mock();opener.open.side_effect=URLError(ssl.SSLCertVerificationError('SYNTHETIC certificate error'))
        with patch('safe_http.time.sleep') as sleep,self.assertRaises(URLError):
            safe_http.open_get(opener,Request('https://example.com'),1,[])
        self.assertEqual(opener.open.call_count,1);sleep.assert_not_called()

    def test_response_size_and_malformed_rdap_fail_explicitly(self):
        for body, limit in [(b'x'*101,100),(b'{"x":1,"x":2}',100),(b'[]',100)]:
            opener=Mock();opener.open.return_value=Response(body)
            evidence=[]
            with patch('rdap_domain_provenance.secure_opener',return_value=opener),self.assertRaises(ValueError):
                fetch_json('https://registry.example/domain/example.com',evidence,1,limit)
            self.assertIsNotNone(evidence[0]['error'])
            self.assertLessEqual(evidence[0]['captured_bytes'],limit)

    def test_budget_enforced_before_connection_and_reset_after_failure(self):
        handler=safe_http.PublicHTTPSHandler();req=Request('https://example.com');req.timeout=1
        with patch.object(handler,'do_open',return_value=Response()) as network:
            with safe_http.investigation_budget(max_requests=1):
                handler.https_open(req)
                with self.assertRaises(OSError): handler.https_open(req)
            with safe_http.investigation_budget(max_requests=1): handler.https_open(req)
            self.assertEqual(network.call_count,2)
        with safe_http.investigation_budget(seconds=-1),self.assertRaises(TimeoutError): safe_http.remaining_timeout(1)

    def test_provider_errors_do_not_keep_raw_body_or_retry_post(self):
        opener=Mock();opener.open.return_value=Response(b'SENSITIVE SENTINEL sk-test-private',429)
        with patch('investigation.llm.build_opener',return_value=opener),self.assertRaises(LLMFailure) as failure:
            OpenAIClient(api_key='sk-test-private').structured('test','SENSITIVE SENTINEL',extraction_schema(),'atomic_claims')
        self.assertEqual(opener.open.call_count,1)
        self.assertNotIn('SENSITIVE',json.dumps(failure.exception.evidence))
        self.assertNotIn('sk-test-private',str(failure.exception))
        self.assertEqual(failure.exception.evidence['http_status'],429)

    def test_invalid_provider_envelopes_and_refusal_fail_closed(self):
        bodies=[b'[]',b'{"status":"incomplete"}',json.dumps({'status':'completed','output':[{'type':'message','content':[{'type':'refusal','refusal':'No'}]}]}).encode(),b'{"status":"completed","output":[null]}']
        for body in bodies:
            opener=Mock();opener.open.return_value=Response(body)
            with self.subTest(body=body),patch('investigation.llm.build_opener',return_value=opener),self.assertRaises(LLMFailure):
                OpenAIClient(api_key='SYNTHETIC').structured('test','hello',extraction_schema(),'atomic_claims')


def raw_http(url, headers, body=b'', host='localhost'):
    from urllib.parse import urlsplit
    port=urlsplit(url).port
    with socket.create_connection(('127.0.0.1',port),timeout=5) as sock:
        sock.sendall(b'POST /investigate HTTP/1.0\r\nHost: '+host.encode()+b'\r\n'+headers+b'\r\n\r\n'+body)
        sock.shutdown(socket.SHUT_WR)
        chunks=[]
        while chunk:=sock.recv(65536): chunks.append(chunk)
    head,body=b''.join(chunks).split(b'\r\n\r\n',1)
    return int(head.split(b' ')[1]),json.loads(body)


class RequestTests(unittest.TestCase):
    def test_cross_origin_and_rebound_host_are_rejected_before_investigation(self):
        backend=Mock();backend.investigate.return_value={'status':'synthetic_test_success'}
        with server_pair(engine=backend) as url:
            body=b'{"message":"synthetic test"}'
            headers=b'Content-Type: application/json\r\nContent-Length: '+str(len(body)).encode()
            status,_=raw_http(url,headers+b'\r\nOrigin: https://attacker.example',body)
            self.assertEqual(status,403)
            status,_=raw_http(url,headers,body,host='rebound.attacker.example')
            self.assertEqual(status,403)
            backend.investigate.assert_not_called()
            status,_=raw_http(url,headers+b'\r\nOrigin: http://localhost',body)
            self.assertEqual(status,200)
            backend.investigate.assert_called_once()

    def test_proxy_and_backend_reject_bad_framing_with_json(self):
        api=make_server(engine(),port=0)
        worker=threading.Thread(target=api.serve_forever,daemon=True);worker.start()
        try:
            with server_pair(engine=engine()) as proxy:
                for url in [proxy,f'http://127.0.0.1:{api.server_port}']:
                    for headers,body,expected in [
                        (b'Content-Length: 2\r\nContent-Length: 2',b'{}',400),
                        (b'Content-Length: '+str(MAX_REQUEST_BYTES+1).encode(),b'',413),
                        (b'Content-Length: 2\r\nContent-Type: text/plain',b'{}',415),
                        (b'Transfer-Encoding: chunked\r\nContent-Length: 2',b'{}',400),
                        (b'Content-Length: 100\r\nContent-Type: application/json',b'{}',400),
                        (b'Content-Length: '+b'9'*100,b'',400)]:
                        with self.subTest(url=url,expected=expected):
                            status,payload=raw_http(url,headers,body)
                            self.assertEqual(status,expected)
                            self.assertIsInstance(payload['error']['message'],str)
        finally:
            api.shutdown();api.server_close();worker.join(2)

    def test_adversarial_json_through_actual_proxy(self):
        with server_pair(engine=engine()) as url:
            for body in [b'['*65+b'0'+b']'*65,b'{"message":"a","message":"b"}',b'{"message":"\\ud800"}',b'{"message":1e400}',b'\xff']:
                status,payload=raw_http(url,b'Content-Type: application/json\r\nContent-Length: '+str(len(body)).encode(),body)
                self.assertEqual(status,400)
                self.assertEqual(payload['status'],'invalid_input')

    def test_body_timeout_returns_structured_408(self):
        with patch('investigation.http_support.REQUEST_TIMEOUT',.1), server_pair() as url:
            from urllib.parse import urlsplit
            with socket.create_connection(('127.0.0.1',urlsplit(url).port),timeout=3) as sock:
                sock.sendall(b'POST /investigate HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{')
                data=b''
                while chunk:=sock.recv(65536): data+=chunk
                self.assertIn(b'408',data.split(b'\r\n')[0])
                self.assertEqual(json.loads(data.split(b'\r\n\r\n')[1])['status'],'request_timeout')

    def test_provider_and_internal_failure_do_not_expose_secrets(self):
        for exc,expected in [(RuntimeError('SENSITIVE SENTINEL'),500),(LLMFailure('SENSITIVE SENTINEL',{'raw_response':'private communication','http_status':429}),502)]:
            backend=Mock();backend.investigate.side_effect=exc
            with server_pair(engine=backend) as url:
                body=b'{"message":"input"}'
                status,payload=raw_http(url,b'Content-Type: application/json\r\nContent-Length: '+str(len(body)).encode(),body)
                self.assertEqual(status,expected)
                self.assertNotIn('SENSITIVE',json.dumps(payload));self.assertNotIn('private communication',json.dumps(payload))

    def test_success_log_contains_only_metadata(self):
        with server_pair(engine=engine()) as url,self.assertLogs('crosscheck.http',level='INFO') as logs:
            body=json.dumps({'message':MESSAGE}).encode()
            status,_=raw_http(url,b'Content-Type: application/json\r\nContent-Length: '+str(len(body)).encode(),body)
            self.assertEqual(status,200)
        self.assertNotIn(MESSAGE,'\n'.join(logs.output))
        self.assertIn('request_id=','\n'.join(logs.output))

    def test_saturated_worker_pool_returns_503_and_recovers(self):
        from http.server import BaseHTTPRequestHandler
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.end_headers()
            def log_message(self,*args): pass
        server=BoundedHTTPServer(('127.0.0.1',0),Handler,max_workers=1)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            server.slots.acquire()
            with socket.create_connection(('127.0.0.1',server.server_port),timeout=3) as sock:
                self.assertIn(b'503',sock.recv(4096))
            server.slots.release()
            with urlopen(f'http://127.0.0.1:{server.server_port}',timeout=3) as response: self.assertEqual(response.status,200)
        finally:
            server.shutdown();server.server_close();worker.join(2)


if __name__=='__main__': unittest.main()
