"""Deployment configuration only; no model or verification behavior changes."""
import os
import threading
import unittest
from unittest.mock import patch
from urllib.request import urlopen
from investigation.api import make_server
from investigation.engine import InvestigationEngine
from run_product import parse_args, make_product_server


class DeploymentTests(unittest.TestCase):
    def test_local_defaults(self):
        with patch.dict(os.environ,{},clear=True):
            args=parse_args([])
        self.assertEqual((args.host,args.port),('127.0.0.1',8080))

    def test_platform_environment_and_cli_override(self):
        with patch.dict(os.environ,{'HOST':'0.0.0.0','PORT':'43210'}):
            args=parse_args([])
            override=parse_args(['--port','8081'])
        self.assertEqual((args.host,args.port),('0.0.0.0',43210))
        self.assertEqual(override.port,8081)

    def test_public_binding_health_and_private_api(self):
        api=make_server(InvestigationEngine(),port=0)
        product=make_product_server(api,port=0,host='0.0.0.0')
        worker=threading.Thread(target=product.serve_forever,daemon=True)
        worker.start()
        try:
            self.assertEqual(product.server_address[0],'0.0.0.0')
            self.assertEqual(api.server_address[0],'127.0.0.1')
            with urlopen(f'http://127.0.0.1:{product.server_port}/health',timeout=5) as response:
                self.assertEqual(response.status,200)
                self.assertEqual(response.read(),b'{"status": "ready"}')
        finally:
            product.shutdown();product.server_close();api.server_close();worker.join(timeout=2)
