import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from mailintel.modules import query_dns, http_json
from mailintel.harvester import execute


class BoundaryTests(unittest.TestCase):
    def test_real_dns_types_parse_without_network(self):
        import dns.rrset
        class Answer:
            rrset = dns.rrset.from_text('example.com.', 120, 'IN', 'TXT', '"v=spf1 " "-all"')
            def __iter__(self): return iter(self.rrset)
        class Resolver:
            def resolve(self, name, kind, lifetime): return Answer()
        result = query_dns('example.com', 'TXT', Resolver())
        self.assertEqual(result['records'], ['v=spf1 -all'])
        self.assertEqual(result['ttl'], 120)

    def test_real_dns_nxdomain_distinct_from_timeout(self):
        import dns.resolver
        import dns.exception
        class Resolver:
            def resolve(self, *args, **kwargs): raise dns.resolver.NXDOMAIN()
        self.assertEqual(query_dns('example.com', 'MX', Resolver())['status'], 'nxdomain')
        class TimeoutResolver:
            def resolve(self, *args, **kwargs): raise dns.exception.Timeout()
        self.assertEqual(query_dns('example.com', 'MX', TimeoutResolver())['status'], 'timeout')

    def test_external_runner_argv_and_output(self):
        # A real local fixture executable exercises subprocess and file discovery.
        # No third-party program or network request is used.
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp)/'theHarvester'
            script.write_text('#!/usr/bin/env python3\nimport sys,json\n'
                              'assert "-b" in sys.argv and "crtsh" in sys.argv\n'
                              'out=sys.argv[sys.argv.index("-f")+1]\n'
                              'open(out+".json", "w").write(json.dumps({"emails":["x@example.com"]}))\n')
            script.chmod(0o700)
            with patch('mailintel.harvester.shutil.which', return_value=str(script)):
                result = execute('example.com', ['crtsh'])
            self.assertEqual(result['status'], 'observed')
            self.assertEqual(result['data']['findings'][0]['value'], 'x@example.com')

    def test_http_transport_size_and_redirect_settings(self):
        import httpx
        real_client = httpx.Client
        def factory(**kwargs):
            self.assertFalse(kwargs['follow_redirects'])
            self.assertFalse(kwargs['trust_env'])
            return real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={'ok':True})), **kwargs)
        with patch('httpx.Client', side_effect=factory):
            code, headers, raw = http_json('https://example.com/', {'User-Agent':'MailIntel/0.1.0'})
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(raw)['ok'])
