import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from mailintel.core import Store, encoded
from mailintel.modules import run_modules, email_info, domain_name, api_check, disposable, dns_check
from mailintel.harvester import load_result, execute
from mailintel.reports import report
from mailintel.cli import main


class MailIntelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'data')
        self.cid = self.store.create('Test <script>alert(1)</script>')

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def test_local_part_preserved_and_idna(self):
        normal, domain, _ = email_info('First.Last+tag@EXAMPLE.COM')
        self.assertEqual(normal, 'First.Last+tag@example.com')
        self.assertEqual(domain_name('bücher.de'), 'xn--bcher-kva.de')
        for invalid in ('x;touch /tmp/owned', 'https://example.com', '-bad.com', 'bad..com'):
            with self.assertRaises(ValueError): domain_name(invalid)

    def test_offline_never_uses_network(self):
        with patch('socket.socket', side_effect=AssertionError('Network forbidden')):
            result = run_modules('email', 'x@example.com', ['syntax', 'disposable'], 'offline', self.store)
            self.assertEqual(result[0]['status'], 'valid_syntax')
            for module in ('dns', 'hibp', 'emailrep'):
                with self.assertRaises(ValueError):
                    run_modules('email', 'x@example.com', [module], 'offline', self.store)

    def test_invalid_case_no_network(self):
        with patch('mailintel.modules.run_modules', side_effect=AssertionError('must not run')):
            self.assertEqual(main(['--data-dir', str(self.root/'data'), 'scan', 'email', 'x@example.com', '--case', 'missing']), 2)

    def test_disposable_snapshot_and_subdomain(self):
        finding = disposable('child.mailinator.com')
        self.assertEqual(finding['status'], 'listed')
        self.assertEqual(finding['data']['dataset']['sha256'], finding['data']['sha256'])
        self.assertEqual(disposable('mailinator.com.attacker.invalid')['status'], 'not_listed')

    def test_missing_key_does_not_call_api(self):
        with patch.dict(os.environ, {}, clear=True):
            result = api_check('hibp', 'x@example.com', self.store, lambda *a: self.fail('network'))
        self.assertEqual(result['status'], 'not_configured')

    def test_hibp_selected_metadata_only(self):
        def fetch(url, headers):
            self.assertIn('x%2Btag%40example.com', url)
            self.assertEqual(headers['User-Agent'], 'MailIntel/0.1.0')
            return 200, {}, json.dumps([{'Name': 'Example', 'BreachDate': '2020-01-01', 'Description': '<script>', 'secret': 'omit'}]).encode()
        with patch.dict(os.environ, {'HIBP_API_KEY': '0'*32}):
            r = api_check('hibp', 'x+tag@example.com', self.store, fetch)
        self.assertEqual(r['status'], 'observed')
        self.assertNotIn('secret', r['data']['breaches'][0])
        self.assertNotIn('Description', r['data']['breaches'][0])

    def test_rate_limit_persisted(self):
        with patch.dict(os.environ, {'HIBP_API_KEY': '0'*32}):
            r = api_check('hibp', 'x@example.com', self.store, lambda *a: (429, {'retry-after': '120'}, b''))
            self.assertEqual(r['status'], 'rate_limited')
            r = api_check('hibp', 'x@example.com', self.store, lambda *a: self.fail('must respect cooldown'))
            self.assertEqual(r['status'], 'rate_limited')

    def test_error_not_negative(self):
        for status, expected in [(401, 'error'), (404, 'not_found'), (503, 'error')]:
            self.store.db.execute('DELETE FROM cooldowns'); self.store.db.commit()
            with patch.dict(os.environ, {'HIBP_API_KEY': '0'*32}):
                r = api_check('hibp', 'x@example.com', self.store, lambda *a: (status, {}, b''))
                self.assertEqual(r['status'], expected)

    def test_schema_failure_not_negative(self):
        with patch.dict(os.environ, {'HIBP_API_KEY': '0'*32}):
            result = api_check('hibp', 'x@example.com', self.store, lambda *a: (200, {}, b'{"error":"bad"}'))
        self.assertEqual(result['status'], 'error')

    def test_emailrep_result(self):
        result = api_check('emailrep', 'x@example.com', self.store, lambda *a: (200, {}, b'{"reputation":"high","suspicious":false,"details":{}}'))
        self.assertEqual(result['status'], 'observed')

    def test_dns_null_mx_and_timeout(self):
        def query(name, kind, resolver):
            return {'status': 'observed', 'records': ['0 .'] if kind == 'MX' else [], 'ttl': 100}
        with patch('mailintel.modules.query_dns', side_effect=query):
            result = dns_check('example.com', resolver=object())
        self.assertTrue(result['data']['mx']['null_mx'])
        with patch('mailintel.modules.query_dns', return_value={'status': 'timeout', 'records': []}):
            self.assertEqual(dns_check('example.com', resolver=object())['status'], 'partial')

    def test_report_integrity_escape_and_no_overwrite(self):
        findings = run_modules('email', 'x@example.com', ['syntax'], 'offline', self.store)
        self.store.save(self.cid, 'x@example.com', 'email', 'offline', findings)
        dest = report(self.store, self.cid, self.root/'report')
        page = (dest/'report.html').read_text()
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;script&gt;', page)
        run = json.loads((dest/'report.json').read_text())['runs'][0]
        digest = run.pop('sha256')
        self.assertEqual(hashlib.sha256(encoded(run)).hexdigest(), digest)
        with self.assertRaises(FileExistsError): report(self.store, self.cid, dest)
        self.store.db.execute("UPDATE runs SET payload='{}'"); self.store.db.commit()
        with self.assertRaises(ValueError): self.store.runs(self.cid)

    def test_harvester_import_filters_scope(self):
        p = self.root/'result.jsonl'
        p.write_text('\n'.join(json.dumps(x) for x in [
            {'type': 'summary'}, {'type':'email', 'value':'x@example.com', 'sources':['fixture']},
            {'type':'email','value':'x@evil-example.com'}, {'type':'hostname','value':'sub.example.com'}]))
        r = load_result(p, 'example.com')
        self.assertEqual(len(r['data']['findings']), 2)
        self.assertEqual(r['data']['input_sha256'], hashlib.sha256(p.read_bytes()).hexdigest())

    def test_harvester_rejects_unreviewed_sources(self):
        with self.assertRaises(ValueError): execute('example.com', ['all'])


if __name__ == '__main__': unittest.main()
