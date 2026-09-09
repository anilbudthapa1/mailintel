import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx
from mailintel.core import Store
from mailintel.archive import collect
from mailintel.auth import extended,verify_dkim
from mailintel.analysis import extract

class AuthArchive(unittest.TestCase):
    def test_archive_snapshot_difference_without_live_website(self):
        calls=[]
        def handler(request):
            calls.append(str(request.url))
            if '/cdx/' in request.url.path:return httpx.Response(200,json=[['timestamp','original'],['20260101000000','https://example.com/contact'],['20260201000000','https://example.com/contact']])
            return httpx.Response(200,text='old@example.com' if '202601' in request.url.path else 'new@example.com')
        real=httpx.Client
        with tempfile.TemporaryDirectory() as t:
            store=Store(t)
            try:
                with patch('httpx.Client',side_effect=lambda **kw:real(transport=httpx.MockTransport(handler),**kw)):
                    result=collect('https://example.com/contact',2,store)
                self.assertEqual(result['status'],'observed')
                self.assertEqual(result['data']['publication_changes'][0]['added'],['new@example.com'])
                self.assertTrue(all(x.startswith('https://web.archive.org/') for x in calls))
            finally:store.db.close()
    def test_auth_psl_and_mta_sts(self):
        def query(name,kind,resolver):
            records=[]
            if name=='_dmarc.example.co.uk':records=['v=DMARC1; p=reject']
            if name=='sub.example.co.uk' and kind=='TXT':records=['v=spf1 include:sender.example.net -all']
            return {'status':'observed' if records else 'no_answer','records':records}
        real=httpx.Client
        with patch('mailintel.auth.query_dns',side_effect=query),patch('mailintel.auth.dns_check',return_value={'status':'observed'}),patch('httpx.Client',side_effect=lambda **kw:real(transport=httpx.MockTransport(lambda r:httpx.Response(200,text='version: STSv1\nmode: enforce\nmx: mail.example.co.uk\nmax_age: 86400')),**kw)):
            result=extended('sub.example.co.uk')
        self.assertEqual(result['dmarc_lookup']['organizational_domain'],'example.co.uk')
        self.assertIn('v=DMARC1; p=reject',result['dmarc_lookup']['fallback']['records'])
        self.assertEqual(result['mta_sts_policy']['fields']['mode'],['enforce'])
    def test_unsigned_dkim_no_dns(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'unsigned.eml';p.write_bytes(b'From: a@example.com\r\n\r\nHello')
            with patch('mailintel.auth.query_dns',side_effect=AssertionError('No DNS for unsigned message')):
                self.assertEqual(verify_dkim(p)['status'],'unsigned')
    def test_real_rsa_dkim_verification(self):
        import subprocess,shutil,dkim
        if not shutil.which('openssl'):self.skipTest('openssl not installed')
        with tempfile.TemporaryDirectory() as t:
            key=Path(t)/'test.key'
            subprocess.run(['openssl','genrsa','-out',str(key),'1024'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            public=subprocess.check_output(['openssl','rsa','-in',str(key),'-pubout'],stderr=subprocess.DEVNULL).decode()
            public=''.join(public.splitlines()[1:-1])
            raw=b'From: a@example.com\r\nTo: b@example.org\r\nSubject: training\r\n\r\nHello\r\n'
            signed=dkim.sign(raw,b'test',b'example.com',key.read_bytes())+raw
            p=Path(t)/'signed.eml';p.write_bytes(signed)
            with patch('mailintel.auth.query_dns',return_value={'status':'observed','records':['v=DKIM1; k=rsa; p='+public]}):
                self.assertEqual(verify_dkim(p)['status'],'valid')
                p.write_bytes(signed.replace(b'Hello',b'Changed'))
                self.assertEqual(verify_dkim(p)['status'],'not_verified')
    def test_pdf_parser_blank_page(self):
        from pypdf import PdfWriter
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'blank.pdf';w=PdfWriter();w.add_blank_page(width=200,height=200);w.write(p)
            self.assertEqual(extract(p)['observations'],[])

if __name__=='__main__':unittest.main()
