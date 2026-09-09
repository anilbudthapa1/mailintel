import contextlib
import io
import json
import mailbox
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch
import httpx
from mailintel import analysis as a, workflows as w, providers, monitor
from mailintel.core import Store
from mailintel.cli import main


class V14(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root/'db');self.cid=self.store.create('Test')
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def file(self,name,data):
        p=self.root/name;p.write_bytes(data if isinstance(data,bytes) else data.encode());return p
    def test_extract_provenance_aliases(self):
        data=a.extract(self.file('contacts.txt','Contact support@example.com\nA.B+tag@gmail.com'))
        self.assertEqual(len(data['observations']),2)
        self.assertEqual(data['observations'][0]['role'],'role_address')
        self.assertEqual(data['observations'][1]['possible_alias_group'],'ab@gmail.com')
        self.assertEqual(data['observations'][1]['location'],'line 2')
    def test_names_are_guesses(self):
        result=a.candidates('Alice','Smith','example.com')
        self.assertTrue(all(x['status']=='unverified_guess' for x in result['candidates']))
        self.assertIn('alice.smith@example.com',[x['email'] for x in result['candidates']])
    def test_html_links_images_attachment(self):
        msg=EmailMessage();msg['From']='billing@example.com';msg['Reply-To']='other@example.net'
        msg.set_content('Hello');msg.add_alternative('<a href="https://other.example/pay">https://example.com/pay</a><img width="1" src="https://other.example/pixel">',subtype='html')
        msg.add_attachment(b'MZpayload',maintype='application',subtype='pdf',filename='invoice.pdf')
        with patch('socket.socket',side_effect=AssertionError('Network forbidden')):data=a.message(msg.as_bytes(),'fixture')
        self.assertTrue(data['links'][0]['host_mismatch']);self.assertTrue(data['images'][0]['possible_tracking_pixel'])
        self.assertEqual(data['attachments'][0]['detected_type'],'DOS/Windows executable')
        self.assertTrue(data['signals'])
    def test_thread_payment_change(self):
        path=self.root/'mail.mbox';box=mailbox.mbox(path)
        for i,account in enumerate(('1111 2222','9999 8888')):
            msg=EmailMessage();msg['From']='billing@example.com';msg['Message-ID']=f'<{i}@example.com>'
            if i:msg['In-Reply-To']='<0@example.com>'
            msg.set_content('Account number: '+account);box.add(msg)
        box.flush();box.close()
        result=a.mailbox_analysis(path)
        self.assertEqual(result['total_messages'],2)
        self.assertFalse(result['threads'][1]['missing_parent'])
        self.assertIn('payment',result['messages'][1]['signals'][0])
    def test_xml_entities_rejected(self):
        for enc in ('utf-8','utf-16'):
            with self.assertRaises(ValueError):a.safe_xml('<!DOCTYPE feedback [<!ENTITY x "boom">]><feedback>&x;</feedback>'.encode(enc))
    def test_dmarc_counts(self):
        p=self.file('d.xml','<feedback><record><row><source_ip>192.0.2.1</source_ip><count>4</count><policy_evaluated><dkim>fail</dkim><spf>pass</spf></policy_evaluated></row></record></feedback>')
        self.assertEqual(a.dmarc(p)['total_messages'],4)
    def test_claim_conflicts_and_independence(self):
        claims=[dict(email='a@example.com',provider=x,source='https://example.com/contact',claim='account',value=v,observed_at='2026-01-01T00:00:00Z') for x,v in [('one','yes'),('two','no')]]
        payload=w.import_claims(self.file('claims.json',json.dumps(claims)))
        self.store.save(self.cid,'a@example.com','email','import',[w.finding('claims',payload)])
        result=w.insights(self.store.runs(self.cid))
        self.assertEqual(len(result['conflicts']),1);self.assertEqual(len(result['shared_declared_sources']),1)
    def test_redaction_removes_email_body_and_terms(self):
        result=w.redact({'body':'full message','note':'a@example.com secret123','sha256':'old'},['secret123'])
        self.assertNotIn('body',result);self.assertNotIn('sha256',result)
        self.assertNotIn('a@example.com',result['note']);self.assertNotIn('secret123',result['note'])
    def test_cross_indicator_compare_rejected(self):
        x=self.store.save(self.cid,'a@example.com','email','offline',[]);y=self.store.save(self.cid,'b@example.com','email','offline',[])
        with self.assertRaises(ValueError):w.compare(self.store.runs(self.cid),x,y)
    def test_batch_validates_all_before_network(self):
        path=self.file('list.txt','a@example.com\ninvalid')
        with patch('mailintel.modules.run_modules',side_effect=AssertionError('Must not run')):
            self.assertEqual(main(['--data-dir',str(self.root/'db'),'batch',str(path),'--case',self.cid,'--profile','passive']),2)
    def test_hunter_headers_no_query_key(self):
        captured=[]
        def handler(request):
            captured.append(request);return httpx.Response(200,json={'data':{'emails':[],'pattern':'{first}.{last}'}})
        real=httpx.Client
        with patch.dict('os.environ',{'HUNTER_API_KEY':'private-key'}),patch('httpx.Client',side_effect=lambda **kw:real(transport=httpx.MockTransport(handler),**kw)):
            result=providers.lookup('hunter-search','example.com',self.store)
        self.assertEqual(result['status'],'observed');self.assertEqual(captured[0].headers['X-API-KEY'],'private-key')
        self.assertNotIn('private-key',str(captured[0].url));self.assertNotIn('private-key',json.dumps(result))
    def test_provider_redirect_not_followed(self):
        real=httpx.Client;requests=[]
        def handler(req):requests.append(req);return httpx.Response(302,headers={'Location':'http://127.0.0.1/secret'})
        with patch('httpx.Client',side_effect=lambda **kw:real(transport=httpx.MockTransport(handler),**kw)):
            result=providers.lookup('rdap','example.com',self.store)
        self.assertEqual(result['status'],'partial');self.assertEqual(len(requests),1)
    def test_watch_offline_and_no_duplicate_due(self):
        monitor.create(self.store,self.cid,'a@example.com',3600,'offline')
        with patch('socket.socket',side_effect=AssertionError('Network forbidden')):
            self.assertEqual(len(monitor.due(self.store,10)),1);self.assertEqual(monitor.due(self.store,10),[])
    def test_external_missing_not_negative(self):
        from mailintel.external import execute
        with patch('shutil.which',return_value=None):self.assertEqual(execute('holehe','a@example.com')['status'],'not_configured')
    def test_review_unknown_run_rejected(self):
        with contextlib.redirect_stdout(io.StringIO()):
            result=main(['--data-dir',str(self.root/'db'),'review','--case',self.cid,'--run','bad','--reviewer','analyst','--decision','accepted','--note','reviewed'])
        self.assertEqual(result,2)
    def test_graph_and_bundle(self):
        self.store.save(self.cid,'a@example.com','email','offline',[w.finding('local',{'email':'a@example.com'})])
        out=self.root/'graph';w.graph(self.store.runs(self.cid),out)
        self.assertIn('a@example.com',(out/'graph.svg').read_text())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--data-dir',str(self.root/'db'),'bundle','--case',self.cid,'--out',str(self.root/'evidence.zip')]),0)
        import zipfile
        with zipfile.ZipFile(self.root/'evidence.zip') as z:self.assertIn('SHA256SUMS',z.namelist())

    def test_budget_stops_additional_reservation(self):
        with self.store.db:self.store.db.execute('INSERT INTO budgets VALUES (?,?,?)',('hunter',1,0.01))
        self.assertEqual(self.store.reserve('hunter',0),0)
        self.assertGreater(self.store.reserve('hunter',0),0)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM requests').fetchone()[0],1)

    def test_ghunt_runner_with_fixture_executable(self):
        from mailintel.external import execute
        import sys
        tool=self.root/'ghunt'
        tool.write_text('#!'+sys.executable+'\nimport sys,json,pathlib\nassert sys.argv[1:3]==["email","a@example.com"]\nassert sys.argv[3]=="--json"\npathlib.Path(sys.argv[4]).write_text(json.dumps({"fixture":True}))\n')
        tool.chmod(0o700)
        with patch('shutil.which',return_value=str(tool)):
            result=execute('ghunt','a@example.com')
        self.assertEqual(result['status'],'observed')
        self.assertTrue(result['data']['upstream_result']['fixture'])

if __name__=='__main__':unittest.main()
