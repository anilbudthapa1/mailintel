"""Bounded local email evidence analysis. Never fetches links or executes attachments."""
import hashlib
import html
import io
import json
import mailbox
import re
import zipfile
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET
from .modules import domain_name

MAX_FILE = 25 * 1024 * 1024
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}")
ROLE = {'admin','billing','accounts','security','support','info','sales','contact','help','abuse','postmaster','hr','careers','noreply','no-reply'}


def read_file(path):
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_FILE:
        raise ValueError('Input must be a regular file of at most 25 MiB.')
    with p.open('rb') as f:
        data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE: raise ValueError('Input exceeds 25 MiB.')
    return data


def digest(raw): return hashlib.sha256(raw).hexdigest()


def identity(address):
    from .modules import email_info
    try: address = email_info(address)[0]
    except ValueError: return None
    local, domain = address.rsplit('@',1)
    base = local.split('+')[0]
    alias = None
    if domain in ('gmail.com','googlemail.com'):
        alias = base.replace('.','').lower() + '@gmail.com'
    return dict(email=address, domain=domain, role='role_address' if base.lower() in ROLE else 'unclassified',
                possible_alias_group=alias, alias_note='Provider-specific hint only; originals are never merged.')


class HTMLSignals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links=[]; self.images=[]; self.current=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='a':
            self.current={'destination':a.get('href',''),'display_text':''}
            self.links.append(self.current)
        if tag=='img':
            style=a.get('style','').lower().replace(' ','')
            small=a.get('width') in ('0','1') or a.get('height') in ('0','1') or any(s in style for s in ('display:none','width:1px','height:1px'))
            self.images.append({'source':a.get('src',''),'possible_tracking_pixel':small,'reason':'Small or hidden image' if small else 'No size-based signal'})
    def handle_endtag(self,tag):
        if tag=='a': self.current=None
    def handle_data(self,data):
        if self.current is not None:self.current['display_text']+=data


def host(url):
    try: return (urlsplit(url).hostname or '').lower()
    except ValueError: return ''


def signature_type(raw):
    for prefix,label in [(b'%PDF-','PDF'),(b'PK\x03\x04','ZIP container (possibly Office)'),(b'MZ','DOS/Windows executable'),(b'\x7fELF','ELF executable'),(b'\x89PNG','PNG'),(b'\xff\xd8\xff','JPEG')]:
        if raw.startswith(prefix):return label
    return 'unknown (not conclusively identified)'


def message(raw, source):
    m=BytesParser(policy=policy.default).parsebytes(raw)
    headers={k:m.get_all(k,[]) for k in ['From','To','Cc','Reply-To','Return-Path','Subject','Date','Message-ID','In-Reply-To','References','Received','Authentication-Results','DKIM-Signature']}
    addresses={k:[a for _,a in getaddresses(headers[k])] for k in ['From','To','Cc','Reply-To','Return-Path']}
    findings=[]; links=[]; images=[]; attachments=[]; text=[]
    if addresses['Reply-To'] and set(addresses['Reply-To']) != set(addresses['From']):
        findings.append('Reply-To differs from From: can be legitimate; review intended reply destination.')
    for part in m.walk():
        if part.is_multipart():continue
        payload=part.get_payload(decode=True) or b''
        if part.get_filename() or part.get_content_disposition()=='attachment':
            attachments.append(dict(name=part.get_filename(),declared_type=part.get_content_type(),detected_type=signature_type(payload),bytes=len(payload),sha256=digest(payload)))
            continue
        if part.get_content_maintype()!='text':continue
        try: body=payload.decode(part.get_content_charset() or 'utf-8',errors='replace')
        except LookupError: body=payload.decode('utf-8',errors='replace')
        text.append(body)
        if part.get_content_type()=='text/html':
            h=HTMLSignals(); h.feed(body)
            for link in h.links:
                shown=link['display_text'].strip()
                shown_host=host(shown if '://' in shown else 'https://'+shown) if re.match(r'^(?:https?://)?[\w.-]+\.[a-z]{2,}(?:/|$)',shown,re.I) else ''
                link.update(destination_host=host(link['destination']),displayed_host=shown_host,
                            host_mismatch=bool(shown_host and host(link['destination']) and shown_host!=host(link['destination'])),
                            has_query_parameters='?' in link['destination'])
            links.extend(h.links);images.extend(h.images)
    # Only structured field labels, not general digits or every price in a message.
    payment=re.findall(r'(?im)\b(?:IBAN|BSB|account\s*(?:number|no\.?))\s*[:=]\s*([A-Z0-9 -]{4,40})', '\n'.join(text))
    return dict(source=source,sha256=digest(raw),headers=headers,addresses=addresses,links=links,images=images,
                attachments=attachments,body='\n'.join(text),payment_markers=payment,signals=findings,
                authentication_note='Header authentication claims are untrusted unless supplied by your trusted receiving infrastructure. DKIM is not verified here.',
                parse_defects=[str(x) for x in m.defects])


def mailbox_analysis(path, query=None):
    raw=read_file(path)
    messages=[]
    if Path(path).suffix.lower()=='.mbox':
        # Parse the bounded snapshot rather than reopening an unbounded input file.
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            snapshot=Path(t)/'mail.mbox'; snapshot.write_bytes(raw)
            box=mailbox.mbox(snapshot,create=False)
            try:
                for i,key in enumerate(box.iterkeys()):
                    if i>=1000:raise ValueError('Mailbox exceeds 1000 messages; split the file.')
                    messages.append(message(box.get_bytes(key),f'{Path(path).name}#message-{i+1}'))
            finally:box.close()
    else: messages=[message(raw,Path(path).name)]
    ids={v for m in messages for v in m['headers']['Message-ID']}
    threads=[]
    for m in messages:
        refs=re.findall(r'<[^>]+>',' '.join(m['headers']['References']+m['headers']['In-Reply-To']))
        parent=refs[-1] if refs else None
        threads.append(dict(message_id=(m['headers']['Message-ID'] or [None])[0],parent=parent,missing_parent=bool(parent and parent not in ids)))
        if parent:
            prev=next((x for x in messages if parent in x['headers']['Message-ID']),None)
            if prev:
                if prev['addresses']['Reply-To']!=m['addresses']['Reply-To']: m['signals'].append('Reply destination changed from parent message; manual review required.')
                if prev['payment_markers'] and m['payment_markers'] and prev['payment_markers']!=m['payment_markers']:m['signals'].append('Labelled payment details changed from parent message; manual review required.')
    selected=[m for m in messages if not query or query.casefold() in json.dumps(m,ensure_ascii=False).casefold()]
    infrastructure={}
    for m in messages:
        for received in m['headers']['Received']:
            for token in re.findall(r'\b(?:from|by)\s+([^\s;()]+)',received,re.I):
                infrastructure.setdefault(token,[]).append(m['sha256'])
    return dict(input_sha256=digest(raw),total_messages=len(messages),matched_messages=len(selected),messages=selected,threads=threads,
                shared_header_infrastructure={k:sorted(set(v)) for k,v in infrastructure.items() if len(set(v))>1},
                limitations='No links/images loaded; attachments not executed or extracted. Threading uses message IDs; infrastructure is a header claim, not owner attribution.')


def extract(path):
    raw=read_file(path); suffix=Path(path).suffix.lower(); sections=[]
    if suffix=='.pdf':
        try: from pypdf import PdfReader
        except ImportError:raise ValueError('PDF extraction needs optional pypdf: .venv/bin/python -m pip install pypdf')
        reader=PdfReader(io.BytesIO(raw))
        if len(reader.pages)>500:raise ValueError('PDF exceeds 500 pages.')
        sections=[(f'page {i+1}',p.extract_text() or '') for i,p in enumerate(reader.pages)]
    elif suffix=='.docx':
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            info=z.getinfo('word/document.xml')
            if info.file_size>MAX_FILE:raise ValueError('Expanded document exceeds limit.')
            text=safe_xml(z.read(info))
            sections=[('document.xml',' '.join(text.itertext()))]
    else:
        sections=[(f'line {i+1}',line) for i,line in enumerate(raw.decode('utf-8',errors='replace').splitlines())]
    observations=[]
    for location,text in sections:
        for match in EMAIL.finditer(html.unescape(text)):
            info=identity(match.group().strip('.'))
            if info:observations.append(dict(**info,location=location,context=text[max(0,match.start()-60):match.end()+60],confidence='observed_in_supplied_document',source=Path(path).name))
    return dict(sha256=digest(raw),observations=observations,note='Occurrence does not prove ownership, current use or deliverability; no OCR.')


def safe_xml(raw):
    # Reject entities in UTF-8 and UTF-16/32 representations before ElementTree.
    check=raw.replace(b'\x00',b'').upper()
    if b'<!DOCTYPE' in check or b'<!ENTITY' in check:raise ValueError('XML entities/DOCTYPE are not accepted.')
    try:return ET.fromstring(raw)
    except ET.ParseError as e:raise ValueError('Invalid XML: '+str(e))


def dmarc(path):
    root=safe_xml(read_file(path)); rows=[]
    for r in root.findall('.//record'):
        def value(key):return r.findtext(key)
        try: count=int(value('row/count') or 0)
        except ValueError:raise ValueError('DMARC count must be an integer.')
        if count<0:raise ValueError('DMARC count cannot be negative.')
        rows.append(dict(source_ip=value('row/source_ip'),count=count,disposition=value('row/policy_evaluated/disposition'),dkim=value('row/policy_evaluated/dkim'),spf=value('row/policy_evaluated/spf'),header_from=value('identifiers/header_from')))
    if root.tag!='feedback':raise ValueError('Expected DMARC feedback XML.')
    return dict(sha256=digest(read_file(path)),organization=root.findtext('report_metadata/org_name'),report_id=root.findtext('report_metadata/report_id'),policy_domain=root.findtext('policy_published/domain'),rows=rows,total_messages=sum(r['count'] for r in rows),note='Aggregate-report claims; failures may be caused by forwarding or misconfiguration, not necessarily spoofing.')


def candidates(first,last,domain):
    domain=domain_name(domain)
    first,last=first.strip().lower(),last.strip().lower()
    if not re.fullmatch('[a-z]{1,50}',first) or not re.fullmatch('[a-z]{1,50}',last):raise ValueError('Use ASCII first/last names of 1–50 letters.')
    locals={first,last,first+'.'+last,first+last,first[0]+last,first+'_'+last,last+'.'+first,first+last[0]}
    return {'candidates':[{'email':x+'@'+domain,'status':'unverified_guess'} for x in sorted(locals)]}


def lookalikes(domain):
    domain=domain_name(domain); label,_,rest=domain.partition('.')
    result=set()
    for i in range(len(label)):
        if len(label)>1:result.add(label[:i]+label[i+1:])
        if i+1<len(label):result.add(label[:i]+label[i+1]+label[i]+label[i+2:])
    for a,b in [('m','rn'),('l','1'),('o','0'),('i','l')]:
        if a in label:result.add(label.replace(a,b))
    result.discard(label)
    return dict(domain=domain,candidates=[x+'.'+rest for x in sorted(result) if x and rest],status='unregistered_unqueried_candidates',note='Heuristic typos, not a complete Unicode confusable analysis; no malicious intent or registration inferred.')
