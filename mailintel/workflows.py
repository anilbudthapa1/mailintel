"""Append-only analyst workflow and derived case views."""
import csv
import hashlib
import html
import json
import re
from pathlib import Path
from .analysis import EMAIL, identity, read_file
from .core import encoded


def finding(module, data, status='observed', detail='Local analysis; review limitations in evidence.'):
    return dict(module=module,status=status,detail=detail,data=data,source=None)


def import_claims(path):
    """Uniform evidence exchange format, not an assertion that a provider was queried."""
    raw=read_file(path)
    try: data=json.loads(raw)
    except json.JSONDecodeError:raise ValueError('Claims input must be JSON.')
    if not isinstance(data,list) or len(data)>5000:raise ValueError('Expected a list of at most 5000 claims.')
    required={'email','provider','source','claim','value','observed_at'}
    for row in data:
        if not isinstance(row,dict) or not required.issubset(row):raise ValueError('Each claim needs email, provider, source, claim, value, observed_at.')
        if not all(isinstance(row[k],str) and len(row[k])<=4096 for k in required):raise ValueError('Claim fields must be strings of at most 4096 characters.')
        from datetime import datetime
        try:
            timestamp=datetime.fromisoformat(row['observed_at'].replace('Z','+00:00'))
            if timestamp.tzinfo is None:raise ValueError()
        except ValueError:raise ValueError('observed_at must be ISO 8601 with timezone.')
        info=identity(row['email'])
        if not info:raise ValueError('Invalid email in claims file.')
        row['email']=info['email']
        row['confidence']='imported_provider_claim'
        row.setdefault('upstream_source',None)
        if row['upstream_source'] is not None and not isinstance(row['upstream_source'],str):raise ValueError('upstream_source must be text or null.')
    return {'input_sha256':hashlib.sha256(raw).hexdigest(),'claims':data,'note':'Imported statements, not independently verified. Imported timestamps are supplied claims.'}


def insights(runs):
    addresses={}; claims=[]; signals=[]; docs=[]; breaches=[]; associations=[]
    for run in runs:
        for f in run['findings']:
            data=f.get('data',{})
            for address in set(EMAIL.findall(json.dumps(data,ensure_ascii=False)+' '+run['indicator'])):
                info=identity(address.strip('.'))
                if info:
                    item=addresses.setdefault(info['email'],dict(**info,evidence=[]))
                    item['evidence'].append({'run':run['id'],'module':f['module'],'status':f['status']})
            claims.extend(data.get('claims',[]))
            for breach in data.get('breaches',[]):
                if isinstance(breach,dict):breaches.append({'email':run['indicator'],'breach':breach,'run':run['id'],'confidence':'provider_claim'})
            upstream=data.get('upstream_result',{})
            if isinstance(upstream,dict):
                for account in upstream.get('accounts',[]):
                    if isinstance(account,dict):associations.append({'email':data.get('email',run['indicator']),'account':account,'run':run['id'],'confidence':'upstream_claim'})
            for snapshot in data.get('snapshots',[]):
                docs.extend(dict(o,capture_timestamp=snapshot.get('timestamp')) for o in snapshot.get('observations',[]))
            for m in data.get('messages',[]):
                for s in m.get('signals',[]):signals.append({'message':m['sha256'],'signal':s,'confidence':'heuristic_review_required'})
            docs.extend(data.get('observations',[]))
    grouped={}; source_groups={}
    for c in claims:
        grouped.setdefault((c['email'],c['claim']),[]).append(c)
        key=c.get('upstream_source') or c['source']
        source_groups.setdefault(key,set()).add(c['provider'])
    conflicts=[{'email':k[0],'claim':k[1],'observations':v,'note':'Values may reflect different dates or definitions; analyst review required.'} for k,v in grouped.items() if len({x['value'] for x in v})>1]
    timeline=sorted(claims,key=lambda x:x['observed_at'])
    return {'addresses':list(addresses.values()),'breach_timeline':sorted(breaches,key=lambda x:x['breach'].get('BreachDate','')),'account_associations':associations,'claim_timeline':timeline,'conflicts':conflicts,'signals':signals,
            'document_occurrences':docs,'shared_declared_sources':[{'source':k,'providers':sorted(v)} for k,v in source_groups.items() if len(v)>1],
            'source_independence_note':'Only identical declared sources are grouped. Unknown underlying sources remain unknown, not independent.',
            'completeness':{'has_evidence':bool(runs),'failed_or_unknown_modules':[{'run':r['id'],'module':f['module'],'status':f['status']} for r in runs for f in r['findings'] if f['status'] in ('error','partial','not_configured','rate_limited')],
                            'unresolved_claim_conflicts':len(conflicts),
                            'analyst_events':[f['data'] for r in runs for f in r['findings'] if f['module']=='review']}}


def graph(runs,out):
    """Standalone SVG/HTML, no javascript, no unescaped evidence labels."""
    dest=Path(out);dest.mkdir(parents=True,exist_ok=False,mode=0o700)
    data=insights(runs);nodes=data['addresses']
    targets={};edges=[]
    for n in nodes:
        target='domain: '+n['domain'];targets[target]='address domain';edges.append((n['email'],target,'syntax'))
    for b in data['breach_timeline']:
        target='breach: '+str(b['breach'].get('Name','unnamed'));targets[target]='provider claim';edges.append((b['email'],target,b['run']))
    for c in data['claim_timeline']:
        if c['claim'] in ('account','account_association'):
            target='claim: '+c['provider']+' / '+c['value'];targets[target]='imported claim';edges.append((c['email'],target,c['source']))
    for c in data['account_associations']:
        account=c['account']
        if str(account.get('exists')).lower()=='true' and str(account.get('rateLimit')).lower()!='true':
            target='account: '+str(account.get('name','unknown'));targets[target]='upstream claim';edges.append((c['email'],target,c['run']))
    ordered=sorted(targets);addresses=[n['email'] for n in nodes]
    height=max(200,70*max(len(nodes),len(ordered))+60)
    labels=[];lines=[]
    for i,target in enumerate(ordered):
        y=50+i*70
        label=target if len(target)<=37 else target[:34]+'…'
        labels.append(f'<g><title>{html.escape(target)} — {html.escape(targets[target])}</title><rect x="560" y="{y-20}" width="320" height="40" rx="8" fill="#d1ece3"/><text x="575" y="{y+5}">{html.escape(label)}</text></g>')
    for email,target,proof in edges:
        if email not in addresses:continue
        y=50+addresses.index(email)*70;dy=50+ordered.index(target)*70
        lines.append(f'<line x1="420" y1="{y}" x2="560" y2="{dy}" stroke="#81949c"><title>{html.escape(str(proof))}</title></line>')
    for i,n in enumerate(nodes):
        y=50+i*70;label=n['email'] if len(n['email'])<=45 else n['email'][:42]+'…'
        labels.append(f'<g><title>{html.escape(n["email"])}</title><rect x="20" y="{y-20}" width="400" height="40" rx="8" fill="#e3eaf5"/><text x="30" y="{y+5}">{html.escape(label)}</text></g>')
    data['graph_edges']=[{'email':email,'target':target,'evidence':proof} for email,target,proof in edges]
    svg=f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 {height}" role="img" aria-label="Email addresses and their domains">'+''.join(lines+labels)+'</svg>'
    (dest/'graph.svg').write_text(svg)
    (dest/'graph.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>MailIntel relationships</title><h1>Email evidence relationships</h1><p>Domain edges show syntax; breach/account edges are provider claims, not verified ownership. Hover over labels/edges for details. Evidence references are in graph.json.</p>'+svg)
    (dest/'graph.json').write_bytes(encoded(data))
    return str(dest.resolve())


def compare(runs,a,b):
    indexed={r['id']:r for r in runs}
    if a not in indexed or b not in indexed:raise ValueError('Both run IDs must belong to this case.')
    if (indexed[a]['kind'],indexed[a]['indicator'])!=(indexed[b]['kind'],indexed[b]['indicator']):raise ValueError('Compare runs for the same indicator and kind.')
    def flatten(obj,prefix=''):
        if isinstance(obj,dict):
            return {k:v for key,val in obj.items() for k,v in flatten(val,prefix+'/'+str(key)).items()}
        if isinstance(obj,list):return {k:v for i,val in enumerate(obj) for k,v in flatten(val,prefix+'/'+str(i)).items()}
        return {prefix:obj}
    x=flatten(indexed[a]['findings']);y=flatten(indexed[b]['findings'])
    return {'before':a,'after':b,'changes':[{'path':k,'before':x.get(k),'after':y.get(k)} for k in sorted(x.keys()|y.keys()) if x.get(k)!=y.get(k)],'note':'Structural differences; list reordering may appear as changes.'}


def redact(value, terms):
    # Pseudonymise email addresses and explicitly supplied secrets throughout all strings.
    mapping={};counter=[0]
    def replacement(m):
        address=m.group()
        if address not in mapping:
            counter[0]+=1;mapping[address]=f'[EMAIL-{counter[0]}]'
        return mapping[address]
    def walk(x):
        if isinstance(x,str):
            for term in sorted(terms,key=len,reverse=True):
                if term:x=x.replace(term,'[REDACTED]')
            return EMAIL.sub(replacement,x)
        if isinstance(x,list):return [walk(y) for y in x]
        if isinstance(x,dict):return {walk(k):walk(v) for k,v in x.items() if k not in ('body','payment_markers','sha256','input_sha256')}
        return x
    return walk(value)


def redacted_report(store,cid,out,terms_file=None):
    terms=read_file(terms_file).decode().splitlines() if terms_file else []
    data=redact({'case':store.case(cid),'runs':store.runs(cid)},terms)
    dest=Path(out);dest.mkdir(parents=True,exist_ok=False,mode=0o700)
    data['notice']='Redacted derivative, not original evidence. Email pseudonyms are local to this export. Review names, domains, headers and context manually before sharing. Hashes removed.'
    (dest/'redacted.json').write_bytes(encoded(data))
    (dest/'redacted.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'"><title>Redacted MailIntel report</title><h1>Redacted derivative — review before sharing</h1><pre>'+html.escape(json.dumps(data,indent=2,ensure_ascii=False))+'</pre>')
    return str(dest.resolve())
