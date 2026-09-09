"""Explicit external adapters. One request per command; no hidden fallback or retry."""
import hashlib
import json
import os
from urllib.parse import quote
from .modules import domain_name,email_info
from .workflows import finding

CATALOG={
 'hunter-search':('HUNTER_API_KEY','https://hunter.io/api-documentation/v2','domain'),
 'hunter-verify':('HUNTER_API_KEY','https://hunter.io/api-documentation/v2','email'),
 'pgp':(None,'https://keys.openpgp.org/about/api/','email'),
 'rdap':(None,'https://about.rdap.org/','domain'),
}


def lookup(provider,value,store):
    import httpx
    env,source,kind=CATALOG[provider]
    value=domain_name(value) if kind=='domain' else email_info(value)[0]
    headers={'User-Agent':'MailIntel/1.4.0 (email investigation CLI)'};params={}
    if env:
        key=os.environ.get(env,'')
        if not key:return finding(provider,{},'not_configured',f'Set {env}; no request made.')
        if '\n' in key or '\r' in key:return finding(provider,{},'error','Invalid API key format.')
        headers['X-API-KEY']=key
    if provider.startswith('hunter-'):
        endpoint='domain-search' if provider=='hunter-search' else 'email-verifier'
        url='https://api.hunter.io/v2/'+endpoint
        params={'domain' if kind=='domain' else 'email':value}
        if kind=='domain':params['limit']=100
    elif provider=='pgp':url='https://keys.openpgp.org/vks/v1/by-email/'+quote(value,safe='')
    else:url='https://rdap.org/domain/'+quote(value,safe='')
    waiting=store.reserve('hunter' if provider.startswith('hunter-') else provider)
    if waiting:return finding(provider,{'retry_after_seconds':waiting},'rate_limited','Local provider cooldown; no request made.')
    try:
        with httpx.Client(timeout=20,follow_redirects=False,trust_env=False) as client:
            with client.stream('GET',url,headers=headers,params=params) as response:
                raw=bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw)>2*1024*1024:raise ValueError('Response exceeds 2 MiB.')
                status=response.status_code
                if status in (301,302,303,307,308):
                    return finding(provider,{'location':response.headers.get('location'),'http_status':status},'partial','Redirect recorded, not followed. For RDAP, use the registry link manually or import its response.')
                if status==429:
                    try: retry=max(6,min(86400,int(response.headers.get('Retry-After','60'))))
                    except ValueError:retry=60
                    store.cooldown('hunter' if provider.startswith('hunter-') else provider,retry)
                    return finding(provider,{'retry_after_seconds':retry},'rate_limited','Provider limit; no automatic retry.')
                if status==404 and provider=='pgp':return finding(provider,{},'not_found','No published key returned; not proof that no key exists.')
                if status!=200:return finding(provider,{'http_status':status},'error','Provider request failed; not negative evidence.')
                data={'response_sha256':hashlib.sha256(raw).hexdigest(),'source':source}
                if provider=='pgp':
                    keytext=raw.decode('utf-8')
                    if not keytext.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):raise ValueError('Unexpected key response.')
                    data.update(armored_public_key=keytext,note='Published key material; ownership not independently verified. Fingerprint parsing not implemented.')
                else:
                    parsed=json.loads(raw)
                    if not isinstance(parsed,dict):raise ValueError('Unexpected response shape.')
                    payload=parsed.get('data') if provider.startswith('hunter-') else parsed
                    if not isinstance(payload,dict):raise ValueError('Missing data object.')
                    if provider=='hunter-search':
                        emails=payload.get('emails')
                        if not isinstance(emails,list):raise ValueError('Missing emails list.')
                        data.update(pattern=payload.get('pattern'),emails=emails,note='Provider observations and confidence, not independently verified. At most 100 results; no automatic pagination.')
                    elif provider=='hunter-verify':
                        if 'status' not in payload:raise ValueError('Missing verifier status.')
                        data.update({k:payload.get(k) for k in ('status','result','score','regexp','gibberish','disposable','webmail','mx_records','smtp_server','smtp_check','accept_all','block','sources')})
                        data['note']='Verification can cause provider-side SMTP probing. Provider claims are not ownership proof; catch-all and uncertain outcomes remain distinct.'
                    else:data.update({k:payload.get(k) for k in ('ldhName','status','events','nameservers','notices')})
                return finding(provider,data,'observed','External provider observation; see source and limitations.')
    except (httpx.HTTPError,ValueError,UnicodeError):
        return finding(provider,{},'error','Network, response-size or schema failure. Request details and secrets omitted.')


def health(store):
    from .core import now
    from importlib.resources import files
    metadata=json.loads(files('mailintel').joinpath('data/dataset.json').read_text())
    latest={}
    for case in store.cases():
        for run in store.runs(case['id']):
            for f in run['findings']:
                if f['module'] not in latest or run['created_at']>latest[f['module']]['at']:
                    latest[f['module']]={'at':run['created_at'],'status':f['status']}
    return {'checked_at':now(),'keys':{k:bool(os.environ.get(k)) for k in ('HIBP_API_KEY','EMAILREP_API_KEY','HUNTER_API_KEY')},'latest_results':latest,'disposable_dataset':metadata,'note':'Key presence is not key validity. No billable health queries were sent. Subscription usage must be checked in provider dashboards.'}
