import json
from pathlib import Path
from . import analysis as a
from . import workflows as w
from .core import encoded,now


def add(sub):
    p=sub.add_parser('budget');p.add_argument('provider',choices=['hibp','emailrep','hunter','pgp','rdap','wayback']);p.add_argument('--max-requests',type=int,required=True);p.add_argument('--cost-per-request',type=float,default=0)
    p=sub.add_parser('usage')
    p=sub.add_parser('archive');p.add_argument('url');p.add_argument('--limit',type=int,default=3);p.add_argument('--case',required=True)
    p=sub.add_parser('auth');p.add_argument('domain');p.add_argument('--case',required=True)
    p=sub.add_parser('dkim');p.add_argument('file');p.add_argument('--case',required=True)
    p=sub.add_parser('blocklist');p.add_argument('ip');p.add_argument('--zone',required=True);p.add_argument('--case',required=True)
    p=sub.add_parser('watch');p.add_argument('email');p.add_argument('--case',required=True);p.add_argument('--interval',type=int,default=86400);p.add_argument('--profile',choices=['offline','passive'],default='offline')
    p=sub.add_parser('run-due');p.add_argument('--limit',type=int,default=10)
    p=sub.add_parser('watches')
    p=sub.add_parser('disable-watch');p.add_argument('id')
    p=sub.add_parser('accounts');p.add_argument('tool',choices=['ghunt','holehe']);p.add_argument('email');p.add_argument('--case',required=True)
    for name in ('mailbox','extract','dmarc','import-claims'):
        p=sub.add_parser(name);p.add_argument('file');p.add_argument('--case',required=True)
        if name=='mailbox':p.add_argument('--query')
    p=sub.add_parser('candidates');p.add_argument('--first',required=True);p.add_argument('--last',required=True);p.add_argument('--domain',required=True);p.add_argument('--case',required=True)
    p=sub.add_parser('lookalikes');p.add_argument('domain');p.add_argument('--case',required=True)
    for name in ('insights','health'):
        p=sub.add_parser(name)
        if name=='insights':p.add_argument('--case',required=True)
    p=sub.add_parser('graph');p.add_argument('--case',required=True);p.add_argument('--out',required=True)
    p=sub.add_parser('compare');p.add_argument('--case',required=True);p.add_argument('--before',required=True);p.add_argument('--after',required=True)
    p=sub.add_parser('redact');p.add_argument('--case',required=True);p.add_argument('--out',required=True);p.add_argument('--terms-file')
    p=sub.add_parser('review');p.add_argument('--case',required=True);p.add_argument('--run',required=True);p.add_argument('--reviewer',required=True);p.add_argument('--decision',choices=['needs-evidence','accepted','rejected','unresolved'],required=True);p.add_argument('--note',required=True)
    p=sub.add_parser('removal');p.add_argument('--case',required=True);p.add_argument('--email',required=True);p.add_argument('--source',required=True);p.add_argument('--status',choices=['identified','requested','removed','still-visible','unverified'],required=True);p.add_argument('--note',required=True)
    p=sub.add_parser('lookup');p.add_argument('provider',choices=['hunter-search','hunter-verify','pgp','rdap']);p.add_argument('value');p.add_argument('--case',required=True)
    p=sub.add_parser('batch');p.add_argument('file');p.add_argument('--case',required=True);p.add_argument('--profile',choices=['offline','passive'],default='offline');p.add_argument('--max-items',type=int,default=100)
    p=sub.add_parser('patterns');p.add_argument('file');p.add_argument('--case',required=True)
    p=sub.add_parser('bundle');p.add_argument('--case',required=True);p.add_argument('--out',required=True)


COMMANDS={'budget','usage','archive','auth','dkim','blocklist','watch','run-due','watches','disable-watch','accounts','mailbox','extract','dmarc','import-claims','candidates','lookalikes','insights','graph','compare','redact','review','removal','lookup','health','batch','patterns','bundle'}

def run(args,store):
    command=args.command
    if hasattr(args,'case'):store.case(args.case)
    indicator=getattr(args,'file',getattr(args,'domain',getattr(args,'value','case-analysis')))
    if command=='budget':
        import math
        if not 1<=args.max_requests<=100000 or not math.isfinite(args.cost_per_request) or args.cost_per_request<0:raise ValueError('Use max requests 1–100000 and finite nonnegative unit cost.')
        with store.db:store.db.execute('INSERT OR REPLACE INTO budgets VALUES (?,?,?)',(args.provider,args.max_requests,args.cost_per_request))
        print('Budget set for rolling 24 hours. Cost is a user-supplied estimate, not a provider invoice.');return 0
    elif command=='usage':
        import time
        rows=store.db.execute('SELECT requests.provider,COUNT(*) AS reserved_requests,COALESCE(budgets.cost_per_request,0) AS unit_cost FROM requests LEFT JOIN budgets ON requests.provider=budgets.provider WHERE requested_at>? GROUP BY requests.provider',(time.time()-86400,)).fetchall()
        print(encoded({'rolling_24h':[dict(r,estimated_cost=r['reserved_requests']*r['unit_cost']) for r in rows],'note':'Counts local request reservations, including subsequent failures; not provider-confirmed billing. Shared data directory only.'}).decode());return 0
    elif command=='archive':
        from .archive import collect
        f=collect(args.url,args.limit,store)
        rid=store.save(args.case,args.url,'page','explicit-network',[f]);print('Saved run:',rid);print(encoded(f).decode())
        return 0 if f['status'] in ('observed','not_found') else 2
    elif command in ('auth','dkim','blocklist'):
        from .auth import extended,verify_dkim,blocklist
        data=extended(args.domain) if command=='auth' else (verify_dkim(args.file) if command=='dkim' else blocklist(args.ip,args.zone))
    elif command=='watch':
        from .monitor import create
        print(create(store,args.case,args.email,args.interval,args.profile));return 0
    elif command in ('run-due','watches','disable-watch'):
        from .monitor import setup,due
        setup(store)
        if command=='run-due':print(encoded(due(store,args.limit)).decode())
        elif command=='watches':print(encoded([dict(r) for r in store.db.execute('SELECT * FROM watches')]).decode())
        else:
            with store.db:
                cursor=store.db.execute('UPDATE watches SET enabled=0 WHERE id=?',(args.id,))
                if cursor.rowcount!=1:raise ValueError('Unknown watch ID.')
            print('Disabled:',args.id)
        return 0
    elif command=='accounts':
        from .external import execute
        f=execute(args.tool,args.email)
        rid=store.save(args.case,args.email,'email','explicit-external',[f]);print('Saved run:',rid);print(encoded(f).decode())
        return 0 if f['status']=='observed' else 2
    elif command=='mailbox':data=a.mailbox_analysis(args.file,args.query)
    elif command=='extract':data=a.extract(args.file)
    elif command=='dmarc':data=a.dmarc(args.file)
    elif command=='import-claims':data=w.import_claims(args.file)
    elif command=='candidates':data=a.candidates(args.first,args.last,args.domain)
    elif command=='lookalikes':data=a.lookalikes(args.domain)
    elif command=='insights':print(encoded(w.insights(store.runs(args.case))).decode());return 0
    elif command=='health':
        from .providers import health
        print(encoded(health(store)).decode());return 0
    elif command=='graph':print(w.graph(store.runs(args.case),args.out));return 0
    elif command=='compare':print(encoded(w.compare(store.runs(args.case),args.before,args.after)).decode());return 0
    elif command=='redact':print(w.redacted_report(store,args.case,args.out,args.terms_file));return 0
    elif command=='review':
        if args.run not in {r['id'] for r in store.runs(args.case)}:raise ValueError('Review must reference a run in this case.')
        if not args.reviewer.strip() or not args.note.strip():raise ValueError('Reviewer and note cannot be empty.')
        data=dict(run=args.run,reviewer=args.reviewer,decision=args.decision,note=args.note,at=now(),limitation='Self-declared analyst identity; no multi-user authentication or approval enforcement.')
    elif command=='removal':
        info=a.identity(args.email)
        if not info:raise ValueError('Invalid email.')
        data=dict(email=info['email'],source=args.source,status=args.status,note=args.note,at=now(),limitation='Manual status log; no removal message sent and no automatic visibility check.')
    elif command=='lookup':
        from .providers import lookup
        f=lookup(args.provider,args.value,store)
        rid=store.save(args.case,args.value,'provider','explicit-external',[f]);print('Saved run:',rid);print(encoded(f).decode())
        return 0 if f['status'] in ('observed','not_found') else 2
    elif command=='batch':
        from .modules import run_modules,email_info
        if not 1<=args.max_items<=1000:raise ValueError('max-items must be 1–1000.')
        values=list(dict.fromkeys(x.strip() for x in a.read_file(args.file).decode().splitlines() if x.strip()))
        if len(values)>args.max_items:raise ValueError('Input exceeds max-items; nothing was queried.')
        for value in values:email_info(value)
        code=0
        for value in values:
            fs=run_modules('email',value,['syntax','disposable']+(['dns'] if args.profile=='passive' else []),args.profile,store)
            rid=store.save(args.case,value,'email',args.profile,fs);print(value,rid)
            if any(f['status'] in ('error','partial') for f in fs):code=2
        return code
    elif command=='patterns':
        import csv,io
        rows=list(csv.DictReader(io.StringIO(a.read_file(args.file).decode())))
        observations=[]
        for row in rows:
            if not {'first','last','email'}.issubset(row):raise ValueError('CSV needs first,last,email headers.')
            info=a.identity(row['email'])
            if not info:raise ValueError('Invalid email in CSV.')
            first,last=row['first'].lower(),row['last'].lower()
            candidates=a.candidates(first,last,info['domain'])['candidates']
            local=info['email'].split('@')[0]
            formats={first:'first',last:'last',first+'.'+last:'first.last',first+last:'firstlast',first[0]+last:'flast',first+'_'+last:'first_last',last+'.'+first:'last.first',first+last[0]:'firstl'}
            observations.append({'email':info['email'],'domain':info['domain'],'matching_pattern':formats.get(local,'unmatched'),'confidence':'matches_supplied_name_and_address'})
        data={'observations':observations,'note':'Requires known names; a matching pattern does not confirm other generated addresses.'}
    elif command=='bundle':
        from .reports import report
        import zipfile,hashlib,platform,importlib.metadata
        import tempfile
        dest=Path(args.out)
        if dest.exists():raise ValueError('Bundle output already exists.')
        with tempfile.TemporaryDirectory() as t:
            folder=Path(t)/'evidence';report(store,args.case,folder)
            (folder/'insights.json').write_bytes(encoded(w.insights(store.runs(args.case))))
            (folder/'environment.json').write_bytes(encoded({'mailintel':'1.4.0','python':platform.python_version(),'dependencies':{x:importlib.metadata.version(x) for x in ('httpx','dnspython','email-validator')},'note':'Stored evidence only; original source files are not included automatically.'}))
            files=list(folder.iterdir())
            (folder/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
            with zipfile.ZipFile(dest,'x',zipfile.ZIP_DEFLATED) as z:
                for p in folder.iterdir():z.write(p,p.name)
        print(dest.resolve());return 0
    else:raise ValueError('Unknown advanced command.')
    status='observed'
    if command=='auth' and (data['records']['status'] in ('error','partial') or data.get('mta_sts_policy',{}).get('status')=='unknown'):status='partial'
    if command=='dkim' and data.get('status')=='unknown':status='partial'
    if command=='blocklist' and data['response']['status'] in ('timeout','error'):status='partial'
    rid=store.save(args.case,str(indicator),command,'explicit-network' if command in ('auth','dkim','blocklist') else 'offline',[w.finding(command,data,status)])
    print('Saved run:',rid);print(encoded(data).decode());return 2 if status=='partial' else 0
