"""Bounded DNS configuration investigation, not a full SMTP policy evaluator."""
from .modules import query_dns,domain_name,dns_check


def inspect(domain):
    import dns.resolver
    resolver=dns.resolver.Resolver();domain=domain_name(domain)
    base=dns_check(domain,resolver=resolver)
    seen=set(); chain=[];budget=[0]
    def visit(name):
        if name in seen:
            chain.append({'domain':name,'status':'already_visited_or_cycle'});return
        if budget[0]>=10:
            chain.append({'domain':name,'status':'local_query_budget_exhausted'});return
        seen.add(name);budget[0]+=1
        result=query_dns(name,'TXT',resolver)
        records=[x for x in result['records'] if x.lower().startswith('v=spf1')]
        chain.append({'domain':name,'dns_status':result['status'],'spf':records})
        for record in records:
            for term in record.split()[1:]:
                clean=term.lstrip('+-~?')
                if clean.startswith('include:') or clean.startswith('redirect='):
                    child=clean.split(':',1)[1] if clean.startswith('include:') else clean.split('=',1)[1]
                    if '%' in child:
                        chain.append({'domain':name,'status':'macro_not_expanded','term':term});continue
                    try:child=domain_name(child)
                    except ValueError:
                        chain.append({'domain':name,'status':'invalid_reference','term':term});continue
                    visit(child)
    visit(domain)
    mx=query_dns(domain,'MX',resolver);missing=[]
    for record in mx['records'][:20]:
        target=record.split()[-1].rstrip('.')
        if not target:continue
        a=query_dns(target,'A',resolver);aaaa=query_dns(target,'AAAA',resolver)
        missing.append({'mx':target,'A':a,'AAAA':aaaa,'potential_missing_destination':all(x['status'] in ('nxdomain','no_answer') for x in (a,aaaa))})
    return {'records':base,'spf_reference_chain':chain,'mx_destinations':missing,'limitations':'SPF include/redirect traversal only: not SMTP sender evaluation, complete DNS-lookup counting, macro expansion, organizational DMARC fallback or proof of a claimable/dangling service. Query errors remain unknown.'}


def blocklist(ip,zone):
    import ipaddress,dns.resolver
    address=ipaddress.ip_address(ip);zone=domain_name(zone)
    if address.version!=4:raise ValueError('This release supports IPv4 DNSBL queries only.')
    query='.'.join(reversed(str(address).split('.')))+'.'+zone
    result=query_dns(query,'A',dns.resolver.Resolver())
    return {'ip':str(address),'zone':zone,'response':result,'note':'Interpret return codes using this zone owner documentation. A DNS answer may indicate a resolver/access error, not a listing. IP reputation is not email-owner reputation.'}


def verify_dkim(path):
    from .analysis import read_file
    try:import dkim
    except ImportError:raise ValueError('Optional dkimpy is required: .venv/bin/python -m pip install dkimpy')
    import dns.resolver
    raw=read_file(path)
    resolver=dns.resolver.Resolver()
    errors=[]
    def dnsfunc(name,timeout=5):
        result=query_dns(name.decode().rstrip('.'),'TXT',resolver)
        if result['status'] not in ('observed','no_answer','nxdomain'):errors.append(result['status'])
        return result['records'][0].encode() if result['records'] else None
    if b'dkim-signature:' not in raw.lower().split(b'\r\n\r\n')[0] and b'dkim-signature:' not in raw.lower().split(b'\n\n')[0]:return {'status':'unsigned'}
    try:valid=dkim.verify(raw,dnsfunc=dnsfunc)
    except Exception as exc:return {'status':'unknown','reason':'Signature parsing/verification failed: '+type(exc).__name__}
    return {'status':'unknown' if errors else ('valid' if valid else 'not_verified'),'dns_errors':errors,'note':'Checks the first signature using current DNS keys. Missing/rotated historical keys or message changes can prevent verification. Valid DKIM does not prove sender identity or benign content.'}


def extended(domain):
    import io,json
    from importlib.resources import files
    import publicsuffix2
    import dns.resolver
    import httpx
    domain=domain_name(domain);result=inspect(domain)
    raw=files('mailintel').joinpath('data/public_suffix_list.dat').read_text()
    psl=publicsuffix2.PublicSuffixList(io.StringIO(raw))
    org=psl.get_sld(domain,strict=True)
    resolver=dns.resolver.Resolver()
    direct=query_dns('_dmarc.'+domain,'TXT',resolver)
    fallback=None
    direct_dmarc=[x for x in direct['records'] if x.lower().startswith('v=dmarc1')]
    if not direct_dmarc and direct['status'] in ('observed','no_answer','nxdomain') and org and org!=domain:
        fallback=query_dns('_dmarc.'+org,'TXT',resolver)
    result['dmarc_lookup']={'domain':domain,'direct':direct,'organizational_domain':org,'fallback':fallback,'psl':json.loads(files('mailintel').joinpath('data/psl_metadata.json').read_text()),'note':'Legacy organizational-domain fallback using bundled PSL; records collected, not full message alignment or all newer DMARC semantics.'}
    try:
        with httpx.Client(timeout=15,follow_redirects=False,trust_env=False) as client:
            with client.stream('GET','https://mta-sts.'+domain+'/.well-known/mta-sts.txt') as r:
                policy=bytearray()
                for chunk in r.iter_bytes():
                    policy.extend(chunk)
                    if len(policy)>65536:raise ValueError('Policy exceeds 64 KiB')
                fields={}
                if r.status_code==200:
                    for line in policy.decode('utf-8').splitlines():
                        if ':' in line:
                            k,v=line.split(':',1);fields.setdefault(k.strip(),[]).append(v.strip())
                result['mta_sts_policy']={'http_status':r.status_code,'fields':fields,'note':'TLS certificate checked by HTTP client; redirects not followed. This is policy collection, not full MX pattern enforcement.'}
    except (httpx.HTTPError,ValueError,UnicodeError):result['mta_sts_policy']={'status':'unknown','note':'Network, TLS or policy parsing failure; not evidence of absence.'}
    return result
