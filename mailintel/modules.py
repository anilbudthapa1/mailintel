"""Explicit modules. External services only run when individually selected."""
import hashlib
import json
import os
import re
from importlib.resources import files
from urllib.parse import quote

from email_validator import validate_email, EmailNotValidError

REGISTRY = {
    'syntax': ('local', 'Email syntax and IDNA normalization'),
    'disposable': ('local', 'Bundled versioned domain dataset'),
    'dns': ('dns', 'MX, SPF, DMARC, MTA-STS TXT, TLS-RPT, optional DKIM selector'),
    'hibp': ('api', 'Have I Been Pwned breach metadata; HIBP_API_KEY required'),
    'emailrep': ('api', 'EmailRep reputation; EMAILREP_API_KEY optional'),
}


def observation(module, status, detail, data=None, source=None):
    return {'module': module, 'status': status, 'detail': detail,
            'interaction': REGISTRY.get(module, ('import',))[0],
            'data': data or {}, 'source': source}


def domain_name(value):
    value = value.rstrip('.')
    try:
        value = value.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Invalid international domain name.') from None
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels
    ):
        raise ValueError('Use a domain such as example.com, without a URL or port.')
    return value


def email_info(value):
    try:
        info = validate_email(value, check_deliverability=False, test_environment=True)
    except EmailNotValidError as e:
        raise ValueError(str(e)) from None
    # Preserve local-part case, dots and plus-tags. Never guess provider aliases.
    return info.normalized, domain_name(info.ascii_domain), info.smtputf8


def disposable(domain):
    data = files('mailintel').joinpath('data')
    raw = data.joinpath('disposable.txt').read_bytes()
    domains = set(raw.decode().splitlines())
    labels = domain.split('.')
    matches = ['.'.join(labels[i:]) for i in range(len(labels)-1) if '.'.join(labels[i:]) in domains]
    meta = json.loads(data.joinpath('dataset.json').read_text())
    return observation('disposable', 'listed' if matches else 'not_listed',
        'List membership is not a judgment of the person or proof of mailbox status.',
        {'matches': matches, 'dataset': meta, 'sha256': hashlib.sha256(raw).hexdigest()}, meta['source'])


def query_dns(name, rrtype, resolver):
    import dns.exception
    import dns.resolver
    try:
        answer = resolver.resolve(name, rrtype, lifetime=5)
        values = []
        for item in answer:
            if rrtype == 'TXT':
                values.append(b''.join(item.strings).decode('utf-8', 'replace'))
            else:
                values.append(item.to_text())
        return {'status': 'observed', 'records': values, 'ttl': answer.rrset.ttl}
    except dns.resolver.NXDOMAIN:
        return {'status': 'nxdomain', 'records': []}
    except dns.resolver.NoAnswer:
        return {'status': 'no_answer', 'records': []}
    except dns.exception.Timeout:
        return {'status': 'timeout', 'records': []}
    except dns.exception.DNSException:
        return {'status': 'error', 'records': []}


def dns_check(domain, selector=None, resolver=None):
    import dns.resolver
    resolver = resolver or dns.resolver.Resolver()
    queries = {'mx': (domain, 'MX'), 'spf': (domain, 'TXT'),
               'dmarc': ('_dmarc.' + domain, 'TXT'),
               'mta_sts': ('_mta-sts.' + domain, 'TXT'),
               'tls_rpt': ('_smtp._tls.' + domain, 'TXT')}
    if selector:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', selector):
            raise ValueError('DKIM selector must be a single label of 1 to 63 letters, numbers, _ or -.')
        queries['dkim'] = (selector + '._domainkey.' + domain, 'TXT')
    results = {key: query_dns(*args, resolver) for key, args in queries.items()}
    prefixes = {'spf': 'v=spf1', 'dmarc': 'v=dmarc1;', 'mta_sts': 'v=stsv1;', 'tls_rpt': 'v=tlsrptv1;'}
    for key, prefix in prefixes.items():
        results[key]['policy_records'] = [r for r in results[key]['records'] if r.lower().startswith(prefix)]
        results[key]['multiple_policy_records'] = len(results[key]['policy_records']) > 1
    results['mx']['null_mx'] = '0 .' in results['mx']['records']
    if results['mx']['status'] == 'no_answer':
        results['a_fallback'] = query_dns(domain, 'A', resolver)
        results['aaaa_fallback'] = query_dns(domain, 'AAAA', resolver)
    errors = any(v['status'] in ('timeout', 'error') for v in results.values())
    return observation('dns', 'partial' if errors else 'observed',
        'DNS observations only; no mailbox, signature or policy-compliance verification. '
        'DKIM requires a known selector. DMARC organizational-domain fallback is not evaluated. '
        'MTA-STS HTTPS policy is not fetched.', results, 'System DNS resolver')


def http_json(url, headers):
    import httpx
    # No redirects and no environment proxies: prevent API key forwarding.
    with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
        with client.stream('GET', url, headers=headers) as response:
            chunks = bytearray()
            for chunk in response.iter_bytes():
                chunks.extend(chunk)
                if len(chunks) > 2_000_000:
                    raise ValueError('Provider response exceeds 2 MB limit.')
            return response.status_code, dict(response.headers), bytes(chunks)


def api_check(module, email, store, fetch=http_json):
    source = 'https://haveibeenpwned.com/' if module == 'hibp' else 'https://emailrep.io/'
    headers = {'User-Agent': 'MailIntel/1.4.0', 'Accept': 'application/json'}
    key = os.environ.get('HIBP_API_KEY' if module == 'hibp' else 'EMAILREP_API_KEY', '')
    if module == 'hibp':
        if not key:
            return observation(module, 'not_configured', 'Set HIBP_API_KEY to enable this module.', source=source)
        if not re.fullmatch(r'[a-fA-F0-9]{32}', key):
            return observation(module, 'error', 'HIBP_API_KEY must be 32 hexadecimal characters.', source=source)
        headers['hibp-api-key'] = key
        url = source + 'api/v3/breachedAccount/' + quote(email, safe='') + '?truncateResponse=false'
    else:
        if key:
            headers['Key'] = key
        url = source + quote(email, safe='')
    wait = store.reserve(module)
    if wait:
        return observation(module, 'rate_limited', f'Local cooldown: retry after {wait} seconds.', source=source)
    try:
        code, response_headers, raw = fetch(url, headers)
        if code == 429:
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone
            value = response_headers.get('retry-after', '60')
            try:
                delay = max(1, int(value))
            except ValueError:
                try:
                    delay = max(1, int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()))
                except (TypeError, ValueError, OverflowError):
                    delay = 60
            store.cooldown(module, delay)
            return observation(module, 'rate_limited', f'Provider requests retry after {delay} seconds. No retry sent.', source=source)
        if module == 'hibp' and code == 404:
            return observation(module, 'not_found', 'No exposure returned by this provider; not proof of no exposure.', {'http_status': code}, source)
        if code != 200:
            return observation(module, 'error', f'Provider HTTP {code}; not a negative finding.', {'http_status': code}, source)
        obj = json.loads(raw)
        if module == 'hibp':
            if not isinstance(obj, list) or not all(isinstance(x, dict) and isinstance(x.get('Name'), str) for x in obj):
                raise ValueError('Unexpected HIBP response schema.')
            allow = ('Name', 'Title', 'Domain', 'BreachDate', 'DataClasses', 'IsVerified', 'IsFabricated', 'IsSpamList')
            result = {'breaches': [{k: x[k] for k in allow if k in x} for x in obj]}
        else:
            if not isinstance(obj, dict) or obj.get('reputation') not in ('high', 'medium', 'low', 'none'):
                raise ValueError('Unexpected EmailRep response schema.')
            result = {k: obj[k] for k in ('reputation', 'suspicious', 'references', 'details') if k in obj}
        # Record selected response data, not raw bodies or headers that might contain secrets.
        result['response_sha256'] = hashlib.sha256(raw).hexdigest()
        result['http_status'] = code
        return observation(module, 'observed', 'Provider observation; independently verify conclusions.', result, source)
    except Exception:
        # Exception text can contain identifiers, keys, proxy URLs or response bodies.
        return observation(module, 'error', 'Network failure, oversized response or unexpected provider schema.', source=source)


def run_modules(kind, value, modules, profile, store, selector=None):
    if kind == 'email':
        normal, domain, utf8 = email_info(value)
    else:
        domain = normal = domain_name(value)
        utf8 = False
    if not modules or len(modules) != len(set(modules)):
        raise ValueError('Select at least one module, without duplicates.')
    unknown = set(modules) - set(REGISTRY)
    if unknown:
        raise ValueError('Unknown modules: ' + ', '.join(sorted(unknown)))
    if kind != 'email' and set(modules) & {'hibp', 'emailrep'}:
        raise ValueError('HIBP and EmailRep require an email input.')
    if profile == 'offline' and any(REGISTRY[m][0] != 'local' for m in modules):
        raise ValueError('Offline profile permits only syntax and disposable modules.')
    out = []
    for module in modules:
        if module == 'syntax':
            out.append(observation(module, 'valid_syntax', 'Syntax only; does not verify deliverability or ownership.',
                {'normalised_value': normal, 'ascii_domain': domain, 'smtputf8': utf8}))
        elif module == 'disposable':
            out.append(disposable(domain))
        elif module == 'dns':
            out.append(dns_check(domain, selector))
        else:
            out.append(api_check(module, normal, store))
    return out
