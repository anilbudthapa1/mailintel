"""Bounded public archive collection for one explicitly supplied page URL."""
import hashlib
import json
import re
from urllib.parse import urlsplit,quote
from .analysis import EMAIL,identity
from .workflows import finding


def collect(url,limit,store):
    import httpx
    parts=urlsplit(url)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password or '*' in url:
        raise ValueError('Supply one HTTP(S) page URL without credentials or wildcards.')
    if not 1<=limit<=3:raise ValueError('Archive limit must be 1–3 snapshots.')
    wait=store.reserve('wayback',10)
    if wait:return finding('archive',{'retry_after_seconds':wait},'rate_limited','Local archive cooldown.')
    def fetch(client,target,params=None):
        with client.stream('GET',target,params=params) as r:
            if r.status_code!=200:raise ValueError('HTTP '+str(r.status_code))
            raw=bytearray()
            for c in r.iter_bytes():
                raw.extend(c)
                if len(raw)>2*1024*1024:raise ValueError('Archive response exceeds 2 MiB')
            return bytes(raw)
    snapshots=[]
    try:
        with httpx.Client(timeout=20,trust_env=False,follow_redirects=False) as client:
            index=fetch(client,'https://web.archive.org/cdx/search/cdx',{'url':url,'matchType':'exact','output':'json','fl':'timestamp,original','filter':'statuscode:200','collapse':'timestamp:6','limit':str(limit)})
            rows=json.loads(index)
            if not rows:return finding('archive',{'snapshots':[]},'not_found','No archive records returned; not proof the address was never published.')
            if not isinstance(rows,list) or rows[0]!=['timestamp','original']:raise ValueError('Unsupported archive index schema.')
            for row in rows[1:limit+1]:
                if not isinstance(row,list) or len(row)!=2 or not all(isinstance(x,str) for x in row):raise ValueError('Unsupported archive row.')
                timestamp,original=row
                if not re.fullmatch(r'\d{14}',timestamp):raise ValueError('Unexpected capture timestamp.')
                if urlsplit(original).hostname!=parts.hostname:raise ValueError('Archive returned an out-of-host original URL.')
                target='https://web.archive.org/web/'+timestamp+'id_/'+quote(original,safe=':/?=&%')
                raw=fetch(client,target);text=raw.decode('utf-8',errors='replace')
                occurrences=[]
                for match in EMAIL.finditer(text):
                    info=identity(match.group().strip('.'))
                    if info:occurrences.append(dict(**info,context=text[max(0,match.start()-50):match.end()+50],location='archived page',source=target))
                snapshots.append({'timestamp':timestamp,'original':original,'archive_url':target,'sha256':hashlib.sha256(raw).hexdigest(),'observations':occurrences})
        changes=[]
        for previous,current in zip(snapshots,snapshots[1:]):
            old={o['email'] for o in previous['observations']};new={o['email'] for o in current['observations']}
            changes.append({'from':previous['timestamp'],'to':current['timestamp'],'added':sorted(new-old),'not_seen_in_later_snapshot':sorted(old-new)})
        return finding('archive',{'snapshots':snapshots,'publication_changes':changes,'note':'At most three early index snapshots, collapsed by month; not comprehensive history. Missing occurrence may reflect capture/extraction differences, not removal or job change.'})
    except (httpx.HTTPError,ValueError,UnicodeError):return finding('archive',{'snapshots':snapshots},'partial' if snapshots else 'error','Archive network/schema failure; no retry or redirect. Saved any already collected evidence.')
