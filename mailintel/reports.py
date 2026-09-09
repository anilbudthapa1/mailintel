import html
import json
from pathlib import Path
from .core import encoded


def report(store, cid, out):
    case, runs = store.case(cid), store.runs(cid)
    dest = Path(out).expanduser()
    # Fresh directory only: no silent overwrite of a prior report.
    dest.mkdir(parents=True, exist_ok=False, mode=0o700)
    bundle = {'schema_version': 1, 'case': case, 'runs': runs,
              'integrity_note': 'SHA256 covers the stored run payload, excluding its exported sha256 field. '
              'Detects accidental changes; not a digital signature against a database administrator.'}
    (dest / 'report.json').write_bytes(encoded(bundle))
    esc = html.escape
    cards = []
    count = sum(len(r['findings']) for r in runs)
    for r in runs:
        rows = []
        for f in r['findings']:
            source = f.get('source') or 'Local analysis'
            link = ('<a rel="noreferrer" href="' + esc(source, quote=True) + '">' + esc(source) + '</a>') if source.startswith('https://') else esc(source)
            rows.append('<section><h3>' + esc(f['module']) + ' <span>' + esc(f['status']) + '</span></h3><p>' + esc(f['detail']) + '</p><p>Source: ' + link + '</p><details><summary>Evidence</summary><pre>' + esc(json.dumps(f['data'], indent=2, ensure_ascii=False)) + '</pre></details></section>')
        cards.append('<article><h2>' + esc(r['indicator']) + '</h2><p>' + esc(r['created_at']) + ' · ' + esc(r['profile']) + '</p>' + ''.join(rows) + '<p class="hash">Run SHA256: ' + esc(r['sha256']) + '</p></article>')
    page = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>MailIntel case report</title><style>
body{font:16px/1.55 system-ui,sans-serif;color:#172838;background:#f0f3f5;margin:0;padding:32px}
main{max-width:960px;margin:auto}h1{font-size:32px}h2{font-size:23px;overflow-wrap:anywhere}
article{background:white;padding:28px;margin:24px 0;border:1px solid #ccd5dc}
section{border-top:1px solid #dde4e9;padding:12px 0}h3{font-size:18px}
span{font-size:13px;font-weight:500;background:#eaf1f4;padding:4px 8px;margin-left:8px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f8;padding:16px;font-size:13px}
a{color:#12617d}.hash{font:12px monospace;overflow-wrap:anywhere}footer{font-size:13px}
@media(max-width:600px){body{padding:16px}article{padding:16px}}@media print{body{background:white;padding:0}details{display:block}article{break-inside:auto}}
</style><main><p>MAILINTEL / CASE REPORT</p>'''
    page += '<h1>' + esc(case['name']) + '</h1><p>' + str(len(runs)) + ' runs · ' + str(count) + ' module results · Case ' + esc(cid) + '</p>'
    page += '<p>Discovery, DNS, reputation and breach exposure are separate observations. No mailbox ownership is established by these checks.</p>'
    page += ''.join(cards)
    page += '<footer>When present, breach information is sourced from <a href="https://haveibeenpwned.com/">Have I Been Pwned</a> under <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>. This report contains personal data; share appropriately.</footer></main></html>'
    (dest / 'report.html').write_text(page, encoding='utf-8')
    return dest.resolve()
