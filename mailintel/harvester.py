"""Import structured theHarvester results; optionally invoke an installed CLI."""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from .modules import domain_name, observation

UPSTREAM = 'https://github.com/laramies/theHarvester'
PIN = '78a78f08d4a0d6d9bf6058effa8ddafb9e2d070b'


def load_result(path, expected_domain):
    path = Path(path)
    if path.stat().st_size > 10_000_000:
        raise ValueError('Import exceeds 10 MB.')
    raw = path.read_bytes()
    records = []
    if path.suffix == '.jsonl':
        lines = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if not lines or not isinstance(lines[0], dict) or lines[0].get('type') != 'summary':
            raise ValueError('JSONL must begin with a theHarvester summary record.')
        for obj in lines[1:]:
            if not isinstance(obj, dict):
                raise ValueError('Expected JSON objects.')
            if obj.get('type') in ('email', 'hostname', 'ip') and isinstance(obj.get('value'), str):
                records.append({k: obj[k] for k in ('type', 'value', 'sources') if k in obj})
    else:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or not any(k in obj for k in ('emails', 'hosts', 'hostnames', 'ips')):
            raise ValueError('Unsupported theHarvester JSON. Prefer JSONL export.')
        for key, kind in [('emails', 'email'), ('hosts', 'hostname'), ('hostnames', 'hostname'), ('ips', 'ip')]:
            if not isinstance(obj.get(key, []), list):
                raise ValueError('Expected list in theHarvester JSON.')
            for value in obj.get(key, []):
                if isinstance(value, str):
                    records.append({'type': kind, 'value': value, 'sources': ['theHarvester import']})
    # Retain addresses/hosts for the requested domain only. IP ownership cannot
    # be inferred from a standalone IP value, so omit IP-only observations.
    selected = []
    for item in records:
        value = item['value']
        try:
            host = domain_name(value.rsplit('@', 1)[-1] if item['type'] == 'email' else value)
        except ValueError:
            continue
        if item['type'] != 'ip' and (host == expected_domain or host.endswith('.' + expected_domain)):
            selected.append(item)
    return observation('theharvester', 'observed',
        'Imported discovery evidence, not proof of current ownership. Out-of-domain and standalone IP records omitted.',
        {'findings': selected, 'input_sha256': hashlib.sha256(raw).hexdigest(),
         'format': path.suffix, 'evidence_origin': 'local import; collection method not independently verified'}, UPSTREAM)


def execute(domain, sources):
    allowed = {'crtsh', 'certspotter', 'hunter'}
    if not sources or not set(sources).issubset(allowed):
        raise ValueError('Allowed theHarvester sources: crtsh,certspotter,hunter. Hunter needs upstream API configuration.')
    binary = shutil.which('theHarvester')
    if binary is None:
        return observation('theharvester', 'not_configured',
                           'Install theHarvester separately using setup-harvester.sh, or use import-harvester.', source=UPSTREAM)
    with tempfile.TemporaryDirectory(prefix='mailintel-') as temp:
        output = str(Path(temp) / 'result')
        command = [binary, '-d', domain, '-b', ','.join(sources), '-l', '100', '-f', output]
        # Argument array, never shell=True. Do not keep console logs or forward API keys.
        env = {k: v for k, v in os.environ.items() if k not in ('HIBP_API_KEY', 'EMAILREP_API_KEY')}
        proc = subprocess.Popen(command, cwd=temp, env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            rc = proc.wait(timeout=180)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            if isinstance(exc, KeyboardInterrupt):
                raise
            return observation('theharvester', 'error', 'Timed out after 180 seconds; process group stopped.', source=UPSTREAM)
        if rc:
            return observation('theharvester', 'error', f'theHarvester exited with status {rc}. Check its independent configuration.', source=UPSTREAM)
        candidates = [Path(output + ext) for ext in ('.jsonl', '.json')]
        path = next((p for p in candidates if p.is_file()), None)
        if path is None:
            return observation('theharvester', 'error', 'No supported output file was produced.', source=UPSTREAM)
        result = load_result(path, domain)
        result['interaction'] = 'third_party_lookup'
        result['data']['command'] = command[:-1] + ['<temporary-output>']
        result['data']['evidence_origin'] = 'installed theHarvester; version managed by operator'
        return result
