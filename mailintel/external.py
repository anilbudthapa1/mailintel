"""Opt-in upstream runners; tools and credentials are installed separately."""
import csv
import io
import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from .analysis import read_file
from .modules import email_info
from .workflows import finding


def execute(tool,email):
    email=email_info(email)[0]
    binary=shutil.which(tool)
    if not binary:return finding(tool,{},'not_configured',f'{tool} is not installed on PATH; see INTEGRATIONS.md.')
    with tempfile.TemporaryDirectory(prefix='mailintel-external-') as tmp:
        if tool=='ghunt':args=[binary,'email',email,'--json',str(Path(tmp)/'result.json')]
        elif tool=='holehe':args=[binary,email,'--csv','--no-color','--no-clear','--no-password-recovery','--timeout','10']
        else:raise ValueError('Unsupported external tool.')
        env={k:v for k,v in os.environ.items() if k not in ('HIBP_API_KEY','EMAILREP_API_KEY','HUNTER_API_KEY')}
        process=subprocess.Popen(args,cwd=tmp,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        try:code=process.wait(timeout=180)
        except (subprocess.TimeoutExpired,KeyboardInterrupt) as exc:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
            if isinstance(exc,KeyboardInterrupt):raise
            return finding(tool,{},'error','External tool exceeded 180 seconds; process group stopped.')
        if code:return finding(tool,{'exit_code':code},'error','Upstream failed; check installation/authentication separately. Console output suppressed.')
        files=list(Path(tmp).glob('*.json' if tool=='ghunt' else '*.csv'))
        if len(files)!=1:return finding(tool,{},'error','Expected one structured result file; upstream schema may have changed.')
        raw=read_file(files[0])
        try:
            if tool=='ghunt':
                data=json.loads(raw)
                if not isinstance(data,dict):raise ValueError()
            else:
                rows=list(csv.DictReader(io.StringIO(raw.decode())))
                if not rows or not {'name','exists','rateLimit'}.issubset(rows[0]):raise ValueError()
                data={'accounts':rows}
        except (ValueError,UnicodeError):return finding(tool,{},'error','Unsupported structured output; not negative evidence.')
        return finding(tool,{'upstream_result':data,'email':email},'observed','Upstream claims, not verified ownership. Account checks may contact third-party registration/recovery endpoints; upstream behavior can change.')
