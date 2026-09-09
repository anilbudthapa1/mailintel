"""Persistent bounded DNS/offline watches. Invoke run-due from cron; no daemon install."""
import json
import time
import uuid
from .modules import email_info,run_modules
from .core import encoded


def setup(store):
    store.db.execute('CREATE TABLE IF NOT EXISTS watches(id TEXT PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),email TEXT NOT NULL,profile TEXT NOT NULL,interval INTEGER NOT NULL,next_due REAL NOT NULL,enabled INTEGER NOT NULL)')
    store.db.commit()


def create(store,cid,email,interval,profile):
    setup(store);store.case(cid);email=email_info(email)[0]
    if interval<3600:raise ValueError('Minimum watch interval is 3600 seconds.')
    wid=uuid.uuid4().hex[:12]
    with store.db:store.db.execute('INSERT INTO watches VALUES(?,?,?,?,?,?,1)',(wid,cid,email,profile,interval,time.time()))
    return wid


def due(store,limit):
    setup(store)
    if not 1<=limit<=100:raise ValueError('Job limit must be 1–100.')
    events=[]
    for _ in range(limit):
        # Reserve in transaction so overlapping cron invocations do not query the same watch.
        with store.db:
            store.db.execute('BEGIN IMMEDIATE')
            row=store.db.execute('SELECT * FROM watches WHERE enabled=1 AND next_due<=? ORDER BY next_due LIMIT 1',(time.time(),)).fetchone()
            if row is None:break
            store.db.execute('UPDATE watches SET next_due=? WHERE id=?',(time.time()+row['interval'],row['id']))
        previous=[r for r in store.runs(row['case_id']) if r['indicator']==row['email'] and r['kind']=='email' and r['profile']==row['profile']]
        fs=run_modules('email',row['email'],['syntax','disposable']+(['dns'] if row['profile']=='passive' else []),row['profile'],store)
        rid=store.save(row['case_id'],row['email'],'email',row['profile'],fs)
        # Exclude transient TTL changes from alerts; preserve them in original evidence.
        def stable(value):
            if isinstance(value,dict):return {k:stable(v) for k,v in value.items() if k!='ttl'}
            if isinstance(value,list):return [stable(v) for v in value]
            return value
        changed=bool(previous and stable(previous[-1]['findings'])!=stable(fs))
        events.append({'watch':row['id'],'run':rid,'changed':changed,'first_observation':not bool(previous),'errors':[f['module'] for f in fs if f['status'] in ('error','partial')]})
    return events
