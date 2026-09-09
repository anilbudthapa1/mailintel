"""Case storage and integrity. No network operations in this module."""
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2).encode('utf-8')


class Store:
    def __init__(self, root):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.root / 'cases.sqlite3', timeout=20)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
            created_at TEXT NOT NULL, payload TEXT NOT NULL, sha256 TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cooldowns (provider TEXT PRIMARY KEY, until REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS budgets (provider TEXT PRIMARY KEY, max_requests INTEGER NOT NULL, cost_per_request REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS requests (provider TEXT NOT NULL, requested_at REAL NOT NULL);
        ''')
        self.db.commit()
        os.chmod(self.root / 'cases.sqlite3', 0o600)

    def create(self, name):
        if not name.strip() or len(name) > 200:
            raise ValueError('Case name must have 1 to 200 characters.')
        cid = uuid.uuid4().hex[:12]
        self.db.execute('INSERT INTO cases VALUES (?,?,?)', (cid, name, now()))
        self.db.commit()
        return cid

    def case(self, cid):
        result = self.db.execute('SELECT * FROM cases WHERE id=?', (cid,)).fetchone()
        if result is None:
            raise ValueError('Unknown case ID. Run: mailintel case list')
        return dict(result)

    def cases(self):
        return [dict(r) for r in self.db.execute('SELECT * FROM cases ORDER BY created_at DESC')]

    def save(self, cid, indicator, kind, profile, findings):
        self.case(cid)
        record = dict(id=uuid.uuid4().hex, case_id=cid, indicator=indicator,
                      kind=kind, profile=profile, created_at=now(),
                      version='1.4.0', findings=findings)
        raw = encoded(record)
        digest = hashlib.sha256(raw).hexdigest()
        self.db.execute('INSERT INTO runs VALUES (?,?,?,?,?)',
                        (record['id'], cid, record['created_at'], raw.decode(), digest))
        self.db.commit()
        return record['id']

    def runs(self, cid):
        self.case(cid)
        results = []
        for row in self.db.execute('SELECT payload,sha256 FROM runs WHERE case_id=? ORDER BY created_at', (cid,)):
            raw = row['payload'].encode()
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('Evidence integrity check failed. Stored payload was changed.')
            result = json.loads(raw)
            result['sha256'] = row['sha256']
            results.append(result)
        return results

    def reserve(self, provider, interval=6):
        """Persist request spacing across CLI processes; do not sleep or auto-retry."""
        import time
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT until FROM cooldowns WHERE provider=?', (provider,)).fetchone()
            current = time.time()
            if row and row[0] > current:
                return int(row[0] - current) + 1
            budget = self.db.execute('SELECT * FROM budgets WHERE provider=?',(provider,)).fetchone()
            if budget:
                recent = self.db.execute('SELECT COUNT(*),MIN(requested_at) FROM requests WHERE provider=? AND requested_at>?',(provider,current-86400)).fetchone()
                if recent[0] >= budget['max_requests']:
                    return max(1,int(recent[1]+86400-current)+1)
            self.db.execute('INSERT INTO requests VALUES (?,?)',(provider,current))
            self.db.execute('INSERT OR REPLACE INTO cooldowns VALUES (?,?)', (provider, current + interval))
        return 0

    def cooldown(self, provider, seconds):
        import time
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO cooldowns VALUES (?,?)', (provider, time.time() + seconds))
