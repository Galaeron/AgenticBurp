"""Durable job metadata; recovering status never schedules or executes work."""
from contextlib import closing
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from urllib.parse import quote

from harness import security

RUNNING = frozenset({'running', 'cancelling'})
TERMINAL = frozenset({'done', 'error', 'cancelled', 'interrupted'})
FIELDS = ('job_id', 'host', 'base_url', 'status', 'started_at', 'finished_at',
          'error', 'manifest_path', 'result', 'result_available', 'recovered',
          'result_ref', 'result_size_bytes', 'result_sha256', 'result_summary', 'delivery_error')
INLINE_LIMIT = 2_000_000


def process_alive(pid):
    """Read-only liveness check; unknown permissions conservatively mean alive."""
    if pid == os.getpid():
        return True
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return ctypes.get_last_error() != 87  # invalid/nonexistent PID
        try:
            status = ctypes.c_uint32()
            return not kernel.GetExitCodeProcess(handle, ctypes.byref(status)) or status.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class JobCapacityError(Exception):
    pass


class JobStatusStore:
    def __init__(self, path, owner, *, retention=900.0, max_terminal=50, max_running=4):
        self.path = Path(path)
        self.owner = owner
        self.retention = retention
        self.max_terminal = max_terminal
        self.max_running = max_running

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute('CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, '
                         'owner TEXT NOT NULL, pid INTEGER NOT NULL, status TEXT NOT NULL, '
                         'started REAL NOT NULL, finished REAL, payload TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS job_results (job_id TEXT PRIMARY KEY, '
                         'content BLOB NOT NULL, sha256 TEXT NOT NULL)')
            conn.commit()
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _payload(job):
        data = security.sanitize_data({k: job.get(k) for k in FIELDS})
        data['base_url'] = security.redact_secrets_in_url(data.get('base_url') or '')
        data['result_available'] = data.get('result') is not None or bool(data.get('result_ref'))
        if len(json.dumps(data.get('result'), ensure_ascii=True)) > INLINE_LIMIT:
            data['result'] = None
            data['result_available'] = bool(data.get('result_ref'))
            if not data['result_available']:
                data['delivery_error'] = 'complete result has not been durably stored'
        return json.dumps(data, ensure_ascii=True, sort_keys=True)

    @staticmethod
    def _store_result(conn, job):
        """Commit result and job metadata together; no operator-controlled paths."""
        data = dict(job)
        if job.get('result') is not None:
            result = security.sanitize_data(job['result'])
            content = json.dumps(result, ensure_ascii=True, sort_keys=True).encode('utf-8')
            digest = hashlib.sha256(content).hexdigest()
            conn.execute('INSERT OR REPLACE INTO job_results VALUES (?,?,?)',
                         (job['job_id'], content, digest))
            summary = {key: result[key][:128] if isinstance(result[key], str) else result[key]
                       for key in ('run_id', 'request_count', 'confirmed_issues', 'partial')
                       if key in result and isinstance(result[key], (int, bool, str))}
            if isinstance(result.get('findings'), list):
                summary['findings'] = len(result['findings'])
            data.update(result_ref=f"/engagement/{quote(job['host'], safe='')}/investigate/{quote(job['job_id'], safe='')}/result",
                        result_size_bytes=len(content), result_sha256=digest,
                        result_summary=summary, result_available=True, delivery_error=job.get('delivery_error'))
        return data

    def read_result(self, job_id):
        """Read and validate the managed JSON artifact; never follows a path."""
        with closing(self._connect()) as conn:
            row = conn.execute('SELECT content,sha256 FROM job_results WHERE job_id=?', (job_id,)).fetchone()
            job = conn.execute('SELECT payload FROM jobs WHERE job_id=?', (job_id,)).fetchone()
        if not row or not job:
            raise ValueError('result artifact is missing')
        content, digest = row
        meta = json.loads(job[0])
        if (hashlib.sha256(content).hexdigest() != digest or digest != meta.get('result_sha256')
                or len(content) != meta.get('result_size_bytes')):
            raise ValueError('result artifact failed integrity validation')
        return content

    @classmethod
    def public_snapshot(cls, job):
        """Use the exact durable redaction and size contract for live polling."""
        return json.loads(cls._payload(job))

    def create(self, job):
        """Atomic admission; the same explicit identity never creates work twice."""
        with closing(self._connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            existing = conn.execute('SELECT payload FROM jobs WHERE job_id=?', (job['job_id'],)).fetchone()
            if existing:
                return json.loads(existing[0]), False
            count = conn.execute("SELECT count(*) FROM jobs WHERE status IN ('running','cancelling')").fetchone()[0]
            if count >= self.max_running:
                raise JobCapacityError('durable job capacity reached')
            saved = self._store_result(conn, job)
            conn.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)',
                         (job['job_id'], self.owner, os.getpid(), job['status'],
                          job['started_at'], job.get('finished_at'), self._payload(saved)))
            return job, True

    def update(self, job):
        with closing(self._connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            saved = self._store_result(conn, job)
            changed = conn.execute('UPDATE jobs SET status=?,finished=?,payload=? WHERE job_id=? AND owner=?',
                                   (job['status'], job.get('finished_at'), self._payload(saved),
                                    job['job_id'], self.owner)).rowcount
            if changed != 1:
                raise ValueError('job ownership missing; durable status was not updated')
        for key in ('result_ref', 'result_size_bytes', 'result_sha256', 'result_summary', 'delivery_error'):
            job[key] = saved.get(key)

    def recover_interrupted(self, *, now=None, is_alive=process_alive):
        stamp = time.time() if now is None else now
        with closing(self._connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            rows = conn.execute("SELECT job_id,owner,pid,payload FROM jobs WHERE status IN ('running','cancelling')").fetchall()
            for job_id, owner, pid, payload in rows:
                if owner == self.owner or is_alive(pid):
                    continue
                job = json.loads(payload)
                job.update(status='interrupted', finished_at=stamp, recovered=True,
                           error='previous job process ended; no work was resumed')
                conn.execute('UPDATE jobs SET status=?,finished=?,payload=? WHERE job_id=?',
                             ('interrupted', stamp, self._payload(job), job_id))

    def get(self, job_id):
        with closing(self._connect()) as conn:
            row = conn.execute('SELECT payload FROM jobs WHERE job_id=?', (job_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def list(self, host):
        with closing(self._connect()) as conn:
            rows = conn.execute('SELECT payload FROM jobs ORDER BY started DESC').fetchall()
        return [job for row in rows if (job := json.loads(row[0])).get('host') == host]

    def prune(self, *, now=None):
        stamp = time.time() if now is None else now
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM jobs WHERE status IN ('done','error','cancelled','interrupted') AND finished < ?",
                         (stamp - self.retention,))
            rows = conn.execute("SELECT job_id FROM jobs WHERE status IN ('done','error','cancelled','interrupted') ORDER BY finished DESC").fetchall()
            conn.executemany('DELETE FROM jobs WHERE job_id=?', rows[self.max_terminal:])
            conn.execute('DELETE FROM job_results WHERE job_id NOT IN (SELECT job_id FROM jobs)')
