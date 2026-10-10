"""Durable job metadata; recovering status never schedules or executes work."""
from contextlib import closing
import ctypes
import json
import os
from pathlib import Path
import sqlite3
import time

from harness import security

RUNNING = frozenset({'running', 'cancelling'})
TERMINAL = frozenset({'done', 'error', 'cancelled', 'interrupted'})
FIELDS = ('job_id', 'host', 'base_url', 'status', 'started_at', 'finished_at',
          'error', 'manifest_path', 'result', 'result_available', 'recovered')


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
            conn.commit()
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _payload(job):
        data = security.sanitize_data({k: job.get(k) for k in FIELDS})
        data['base_url'] = security.redact_secrets_in_url(data.get('base_url') or '')
        data['result_available'] = data.get('result') is not None
        # Metadata/result bounds do not delete manifests or findings artifacts.
        if len(json.dumps(data.get('result'), ensure_ascii=True)) > 2_000_000:
            data['result'] = None
            data['result_available'] = False
            data['error'] = 'job result exceeds durable polling limit; see preserved artifacts'
        return json.dumps(data, ensure_ascii=True, sort_keys=True)

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
            conn.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)',
                         (job['job_id'], self.owner, os.getpid(), job['status'],
                          job['started_at'], job.get('finished_at'), self._payload(job)))
            return job, True

    def update(self, job):
        with closing(self._connect()) as conn, conn:
            changed = conn.execute('UPDATE jobs SET status=?,finished=?,payload=? WHERE job_id=? AND owner=?',
                                   (job['status'], job.get('finished_at'), self._payload(job),
                                    job['job_id'], self.owner)).rowcount
            if changed != 1:
                raise ValueError('job ownership missing; durable status was not updated')

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
                           error='previous job process ended; no work was resumed', result=None)
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
