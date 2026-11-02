"""Independent replay audit of every confirmed validator claim from a finished live run.

Usage: python replay_audit.py <live-dir> [--inventory]

Reads the run's confirmed proof instances (result.json issue_accounting), resolves each
to the request it judged, then re-sends that request against the owned target with its
own baseline and negative controls and judges it by fixed rules -- no harness code and
no model. --inventory lists the claims and sends nothing.

Only http://127.0.0.1:3002/ is reachable. Fresh audit accounts are registered through
the target's API; their credentials and every token are written only to
replay-audit-private.json and never printed or traced. The trace keeps status, size,
body hash and the security headers of each response.

Every claim ends in one audit state: audited, not_audited (a procedure exists but gave
no conclusion) or unsupported_audit (no procedure; the reason is recorded per claim).
False positives are counted over audited claims only (AR-08c).
"""
import base64
import collections
import hashlib
import html
import json
import re
import secrets
import socket
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

sys.stdout.reconfigure(encoding='utf-8')
BASE = 'http://127.0.0.1:3002'
MAX_REQUESTS = 400
TRACED_HEADERS = ('content-type', 'content-security-policy', 'x-frame-options',
                  'access-control-allow-origin', 'access-control-allow-credentials')
AUDIT_ORIGIN = 'http://audit-origin.invalid'


def short(*parts):
    return hashlib.sha256('\x1f'.join('' if p is None else str(p) for p in parts)
                          .encode('utf-8')).hexdigest()[:16]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ok(status):
    return 200 <= status < 300


def rejected(status):
    return status in (401, 403)


# ---------------------------------------------------------------- inventory

def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]


def inventory(live):
    result = json.loads((live / 'result.json').read_text(encoding='utf-8'))
    accounting = result.get('issue_accounting') or {}
    group_of = {pid: g for g in accounting.get('groups') or [] for pid in g.get('proof_ids') or []}
    db = sqlite3.connect(f"file:{live / 'source/harness/harness_state.db'}?mode=ro", uri=True)
    by_proof = {pid: (method, url, cls) for pid, method, url, cls in db.execute(
        "select proof_id, method, url, vulnerability_class from findings "
        "where coalesce(proof_id, '') != ''")}
    observed = dict(db.execute("select proof_id, coalesce(observed_result, '') from proof_records"))
    db.close()
    # Proofs whose template matches no stored exchange, resolved by hand with the reason
    # recorded beside them (e.g. from the safety-gate log order of a tool's targets).
    overrides_path = live / 'replay-audit-overrides.json'
    overrides = json.loads(overrides_path.read_text(encoding='utf-8')) if overrides_path.exists() else {}
    templates = {}
    captures = live / 'setup-captures-private.json'
    for c in json.loads(captures.read_text(encoding='utf-8')) if captures.exists() else []:
        templates[short(c['method'].upper(), c['url'], c.get('request_body') or '')] = (
            c['method'].upper(), c['url'])
    methods_seen = collections.defaultdict(set)
    for e in rows(live / 'network.jsonl'):
        templates.setdefault(short(e['method'].upper(), e['url'], ''), (e['method'].upper(), e['url']))
        methods_seen[e['url']].add(e['method'].upper())

    claims, seen = [], {}
    for p in accounting.get('proof_instances') or []:
        if p.get('verdict') != 'confirmed':
            continue
        pid, case = p['proof_id'], p.get('case') or {}
        group = group_of.get(pid) or {}
        cls = (group.get('vulnerability_class') or case.get('check_id') or '').lower()
        source = 'finding'
        if pid in by_proof:
            method, url, finding_cls = by_proof[pid]
            cls = (finding_cls or cls).lower()
        elif case.get('request_template_id') in templates:
            method, url = templates[case['request_template_id']]
            source = 'template'
        elif case.get('request_template_id') in overrides:
            override = overrides[case['request_template_id']]
            method, url = override['method'], override['url']
            source = 'override: ' + override['why']
        elif group.get('routes'):
            url = group['routes'][0]
            seen_methods = methods_seen.get(url) or {'GET'}
            method = 'POST' if 'POST' in seen_methods else sorted(seen_methods)[0]
            source = 'group route'
        else:
            method = url = None
            source = 'unresolved'
        # A jwt/sqlmap claim is the same test whatever check label the run gave it;
        # header claims differ by class (CSP vs framing vs CORS on one route).
        key = (p['validator'], '' if p['validator'] in ('jwt_forge', 'sqlmap') else cls, method, url)
        if key in seen:
            seen[key]['proof_ids'].append(pid)
            if cls not in seen[key]['class'].split(' + '):
                seen[key]['class'] += ' + ' + cls
            continue
        claim = {'validator': p['validator'], 'class': cls, 'method': method, 'url': url,
                 'resolved_from': source, 'accounting_kind': group.get('kind') or 'unreferenced',
                 'principal': case.get('principal_id') or '', 'proof_ids': [pid],
                 'observed': observed.get(pid, '')[:240]}
        seen[key] = claim
        claims.append(claim)
    return claims


# ---------------------------------------------------------------- target

class Target:
    def __init__(self, trace_path):
        self.client = httpx.Client(timeout=60, trust_env=False, follow_redirects=False)
        self.count = 0
        self.trace = trace_path.open('a', encoding='utf-8')

    def send(self, label, method, url, token=None, raw_auth=None, origin=None, body=None):
        if not (url == BASE or url.startswith(BASE + '/')):
            raise ValueError(f'out of scope: {url}')
        if self.count >= MAX_REQUESTS:
            raise RuntimeError('audit request ceiling reached')
        self.count += 1
        headers = {'accept': 'application/json, text/plain, */*'}
        if token:
            headers['authorization'] = f'Bearer {token}'
        if raw_auth:
            headers['authorization'] = raw_auth
        if origin:
            headers['origin'] = origin
        started = time.monotonic()
        resp = self.client.request(method, url, headers=headers, json=body)
        row = {'label': label, 'method': method, 'url': url, 'status': resp.status_code,
               'bytes': len(resp.content), 'sha256': sha(resp.content),
               'seconds': round(time.monotonic() - started, 3),
               'headers': {k: resp.headers[k] for k in TRACED_HEADERS if k in resp.headers}}
        self.trace.write(json.dumps({'time': time.time(), **row}) + '\n')
        self.trace.flush()
        return resp, row

    def handshake(self, label, url, origin, version='13'):
        """One raw WebSocket upgrade request with no credentials. Only the status line
        is read; no frame is ever sent."""
        if url.startswith(('ws://', 'wss://')):
            url = 'http' + url[2:]
        if not (url == BASE or url.startswith(BASE + '/')):
            raise ValueError(f'out of scope: {url}')
        if self.count >= MAX_REQUESTS:
            raise RuntimeError('audit request ceiling reached')
        self.count += 1
        parts = urlsplit(url)
        path = (parts.path or '/') + (f'?{parts.query}' if parts.query else '')
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (f'GET {path} HTTP/1.1\r\nHost: {parts.netloc}\r\nUpgrade: websocket\r\n'
                   f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
                   f'Sec-WebSocket-Version: {version}\r\nOrigin: {origin}\r\n\r\n')
        started = time.monotonic()
        head = b''
        with socket.create_connection((parts.hostname, parts.port or 80), timeout=60) as sock:
            sock.sendall(request.encode('ascii'))
            while b'\r\n' not in head and len(head) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                head += chunk
        status_line = head.split(b'\r\n', 1)[0].decode('latin-1')
        match = re.match(r'HTTP/\d(?:\.\d)?\s+(\d{3})', status_line)
        status = int(match.group(1)) if match else 0
        row = {'label': label, 'method': 'GET (websocket upgrade)', 'url': url, 'origin': origin,
               'version': version, 'status': status, 'upgraded': status == 101,
               'seconds': round(time.monotonic() - started, 3)}
        self.trace.write(json.dumps({'time': time.time(), **row}) + '\n')
        self.trace.flush()
        return row

    def close(self):
        self.client.close()
        self.trace.close()


def body_keys(resp):
    try:
        data = resp.json()
    except ValueError:
        return None
    inner = data.get('data') if isinstance(data, dict) else None
    return {'top': sorted(data) if isinstance(data, dict) else type(data).__name__,
            'data': (type(inner).__name__, len(inner)) if isinstance(inner, (list, dict)) else None}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def claims_of(token):
    return json.loads(unb64(token.split('.')[1]))


def register(target, tag, private):
    email = f'av-audit-{int(time.time())}-{tag}-{secrets.token_hex(3)}@example.invalid'
    password = secrets.token_urlsafe(13)
    resp, _ = target.send(f'register {tag}', 'POST', BASE + '/api/Users',
                          body={'email': email, 'password': password, 'passwordRepeat': password})
    if resp.status_code != 201:
        raise RuntimeError(f'audit registration failed: HTTP {resp.status_code}')
    resp, _ = target.send(f'login {tag}', 'POST', BASE + '/rest/user/login',
                          body={'email': email, 'password': password})
    token = resp.json()['authentication']['token']
    account = {'tag': tag, 'email': email, 'password': password, 'token': token}
    private['accounts'].append(account)
    return account


# ---------------------------------------------------------------- family audits

def audit_jwt_forge(target, claim, account):
    """Signature verification on the claimed route: a forged unsigned (alg:none) copy
    of a valid token must be rejected like no token and a garbage token are."""
    url, method = claim['url'], claim['method'] or 'GET'
    token = account['token']
    header, payload, signature = token.split('.')
    none_token = b64url(json.dumps({'typ': 'JWT', 'alg': 'none'}).encode()) + f'.{payload}.'
    flipped = bytearray(unb64(signature))
    flipped[len(flipped) // 2] ^= 0x01
    bad_sig = f'{header}.{payload}.{b64url(bytes(flipped))}'
    base, base_row = target.send('baseline: valid token', method, url, token=token)
    _, none_row = target.send('control: no token', method, url)
    _, garbage_row = target.send('control: garbage token', method, url, raw_auth='Bearer garbage')
    _, badsig_row = target.send('control: valid claims, altered signature', method, url, token=bad_sig)
    attack, attack_row = target.send('attack: same claims, alg:none, unsigned', method, url,
                                     token=none_token)
    same_shape = body_keys(base) == body_keys(attack)
    checks = [base_row, none_row, garbage_row, badsig_row, attack_row]
    if not ok(base_row['status']):
        controls = (base_row, none_row, garbage_row, badsig_row)
        if ok(attack_row['status']) and not any(ok(row['status']) for row in controls):
            return 'confirmed', ('the unsigned alg:none token was accepted (HTTP %s) where the valid token, '
                                 'an altered signature, no token and a garbage token were all refused: '
                                 'alg:none skips verification and reaches a route the account itself '
                                 'cannot' % attack_row['status']), checks
        return 'inconclusive', 'the valid-token baseline was not accepted', checks
    if ok(none_row['status']):
        return 'false_positive', 'the route answers without any token, so accepting a forged one proves nothing', checks
    if ok(garbage_row['status']):
        return 'inconclusive', 'a garbage token was accepted', checks
    if ok(attack_row['status']) and same_shape:
        extra = ('; an altered signature was also accepted' if ok(badsig_row['status'])
                 else '; an altered RS256 signature was rejected, so only alg:none bypasses verification')
        return 'confirmed', ('an unsigned alg:none token carrying the audit account claims was accepted '
                             'with the same response shape as the valid token, while no token and a '
                             'garbage token were rejected' + extra), checks
    if rejected(attack_row['status']):
        return 'false_positive', 'the unsigned alg:none token was rejected', checks
    return 'inconclusive', 'the alg:none response differed from the baseline without a clear rejection', checks


def audit_sqli_login(target, claim, account):
    """Boolean pair on the login email: a true condition must authenticate an absent
    account while the false condition and the plain absent email do not."""
    url = claim['url']
    absent = f'av-audit-absent-{secrets.token_hex(4)}@example.invalid'
    password = secrets.token_urlsafe(10)
    _, valid_row = target.send('positive control: audit account login', 'POST', url,
                               body={'email': account['email'], 'password': account['password']})
    _, plain_row = target.send('baseline: absent email', 'POST', url,
                               body={'email': absent, 'password': password})
    _, false_row = target.send("control: absent email + ' AND 1=2--", 'POST', url,
                               body={'email': absent + "' AND 1=2--", 'password': password})
    true, true_row = target.send("attack: absent email + ' OR 1=1--", 'POST', url,
                                 body={'email': absent + "' OR 1=1--", 'password': password})
    issued = None
    if ok(true_row['status']):
        try:
            issued = true.json()['authentication']['token']
        except (ValueError, KeyError, TypeError):
            issued = None
    if issued:
        identity = (claims_of(issued).get('data') or {})
        true_row['token_issued'] = True
        true_row['token_identity'] = {'role': identity.get('role'),
                                      'is_audit_account': identity.get('email') == account['email']}
    checks = [valid_row, plain_row, false_row, true_row]
    if not ok(valid_row['status']):
        return 'inconclusive', 'the endpoint did not authenticate the audit account', checks
    if issued and rejected(plain_row['status']) and rejected(false_row['status']):
        return 'confirmed', ('the always-true condition authenticated an email that does not exist and '
                             'returned a session token for another account, while the plain absent '
                             'email and the always-false condition were rejected'), checks
    if not ok(true_row['status']) and false_row['status'] == plain_row['status']:
        return 'false_positive', 'the true and false conditions behaved like a plain absent email', checks
    return 'inconclusive', 'the boolean pair did not separate cleanly', checks


SQLMAP_IMAGE = 'harness/sqlmap:1.10.9'
# The harness validator's own invocation (validators/sqlmap.py, tool_runner hardening),
# so a rerun reproduces the claim rather than a different scan.
SQLMAP_DOCKER = ['docker', 'run', '--rm', '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
                 '--pids-limit', '256', '--memory', '1g', '--cpus', '2',
                 '--add-host', 'host.docker.internal:host-gateway', SQLMAP_IMAGE]
SQLMAP_FLAGS = ['--batch', '--level', '1', '--risk', '1', '--threads', '1', '--timeout', '10',
                '--retries', '1', '--flush-session', '--disable-coloring']
SQLMAP_WALL_SECONDS = 300


def fresh_body(live, method, url, account):
    """The captured JSON body for this route with every value refreshed: a new unique
    email per call and one new password for all password fields. A login uses the
    audit account, as the harness's capture held valid credentials (2xx baseline)."""
    path = url.split('://', 1)[-1].split('/', 1)[-1].rstrip('/')
    if path == 'rest/user/login':
        return {'email': account['email'], 'password': account['password']}
    template = None
    for c in json.loads((live / 'setup-captures-private.json').read_text(encoding='utf-8')):
        if c['method'].upper() == method and c['url'].split('://', 1)[-1].split('/', 1)[-1].rstrip('/') == path:
            template = json.loads(c['request_body'])
            break
    if template is None:
        return None
    password = secrets.token_urlsafe(12)
    body = {}
    for key, value in template.items():
        if key == 'email':
            body[key] = f'av-audit-{secrets.token_hex(5)}@example.invalid'
        elif 'password' in key.lower():
            body[key] = password
        elif isinstance(value, str):
            body[key] = 'audit-' + secrets.token_hex(3)
        else:
            body[key] = value
    return body


def run_sqlmap(live, claim, index, account):
    import re
    import subprocess
    body = fresh_body(live, claim['method'], claim['url'], account)
    if body is None:
        return None, 'no captured body shape for this route'
    url = claim['url'].replace('http://127.0.0.1:3002', 'http://host.docker.internal:3002')
    argv = SQLMAP_DOCKER + ['-u', url, '--data', json.dumps(body), '-H', 'Content-Type: application/json',
                            *SQLMAP_FLAGS, '--ignore-code', '401,403']
    started = time.monotonic()
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace',
                              timeout=SQLMAP_WALL_SECONDS)
        output, code = (done.stdout or '') + '\n' + (done.stderr or ''), done.returncode
    except subprocess.TimeoutExpired as exc:
        output, code = (exc.stdout or '') if isinstance(exc.stdout, str) else '', 'timeout'
    # The log echoes the fresh throwaway password, so it is private.
    (live / f'replay-audit-sqlmap-{index}-private.log').write_text(output, encoding='utf-8')
    total = re.search(r'with a total of (\d+) HTTP', output)
    points = []
    for block in re.findall(r'Parameter: (.+?)\n(.*?)(?=\nParameter: |\n---)', output, re.S):
        name = re.match(r'(?:JSON )?(\S+)', block[0]).group(1)
        for kind, title, payload in re.findall(r'Type: (.+?)\n\s+Title: (.+?)\n\s+Payload: (.+?)\n', block[1] + '\n'):
            points.append({'parameter': name, 'type': kind.strip(), 'title': title.strip(),
                           'payload': payload.strip()})
    return {'exit': code, 'seconds': round(time.monotonic() - started, 1),
            'reports_vulnerable': 'is vulnerable' in output.lower() or bool(points),
            'sqlmap_requests': int(total.group(1)) if total else None,
            'base_body': body, 'points': points}, None


def injected_suffix(point, base_body):
    """What sqlmap appended to the parameter's original value, or None."""
    try:
        injected = json.loads(point['payload']).get(point['parameter'])
    except (ValueError, AttributeError):
        return None
    original = str(base_body.get(point['parameter'], ''))
    if not isinstance(injected, str):
        return None
    return injected[len(original):] if original and injected.startswith(original) else None


def response_signature(resp):
    try:
        data = resp.json()
    except ValueError:
        return (resp.status_code, 'non-json', len(resp.content) // 64)
    if isinstance(data, dict):
        message = data.get('message') or data.get('error') or ''
        if isinstance(message, dict):
            message = message.get('message', '')
        inner = data.get('data')
        return (resp.status_code, tuple(sorted(data)),
                tuple(sorted(inner)) if isinstance(inner, dict) else type(inner).__name__,
                ''.join(ch for ch in str(message) if not ch.isdigit())[:80])
    return (resp.status_code, type(data).__name__)


def audit_sqlmap(target, claim, account, live, index):
    """Rerun the claim's own tool, then test the reported point independently with
    fresh unique values in every request so state (e.g. a unique email) cannot pose
    as a boolean or timing signal."""
    import re
    rerun, why = run_sqlmap(live, claim, index, account)
    if rerun is None:
        return 'not_audited', why, []
    public = {k: v for k, v in rerun.items() if k not in ('base_body', 'points')}
    public['points'] = [{k: p[k] for k in ('parameter', 'type', 'title')} for p in rerun['points']]
    checks = [{'label': 'sqlmap rerun (same image and flags)', **public}]
    login_pair = None
    if claim['url'].endswith('/rest/user/login'):
        login_pair = audit_sqli_login(target, claim, account)
        checks += [{'label': 'independent login boolean pair', 'verdict': login_pair[0],
                    'reason': login_pair[1]}] + login_pair[2]
    if not rerun['reports_vulnerable']:
        if login_pair and login_pair[0] == 'confirmed':
            return 'confirmed', 'sqlmap did not reproduce, but ' + login_pair[1], checks
        return 'not_reproduced', ('a fresh sqlmap run with the same image and flags found no injection '
                                  'point (exit %s); the run stored no parameter, technique or payload, '
                                  'so the original detection cannot be re-tested point by point'
                                  % rerun['exit']), checks
    verdicts = []
    for point in rerun['points']:
        suffix = injected_suffix(point, rerun['base_body'])
        record = {'label': f"independent check: {point['parameter']} / {point['type']}",
                  'suffix': suffix}
        if suffix is None:
            record['result'] = 'payload did not extend the original value; not re-tested'
            checks.append(record)
            continue

        def send(label, tail):
            body = fresh_body(live, claim['method'], claim['url'], account)
            body[point['parameter']] = str(body.get(point['parameter'], '')) + tail
            resp, row = target.send(label, claim['method'], claim['url'], body=body)
            row['signature'] = list(map(str, response_signature(resp)))
            checks.append(row)
            return resp, row

        if 'boolean' in point['type']:
            false_tail = re.sub(r'(\d+)=(\1)\b', lambda m: f'{m.group(1)}={int(m.group(1)) + 1}', suffix, count=1)
            if false_tail == suffix:
                record['result'] = 'no numeric tautology to negate; not re-tested'
                checks.append(record)
                continue
            signatures = {'true': [], 'false': []}
            for _ in range(2):
                for kind, tail in (('true', suffix), ('false', false_tail)):
                    resp, _ = send(f'{kind} condition, fresh values', tail)
                    signatures[kind].append(response_signature(resp))
            separated = (len(set(signatures['true'])) == 1 and len(set(signatures['false'])) == 1
                         and signatures['true'][0] != signatures['false'][0])
            record['result'] = 'true and false conditions separate reproducibly' if separated else \
                'true and false conditions do not separate with fresh values'
            verdicts.append(separated)
        elif 'time' in point['type']:
            control_tail = re.sub(r'RANDOMBLOB\(\d+(/\d+)?\)', 'RANDOMBLOB(1)', suffix)
            control_tail = re.sub(r'(PG_)?SLEEP\(\d+\)', lambda m: f"{m.group(1) or ''}SLEEP(0)", control_tail)
            control_tail = re.sub(r"DELAY '0:0:\d+'", "DELAY '0:0:0'", control_tail)
            if control_tail == suffix:
                record['result'] = 'no delay term to neutralise; not re-tested'
                checks.append(record)
                continue
            timings = {'attack': [], 'control': []}
            for _ in range(3):
                for kind, tail in (('attack', suffix), ('control', control_tail)):
                    _, row = send(f'{kind}: delay {"on" if kind == "attack" else "neutralised"}', tail)
                    timings[kind].append(row['seconds'])
            delayed = min(timings['attack']) - max(timings['control']) > 2.0
            record['timings'] = timings
            record['result'] = 'every delayed request is >2 s slower than every control' if delayed else \
                'delays do not separate from controls'
            verdicts.append(delayed)
        else:
            record['result'] = 'technique has no independent rule here; recorded only'
        checks.append(record)
    if any(verdicts) or (login_pair and login_pair[0] == 'confirmed'):
        return 'confirmed', ('sqlmap reproduced the claim and an independent paired check with fresh '
                             'values separated attack from control'), checks
    if verdicts:
        return 'false_positive', ('sqlmap reproduced its report, but no reported point separated attack '
                                  'from control once every request used fresh values'), checks
    return 'inconclusive', 'sqlmap reproduced its report; no reported technique could be re-tested independently', checks


_HEADER_OBSERVATIONS = {}


def audit_headers(target, claim, account):
    """Header claims (CSP, framing, CORS) re-read from the claimed route, one request
    per route shared by every claim on it."""
    import re
    url, cls = claim['url'], claim['class']
    if url not in _HEADER_OBSERVATIONS:
        row = target.send('observe response headers', 'GET', url, origin=AUDIT_ORIGIN)[1]
        if rejected(row['status']):
            row = target.send('observe response headers (audit account)', 'GET', url,
                              token=account['token'], origin=AUDIT_ORIGIN)[1]
        _HEADER_OBSERVATIONS[url] = row
    row = _HEADER_OBSERVATIONS[url]
    headers, checks = row['headers'], [row]
    csp = headers.get('content-security-policy', '')
    ctype = headers.get('content-type', '')
    mismatch = ''
    if csp and 'no content-security-policy header present' in claim.get('observed', '').lower():
        mismatch = ('; the validator\'s stated proof ("no Content-Security-Policy header present") '
                    'is contradicted: this route sends one')
    if 'xss' in cls:
        return 'not_supported', ('csp_validator inspects response headers only; its proof does not test '
                                 'the XSS this record claims' + mismatch), checks
    if not ok(row['status']):
        return 'inconclusive', f"the route answered HTTP {row['status']}", checks
    if 'cors' in cls:
        acao = headers.get('access-control-allow-origin', '')
        acac = headers.get('access-control-allow-credentials', '').lower() == 'true'
        if acao == AUDIT_ORIGIN and acac:
            return 'confirmed', 'an arbitrary origin is reflected with credentials allowed', checks
        if acao == '*':
            return 'confirmed_hardening', ('Access-Control-Allow-Origin: * without credentials; '
                                           'the API uses bearer tokens that a cross-origin page cannot attach, '
                                           'so this is not a credentialed read'), checks
        return 'false_positive', f'Access-Control-Allow-Origin is {acao or "absent"}', checks
    if 'text/html' not in ctype:
        return 'not_applicable', (f'the route returns {ctype or "no content type"}; CSP and framing '
                                  'headers protect HTML documents' + mismatch), checks
    if 'clickjacking' in cls:
        xfo = headers.get('x-frame-options', '').upper()
        if xfo in ('DENY', 'SAMEORIGIN') or 'frame-ancestors' in csp:
            return 'false_positive', (f'X-Frame-Options: {xfo or "-"} / frame-ancestors '
                                      f'{"present" if "frame-ancestors" in csp else "absent"}; '
                                      'browsers refuse cross-origin framing' + mismatch), checks
        return 'confirmed_hardening', 'no X-Frame-Options or frame-ancestors: cross-origin framing allowed', checks
    if any(word in cls for word in ('weak', 'unsafe-eval', 'overly broad', 'weakness')):
        loose = [d for d in ("'unsafe-eval'", "'unsafe-inline'") if d in csp]
        loose += [m.group(2) for m in re.finditer(r"(^|\s)(\*|https?:|data:)(?=\s|;|$)", csp)]
        if loose:
            return 'confirmed_hardening', ('the policy allows ' + ', '.join(loose) + mismatch), checks
        if csp:
            return 'false_positive', 'the policy has none of the claimed loose sources' + mismatch, checks
        return 'false_positive', 'no policy is sent, so there is no directive to be weak', checks
    if 'content security policy' in cls or 'content-security-policy' in cls or 'csp' in cls:
        if csp:
            return 'false_positive', 'a Content-Security-Policy header is present' + mismatch, checks
        return 'confirmed_hardening', 'no Content-Security-Policy header (defence in depth only)', checks
    return 'unsupported_audit', f'no header rule for class {cls!r}', checks


def audit_recon(target, claim, account):
    """Reconnaissance claims: the route must be served without authentication and
    differ from an absent sibling path (so a fallback page cannot pose as content).
    A claim the validator's own result contradicts is not supported."""
    url, cls, observed = claim['url'], claim['class'], claim.get('observed', '').lower()
    if 'technolog' in cls and 'detected 0 technologies' in observed:
        return 'not_supported', "the validator's own result reports 0 technologies detected", []
    if 'parameter' in cls and 'identified 0 parameters' in observed:
        return 'not_supported', "the validator's own result reports 0 parameters identified", []
    _, row = target.send('anonymous request', 'GET', url)
    control_url = url.rsplit('/', 1)[0] + '/av-audit-absent-' + secrets.token_hex(4)
    _, control = target.send('control: absent sibling path', 'GET', control_url)
    checks = [row, control]
    kind = row['headers'].get('content-type', 'no content type')
    if not ok(row['status']):
        return 'false_positive', f"the route is not served anonymously (HTTP {row['status']})", checks
    if ok(control['status']) and control['sha256'] == row['sha256']:
        return 'false_positive', 'an absent sibling path returns the same body (fallback page)', checks
    served = (f"served without authentication ({kind}, {row['bytes']} bytes) while an absent sibling "
              f"path answers HTTP {control['status']}")
    if 'disclosure' in cls:
        return 'confirmed_observation', served + '; whether the content is sensitive is a manual judgement', checks
    return 'confirmed_observation', served, checks


def audit_websocket(target, claim, account):
    """CSWSH claims: the server upgrades a WebSocket handshake despite a foreign Origin.
    Three anonymous handshakes: same-origin baseline, foreign-origin attack, and an
    invalid protocol version that must not upgrade. Message-level authorization is
    not audited."""
    url = claim['url']
    baseline = target.handshake('baseline: same-origin handshake', url, BASE)
    attack = target.handshake('attack: foreign-origin handshake', url, AUDIT_ORIGIN)
    control = target.handshake('control: invalid protocol version', url, BASE, version='99')
    checks = [baseline, attack, control]
    if control['upgraded']:
        return 'inconclusive', 'the server upgrades an invalid handshake, so an upgrade proves nothing', checks
    if not baseline['upgraded']:
        if rejected(baseline['status']):
            return 'inconclusive', (f"the handshake needs credentials (HTTP {baseline['status']}); the audit "
                                    'holds no ambient cookie session to replay it with'), checks
        return 'inconclusive', (f"the route did not upgrade a same-origin handshake (HTTP {baseline['status']}); "
                                'the claimed handshake cannot be reproduced'), checks
    if not attack['upgraded']:
        return 'false_positive', (f"the foreign Origin was refused (HTTP {attack['status']}) while the same-origin "
                                  'handshake upgraded: Origin is validated'), checks
    return 'confirmed_hardening', ('a foreign-Origin handshake upgrades with no credential at all: Origin is not '
                                   'checked, but a cross-site page gains nothing a direct client lacks, so no '
                                   'ambient-credential hijack is shown; message authorization was not audited'), checks


# The audit's own error signatures (not the harness validator's): stack frames,
# framework debug pages and database engine errors. Banners and bare paths are not errors.
_ERROR_SIGNATURES = (
    ('python_traceback', re.compile(r'Traceback \(most recent call last\)')),
    ('java_stack_frame', re.compile(r'\bat [\w$.]+\.[\w$<>]+\([\w$]+\.java:\d+\)')),
    ('dotnet_stack_frame', re.compile(r'\bat [\w.`<>]+\([^)]*\) in \S[^\r\n]*?:line \d+')),
    ('node_stack_frame', re.compile(r'\bat (?:[\w$.<>\[\] ]+ \()?(?:/|[A-Za-z]:\\|file://)[^()\s]+\.[cm]?[jt]s:\d+:\d+')),
    ('php_error', re.compile(r'(?:Fatal error|Parse error|Warning|Notice):[^\r\n]{0,300}? on line \d+')),
    ('framework_debug_page', re.compile(r"Werkzeug Debugger|You're seeing this error because you have DEBUG = True|"
                                        r'Whoops! There was an error')),
    ('database_engine_error', re.compile(r'SQLSTATE\[|ORA-\d{5}|PG::\w+Error|sqlite3\.OperationalError|SQLITE_ERROR|'
                                         r'You have an error in your SQL syntax|Unclosed quotation mark')),
)
_ANONYMOUS_PRINCIPALS = ('', 'anonymous')


def error_signatures(resp):
    text = html.unescape(resp.text)
    return [name for name, pattern in _ERROR_SIGNATURES if pattern.search(text)]


def audit_error_disclosure(target, claim, account):
    """Error-disclosure claims: the route serves a stack trace, debug page or database
    engine error. The claimed GET is replayed twice; only signature names are kept,
    never body text."""
    url, method = claim['url'], (claim['method'] or 'GET').upper()
    if method != 'GET':
        return 'inconclusive', (f'the claimed {method} request carried a body the run did not record; '
                                'replaying it without that body would test another request'), []
    checks, token = [], None

    def replay(label):
        resp, row = target.send(label, 'GET', url, token=token)
        row['error_signatures'] = error_signatures(resp)
        checks.append(row)
        return row

    first = replay('replay 1: claimed request, no credentials')
    if rejected(first['status']):
        token = account['token']
        first = replay('replay 1: claimed request, audit account')
    second = replay('replay 2: same request')
    if first['error_signatures'] and second['error_signatures']:
        found = sorted(set(first['error_signatures']) | set(second['error_signatures']))
        return 'confirmed_observation', (f"both replays (HTTP {first['status']}/{second['status']}) carry "
                                         f"{', '.join(found)}; whether the detail is sensitive is a manual "
                                         'judgement'), checks
    identical = (first['status'], first['sha256']) == (second['status'], second['sha256'])
    if first['error_signatures'] or second['error_signatures'] or not identical:
        return 'inconclusive', 'the replays differ, so the error may depend on state the run held', checks
    if (claim.get('principal') or '').lower() not in _ANONYMOUS_PRINCIPALS:
        return 'inconclusive', ("the claim was made as principal %r; a clean replay as another identity does "
                                'not refute it' % claim['principal']), checks
    return 'false_positive', (f"two identical replays (HTTP {first['status']}) carry no stack trace, debug page "
                              'or database engine error; a header such as a version banner is not an error '
                              'disclosure'), checks


# AR-08c: classes with no procedure, each with the reason recorded on its claims.
_RACE_REASON = ('race claims are not replay-audited: the claim is a concurrent burst of a captured '
                'state-changing request, but the inventory holds only its method and URL (no body, '
                'credentials or workflow state); re-firing the burst mutates the target, so it would be '
                'a new mutating assessment rather than a re-observation, and there is no independent '
                'oracle for how often the operation may succeed')
UNSUPPORTED_REASONS = {'race_condition_validator': _RACE_REASON, 'toctou_validator': _RACE_REASON}


def unsupported_reason(claim):
    return UNSUPPORTED_REASONS.get(claim['validator'], 'no independent audit procedure for this claim')


# Batch 08: a header rule applies only to a claim that names that header. A generic
# CONF-05 / misconfiguration claim from csp_validator is not a CSP claim and stays
# unsupported_audit, as do race claims (AR-08c, UNSUPPORTED_REASONS).
_HEADER_CLAIM_WORDS = ('content security policy', 'content-security-policy', 'csp', 'clickjacking',
                       'x-frame-options', 'frame-ancestors', 'cors', 'xss')


def header_claim(cls):
    return any(word in (cls or '') for word in _HEADER_CLAIM_WORDS)


def audit_for(claim):
    validator, cls = claim['validator'], claim['class']
    if validator == 'jwt_forge':
        return audit_jwt_forge
    if validator == 'sqlmap':
        return audit_sqlmap
    if validator == 'cors_validator' or (validator == 'csp_validator' and header_claim(cls)):
        return audit_headers
    if validator == 'recon_validator':
        return audit_recon
    if validator == 'websocket_validator':
        return audit_websocket
    if validator == 'verbose_error_validator':
        return audit_error_disclosure
    return None


# Each verdict is one audit state. Only an audited claim can be a false positive.
AUDITED = {'confirmed', 'confirmed_hardening', 'confirmed_observation', 'false_positive',
           'not_applicable', 'not_supported'}


def audit_state(verdict):
    if verdict in AUDITED:
        return 'audited'
    if verdict == 'unsupported_audit':
        return 'unsupported_audit'
    return 'not_audited'   # a rule exists but gave no conclusion (inconclusive, unresolved route)


def summarize(claims):
    """Totals that never read missing audit support as zero false positives: the rate
    is over audited claims only, and None when nothing was audited."""
    states = collections.Counter(audit_state(c.get('verdict')) for c in claims)
    audited = states['audited']
    fps = sum(c.get('verdict') == 'false_positive' for c in claims)
    return {'claims': len(claims), 'audited': audited, 'not_audited': states['not_audited'],
            'unsupported_audit': states['unsupported_audit'],
            'false_positives': fps if audited else None,
            'false_positive_rate': round(fps / audited, 4) if audited else None,
            'all_claims_audited': bool(claims) and audited == len(claims)}


# ---------------------------------------------------------------- main

def main(live, inventory_only):
    claims = inventory(live)
    print(json.dumps({'confirmed_claims': len(claims),
                      'by_validator': collections.Counter(c['validator'] for c in claims)}, default=str))
    for c in claims:
        print(c['validator'], '|', c['class'], '|', c['method'], c['url'], '|', c['resolved_from'],
              '|', c['accounting_kind'], '| proofs', len(c['proof_ids']),
              '| handler', getattr(audit_for(c), '__name__', None))
    if inventory_only:
        return
    private = {'accounts': []}
    target = Target(live / 'replay-audit-trace.jsonl')
    started = time.time()
    try:
        account = register(target, 'a', private)
        for index, claim in enumerate(claims):
            audit = audit_for(claim)
            if audit is None:
                claim.update(verdict='unsupported_audit', audit_state='unsupported_audit',
                             reason=unsupported_reason(claim), checks=[])
                continue
            if not claim['url']:
                claim.update(verdict='not_audited', audit_state='not_audited',
                             reason='the claimed route could not be resolved', checks=[])
                continue
            try:
                if audit is audit_sqlmap:
                    verdict, reason, checks = audit(target, claim, account, live, index)
                else:
                    verdict, reason, checks = audit(target, claim, account)
            except Exception as exc:  # recorded per claim; one failure never hides the rest
                verdict, reason, checks = 'inconclusive', f'audit error: {type(exc).__name__}: {exc}', []
            claim.update(verdict=verdict, audit_state=audit_state(verdict), reason=reason, checks=checks)
    finally:
        target.close()
        (live / 'replay-audit-private.json').write_text(json.dumps(private, indent=2), encoding='utf-8')
    summary = collections.defaultdict(collections.Counter)
    for c in claims:
        summary[f"{c['validator']} / {c['class']}"][c['verdict']] += 1
    out = {'target': BASE, 'started': started, 'finished': time.time(), 'requests': target.count,
           'request_ceiling': MAX_REQUESTS, 'script_sha256': sha(Path(__file__).read_bytes()),
           'accounts': [{'tag': a['tag'], 'fresh': True} for a in private['accounts']],
           'summary': {k: dict(v) for k, v in summary.items()}, 'audit_totals': summarize(claims),
           'claims': claims}
    (live / 'replay-audit.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    print(json.dumps({'requests': target.count, 'summary': out['summary'],
                      'audit_totals': out['audit_totals']}, indent=1))
    for c in claims:
        print(f"{c['verdict']:>20} | {c['validator']} | {c['class']} | {c['method']} {c['url']} | {c['reason']}")


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), '--inventory' in sys.argv[2:])
