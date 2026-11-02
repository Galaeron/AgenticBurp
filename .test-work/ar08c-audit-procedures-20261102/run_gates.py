"""AR-08c gates: precondition, smoke, this folder's audit tests and full, per interpreter.

Run from the worktree root. Logs go beside this file; SUMMARY.json keeps exit codes,
counts and failure lines only. Sources are hashed before and after each stage.
"""
import hashlib, json, os, pathlib, re, subprocess, sys, time

root = pathlib.Path.cwd()
out = root / '.test-work/ar08c-audit-procedures-20261102'
watched = sorted(p for p in subprocess.check_output(['git', 'ls-files', '--', 'harness'], text=True).splitlines()
                 if p.endswith('.py') and 'answer_key' not in p.lower()) + [
    'harness/config.yaml', '.test-work/ar08c-audit-procedures-20261102/replay_audit.py',
    '.test-work/ar08c-audit-procedures-20261102/test_replay_audit.py']


def hashes():
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in watched}


frozen = hashes()
interpreters = [('py314', r'C:\Users\arthu\AppData\Local\Python\pythoncore-3.14-64\python.exe'),
                ('py312', r'C:\Users\arthu\Documents\AgenticVibe\.venv-rationalisation\Scripts\python.exe')]
env = dict(os.environ, PYTHONPATH=str(root), PYTHONIOENCODING='utf-8')
stages = [('precondition', ['-m', 'unittest', 'harness.test_orchestrator_precondition']),
          ('smoke', ['-m', 'harness.suite', 'smoke']),
          ('audit', ['-W', 'error::ResourceWarning', '-m', 'unittest', 'discover', '-s', str(out), '-t', str(out),
                     '-p', 'test_replay_audit.py']),
          ('full', ['-m', 'harness.suite', 'full'])]
summary = {'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
           'diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff'])).hexdigest(), 'runs': []}
only = sys.argv[1:]
for label, exe in interpreters:
    if only and label not in only:
        continue
    who = subprocess.check_output([exe, '-c', 'import sys, harness, pathlib; print(sys.version.split()[0]); '
                                   'print(harness.__file__); assert pathlib.Path(harness.__file__).resolve()'
                                   '.is_relative_to(pathlib.Path.cwd())'], cwd=root, env=env, text=True)
    for name, args in stages:
        log_path = out / f'{label}-{name}.log'
        started = time.monotonic()
        with log_path.open('w', encoding='utf-8') as log:
            code = subprocess.run([exe, *args], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        counts, failures = [], []
        with log_path.open(encoding='utf-8', errors='replace') as log:
            for line in log:
                if re.search(r'^Ran \d+ tests|\d+ passed|^OK|^FAILED|^=+ .* in ', line):
                    counts.append(line.strip())
                if re.match(r'^(FAIL|ERROR): ', line):
                    failures.append(line.strip())
        unchanged = hashes() == frozen
        summary['runs'].append({'label': label, 'stage': name, 'identity': who.split(), 'exit_code': code,
                                'seconds': round(time.monotonic() - started, 1), 'counts': counts[-8:],
                                'failures': failures[:40], 'source_unchanged': unchanged})
        (out / f'SUMMARY{"-" + "-".join(only) if only else ""}.json').write_text(json.dumps(summary, indent=2),
                                                                             encoding='utf-8')
        print(label, name, code, counts[-3:], flush=True)
ok = all(r['exit_code'] == 0 and r['source_unchanged'] for r in summary['runs'])
summary['status'] = 'all gates passed' if ok else 'failed'
(out / f'SUMMARY{"-" + "-".join(only) if only else ""}.json').write_text(json.dumps(summary, indent=2),
                                                                     encoding='utf-8')
raise SystemExit(0 if ok else 1)
