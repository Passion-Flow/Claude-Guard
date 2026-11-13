"""Exercise actual concurrent health parsing, timestamps and cancellation.

Only curl is substituted. No network, installed helper, PF or host clock changes.
"""
from pathlib import Path
import json
import os
import signal
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cg-health-') as temporary:
    root = Path(temporary)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    curl = root / 'curl'
    curl.write_text('''#!/usr/bin/python3
from pathlib import Path
import json,os,sys,time
root=Path(__file__).parent
args=sys.argv[1:]
assert args[0]=='-q' and args[args.index('--noproxy')+1]=='*'
assert args[args.index('--interface')+1]=='if!utun1'
assert args[args.index('--proto')+1]=='=https' and '--tlsv1.2' in args
name='primary' if '1.1.1.1' in args[-1] else 'backup'
case=json.loads((root/'scenario.json').read_text())[name]
with (root/'started').open('a') as f:f.write(str(os.getpid())+'\\n')
budget=float(args[args.index('--max-time')+1])
time.sleep(min(case['delay'],budget))
if case['delay']>budget or case.get('unavailable'):raise SystemExit(28)
body=case.get('body','ip=192.0.2.42\\nloc=US\\n')
Path(args[args.index('--output')+1]).write_text(body)
print(case.get('status','200'),end='')
''')
    curl.chmod(0o700)
    source = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]
    source = source.replace('/usr/bin/curl', str(curl))
    command = source + f'''
directory='{runtime}'; iface=utun1; expected=192.0.2.42; risk_region=US
trap 'cleanup_health_round; exit 0' TERM
if sample_exit; then printf '%s|%s|%s' "$observed" "$probe_used" "$probe_observed_at"; else printf unavailable; fi
'''
    def scenario(primary, backup):
        (root / 'scenario.json').write_text(json.dumps({'primary': primary, 'backup': backup}))
        (root / 'started').write_text('')
    def run(primary, backup):
        scenario(primary, backup)
        began = time.monotonic()
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, check=True, timeout=7)
        assert not list(runtime.glob('health.*'))
        return result.stdout, time.monotonic() - began

    output, elapsed = run({'delay': 3}, {'delay': 3})
    assert output.startswith('192.0.2.42|') and elapsed < 5, (output, elapsed)
    output, elapsed = run({'delay': .1}, {'delay': 3.2})
    assert output.startswith('192.0.2.42|1.0.0.1|') and time.time() - int(output.split('|')[2]) < 2
    output, elapsed = run({'delay': .1}, {'delay': 3.2, 'unavailable': True})
    assert output.startswith('192.0.2.42|1.1.1.1|') and time.time() - int(output.split('|')[2]) >= 2
    output, _ = run({'delay': .1}, {'delay': .1, 'body': 'ip=192.0.2.99\nloc=US\n'})
    assert output.startswith('192.0.2.99|1.0.0.1|')
    output, _ = run({'delay': .1, 'body': 'ip=192.0.2.42\nloc=CN\n'}, {'delay': .2})
    assert output.startswith('192.0.2.42|1.1.1.1|')
    output, _ = run({'delay': .1, 'unavailable': True}, {'delay': .1})
    assert output.startswith('192.0.2.42|1.0.0.1|')
    for invalid in ['ip=192.0.2.42\nip=192.0.2.99', 'ip=192.0.2.\0' + '42', 'ip=192.0.2.42=extra']:
        output, _ = run({'delay': .1, 'body': invalid}, {'delay': .1, 'status': '302'})
        assert output == 'unavailable', output
    scenario({'delay': 3}, {'delay': 3})
    child = subprocess.Popen(['/bin/sh', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        end = time.monotonic() + 3
        while time.monotonic() < end and len((root / 'started').read_text().splitlines()) < 2:
            time.sleep(.05)
        assert len((root / 'started').read_text().splitlines()) == 2
        child.send_signal(signal.SIGTERM)
        child.communicate(timeout=6)
        assert child.returncode == 0 and not list(runtime.glob('health.*'))
        for pid in (root / 'started').read_text().splitlines():
            try:
                os.kill(int(pid), 0)
            except ProcessLookupError:
                continue
            raise AssertionError('Health child survived completed cleanup')
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()
    print('PASS: concurrent bounded HTTPS, actual observation age, wrong-backup rejection, strict responses and drained cancellation')
