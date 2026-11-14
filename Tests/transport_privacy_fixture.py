"""Actual worker failure handling with hostile transport errors; no network or PF."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
definitions = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]
with tempfile.TemporaryDirectory(prefix='transport-privacy-') as scratch:
    root = Path(scratch)
    curl = root / 'curl'
    curl.write_text('''#!/bin/sh
output=
while [ "$#" -gt 0 ]; do
  case "$1" in --output) output=$2; shift 2;; *) shift;; esac
done
root=$(dirname "$0")
code=$(cat "$root/code")
printf 'transport-secret https://example.invalid/private?key=private-secret 192.0.2.42 %s\\n' "$(cat "$root/error")" >&2
printf 'ip=192.0.2.42\\nloc=US\\n' > "$output"
if [ "$code" = 0 ]; then printf 200; else printf 000; fi
exit "$code"
''')
    curl.chmod(0o700)
    definitions = definitions.replace('/usr/bin/curl', str(curl))
    cases = [(0, '', 'none'), (6, '', 'resolution'), (7, '', 'connect'), (22, '', 'http'),
             (28, '', 'timeout'), (35, 'SSL_ERROR_SYSCALL', 'tls-peer-closed'),
             (35, 'unrecognized private error', 'tls-handshake'), (60, 'private certificate', 'tls-verification'),
             (52, '', 'empty-response'), (56, '', 'transfer'), (99, '', 'other')]
    for code, message, category in cases:
        (root / 'code').write_text(str(code))
        (root / 'error').write_text(message)
        runtime = root / ('case-' + str(code) + '-' + category)
        runtime.mkdir(mode=0o700)
        script = definitions + f'''
directory='{runtime}'; iface=utun1
if tunnel_response 4 https://example.invalid >/dev/null; then outcome=accepted; else outcome=rejected; fi
printf '%s|%s' "$outcome" "$(cat "$directory/transport-category")"
'''
        result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, check=True, timeout=5)
        assert result.stdout == ('accepted' if code == 0 else 'rejected') + '|' + category, result.stdout
        assert not result.stderr and not list(runtime.glob('probe.*'))
        for path in runtime.iterdir():
            assert not any(value in path.read_text() for value in ('private-secret', 'example.invalid', '192.0.2.42', message) if value)
    print('PASS: bounded transport categories, unchanged request verdicts and no retained raw error data')
