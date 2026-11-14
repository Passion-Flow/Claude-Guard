"""Service-bound continuity DNS cache controls; no network or system changes."""
from pathlib import Path
import copy
import json
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
definitions = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]
host = 'checkip.amazonaws.com'
document = {'Status': 0, 'TC': False, 'Question': [{'name': host, 'type': 1}],
            'Answer': [{'name': host, 'type': 1, 'data': '9.9.9.9', 'TTL': 60}]}

with tempfile.TemporaryDirectory(prefix='cg-continuity-resolution-') as temporary:
    root = Path(temporary)
    setup = f'''
directory='{root}'; health_cache_file="$directory/cache"
health_request_budget=8; peer=192.0.2.7; phase=OPEN
route_via_tunnel() {{ [ "$1" = 8.8.8.8 ] && [ ! -f '{root}/wrong-route' ]; }}
tunnel_response() {{
 [ "$2" = --resolve ] || return 1
 if [ "$phase" = OPEN ]; then
   [ "$1" = 4 ] && [ "$3" = dns.google:443:8.8.8.8 ] &&
     [ "$4" = 'https://dns.google/resolve?name=checkip.amazonaws.com&type=A&edns_client_subnet=0.0.0.0/0' ] || return 1
 else
   [ "$1" = 2 ] && [ "$3" = cloudflare-dns.com:443:1.1.1.1 ] || return 1
 fi
 printf lookup >> '{root}/calls'
 /bin/cat '{root}/dns.json'
}}
independent_health_address
'''
    def run(cache, dns=None, phase='OPEN', clock=None):
        (root / 'calls').write_text('')
        (root / 'dns.json').write_text(json.dumps(document if dns is None else dns))
        if cache is None:
            (root / 'cache').unlink(missing_ok=True)
        else:
            (root / 'cache').write_text(cache)
        command = setup.replace('phase=OPEN', 'phase=' + phase)
        if phase == 'LOCKED':
            command = command.replace('health_request_budget=8', 'health_request_budget=4')
        code = definitions
        if clock is not None:
            (root / 'clock-values').write_text(json.dumps(clock))
            date = root / 'fixture-date'
            date.write_text('''#!/usr/bin/python3
from pathlib import Path
import json
p=Path(__file__).parent/'clock-values'
values=json.loads(p.read_text());value=values.pop(0);p.write_text(json.dumps(values));print(value)
''')
            date.chmod(0o700)
            code = code.replace('/bin/date', str(date))
        result = subprocess.run(['/bin/sh', '-c', code + command], capture_output=True, text=True, timeout=4)
        return result, (root / 'calls').read_text(), (root / 'cache').read_text() if (root / 'cache').exists() else ''

    now = int(time.time())
    result, calls, record = run(f'9.9.9.9|{now}|600|{host}')
    assert result.returncode == 0 and result.stdout == '9.9.9.9|8' and not calls

    for cache in (None, f'9.9.9.9|{now}', f'9.9.9.9|{now}|60|api.ipify.org',
                  f'9.9.9.9|{now - 61}|60|{host}', f'9.9.9.9|{now + 600}|60|{host}',
                  f'9.9.9.9|{now}|601|{host}', f'10.0.0.1|{now}|60|{host}',
                  f'192.0.2.7|{now}|60|{host}', f'9.9.9.9|{now}|60|{host}|extra',
                  f'9.9.9.9|{now}|60|{host}\nextra'):
        result, calls, record = run(cache)
        fields = result.stdout.split('|')
        assert result.returncode == 0 and len(fields) == 2 and fields[0] == '9.9.9.9' and 1 <= int(fields[1]) <= 7 and calls == 'lookup', (cache, result.stdout)
        assert record.strip().split('|')[2:] == ['60', host]

    for ttl, expected in ((0, 0), (1, 1), (600, 600), (3600, 600)):
        dns = copy.deepcopy(document); dns['Answer'][0]['TTL'] = ttl
        result, calls, record = run(None, dns)
        assert result.returncode == 0 and record.strip().split('|')[2] == str(expected), (ttl, result.stderr)
        if ttl == 0:
            result, calls, _ = run(record, dns)
            assert calls == 'lookup', 'A zero-TTL address was reused'

    for ttl in (None, -1, '60', True, 1.5):
        dns = copy.deepcopy(document)
        if ttl is None:
            del dns['Answer'][0]['TTL']
        else:
            dns['Answer'][0]['TTL'] = ttl
        result, _, _ = run(None, dns)
        assert result.returncode != 0, ('invalid-ttl', ttl)
    for key, value in (('Status', 3), ('TC', True)):
        dns = copy.deepcopy(document); dns[key] = value
        assert run(None, dns)[0].returncode != 0
    dns = copy.deepcopy(document); dns['Question'][0]['name'] = 'unrelated.invalid'
    assert run(None, dns)[0].returncode != 0
    for address in ('10.0.0.1', '192.0.2.7', '9.9.9.9\n8.8.8.8'):
        dns = copy.deepcopy(document); dns['Answer'][0]['data'] = address
        assert run(None, dns)[0].returncode != 0

    (root / 'wrong-route').touch()
    result, calls, _ = run(None)
    assert result.returncode != 0 and not calls, 'A physical resolver route was used'
    (root / 'wrong-route').unlink()
    result, calls, _ = run(None, phase='LOCKED')
    assert result.returncode == 0 and result.stdout == '9.9.9.9|2' and calls == 'lookup', 'Initial warming must retain its existing probe exception and budget'

    for finished, remaining in ((1000, 7), (1003, 4), (1006, 1)):
        result, calls, record = run(None, clock=[1000, finished])
        assert result.returncode == 0 and result.stdout == '9.9.9.9|' + str(remaining)
        assert record.split('|')[1] == '1000', 'Resolution work must not reset DNS age'
    for finished in (999, 1007, 1008, 1100):
        result, calls, _ = run(None, clock=[1000, finished])
        assert result.returncode != 0 and not result.stdout, 'Clock reversal or exhausted budget authorized a target request'

print('PASS: service identity, DNS TTL, expiry, rollback, shared request budgets and strict resolver response controls')

