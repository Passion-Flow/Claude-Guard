"""Read-only installed-runtime acceptance with separate proof and heartbeat ages.

Run only through an authorized, root-owned, hash-pinned local controller.
Reports contain categories and durations, never route addresses or credentials.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid

PRODUCT = Path('/Library/PrivilegedHelperTools/org.claudeguard')
RUNTIME = Path('/var/run/org.claudeguard.runtime')
ANCHOR = 'com.apple/00000.org.claudeguard.runtime'
PF_READBACK = {'generationRetries': 0}


class EvidenceFailure(Exception):
    pass


def private_text(path, maximum, owner=0):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner or metadata.st_mode & 0o077:
            raise EvidenceFailure('private-file-permission')
        data = os.read(descriptor, maximum + 1)
        if len(data) > maximum:
            raise EvidenceFailure('private-file-size')
        return data.decode('utf-8')
    finally:
        os.close(descriptor)


def decode_evidence(text):
    fields = text.rstrip('\n').split('|')
    if len(fields) != 11 or fields[0] != '1' or '\n' in text.rstrip('\n'):
        raise EvidenceFailure('evidence-shape')
    if any(re.fullmatch(r'0|[1-9][0-9]{0,11}', fields[i]) is None for i in (3, 4, 5)):
        raise EvidenceFailure('evidence-time-format')
    if fields[10] not in ('0', '1'):
        raise EvidenceFailure('evidence-binding-format')
    return dict(session=fields[1], phase=fields[2], published=int(fields[3]), observed=int(fields[4]),
                risk=int(fields[5]), interface=fields[6], service=fields[7], endpoint=fields[8],
                expected=fields[9], bound=fields[10] == '1')


def binding_digest(intent):
    # Kept only in memory or root-only controller state, never in the report.
    return hashlib.sha256(json.dumps({k:intent.get(k) for k in
        ('route', 'serviceID', 'profileFingerprint', 'policy')},sort_keys=True).encode()).hexdigest()


def open_checks(evidence, intent, fence, now):
    route = intent.get('route') or {}
    endpoint = str(route.get('peer', '')) + ':' + str(route.get('port', '')) + '/' + str(route.get('transport', ''))
    return {
        'open': evidence['phase'] == 'OPEN',
        'armed-approved-persistent': all(intent.get(k) is True for k in ('armed','approved','persistent')),
        'not-maintenance': not intent.get('maintenance'),
        'session': evidence['session'] == intent.get('session') == fence.get('session'),
        'route': evidence['endpoint'] == endpoint and evidence['expected'] == route.get('expected'),
        'service': evidence['service'] == intent.get('serviceID'),
        'proof-context': evidence['bound'],
        'heartbeat-age': 0 <= now - evidence['published'] <= 12,
        'observation-age': evidence['observed'] > 0 and 0 <= now - evidence['observed'] <= 12,
        'risk-age': evidence['risk'] > 0 and 0 <= now - evidence['risk'] < 3600,
        'native-permission': fence.get('monitoring') is True and fence.get('openAllowed') is True
            and fence.get('powerBlocked') is False and fence.get('sleepPending') is not True,
    }


def command(arguments, timeout=10):
    return subprocess.run(list(map(str, arguments)), capture_output=True, timeout=timeout,
                          env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','HOME':'/var/empty'})


def pf_read(arguments):
    """Reject partial enumerations, including pfctl's zero-exit busy errors.

    A concurrent ruleset commit invalidates the enumeration ticket. Only that
    explicit read error permits a bounded reread. A complete missing boundary,
    disabled filter or expired authorization is never retried into a pass.
    No writer lock is held: observation must not delay the native lease seal.
    """
    warnings = {b'No ALTQ support in kernel', b'ALTQ related functions disabled'}
    busy = {b'pfctl: DIOCGETRULE: Resource busy', b'pfctl: DIOCGETADDRS: Resource busy'}
    for attempt in range(3):
        result = command(['/sbin/pfctl', *arguments], timeout=2)
        diagnostics = set(result.stderr.splitlines()) - warnings - {b''}
        if result.returncode == 0 and not diagnostics:
            return result
        if not diagnostics or not diagnostics.issubset(busy):
            raise EvidenceFailure('kernel-readback-unavailable')
        PF_READBACK['generationRetries'] += 1
        if attempt == 2:
            raise EvidenceFailure('kernel-generation-remained-unstable')
        time.sleep(.01)


def sample():
    # Retry only a concurrent publication/session transition. This never turns
    # an expired observation or a negative policy verdict into valid evidence.
    for attempt in range(3):
        first = private_text(RUNTIME/'evidence', 2048)
        intent = json.loads(private_text(PRODUCT/'state/intent.json', 32768))
        fence = json.loads(private_text(PRODUCT/'state/filter.json', 131072))
        last = private_text(RUNTIME/'evidence', 2048)
        if first == last:
            evidence = decode_evidence(last)
            now = int(time.time())
            return evidence, intent, fence, open_checks(evidence, intent, fence, now)
        time.sleep(.02)
    raise EvidenceFailure('concurrent-publication')


def kernel_matches(fence, require_open=True):
    info = pf_read(['-s','info'])
    rules = pf_read(['-a',ANCHOR,'-sr'])
    if info.returncode or rules.returncode or b'Status: Enabled' not in info.stdout:
        return False
    actual = rules.stdout.decode().strip()
    expected = str(fence.get('lastRules') or '').strip()
    return bool(actual) and actual == expected and 'CG_BLOCK' in actual and (
        not require_open or 'CG_TUNNEL' in actual)


def write_report(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.guard-observation-', dir=path.parent)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def failure_boundary():
    """Capture actual permission when a publication check fails.

    The status publication follows the kernel write. A stale OPEN label alone
    does not establish that the packet filter still admits tunnel traffic.
    These observations retain the original failure; they never convert it to
    a pass or extend the policy's lease.
    """
    began = time.monotonic()
    observations = []
    while time.monotonic() - began < 6:
        try:
            evidence, _, fence, _ = sample()
            rules = pf_read(['-a', ANCHOR, '-sr'])
            info = pf_read(['-s', 'info'])
            text = rules.stdout.decode().strip()
            now = int(time.time())
            row = {'seconds': round(time.monotonic() - began, 3), 'phase': evidence['phase'],
                   'proofAge': now - evidence['observed'] if evidence['observed'] else None,
                   'filterEnabled': info.returncode == 0 and b'Status: Enabled' in info.stdout,
                   'readbackAvailable': rules.returncode == 0,
                   'defaultDeny': 'block drop quick all label "CG_BLOCK"' in text,
                   'tunnelPassPresent': 'CG_TUNNEL' in text,
                   'matchesPersistedRules': text == str(fence.get('lastRules') or '').strip()}
        except Exception:
            row = {'seconds': round(time.monotonic() - began, 3), 'failure': 'boundary-observation-unavailable'}
        observations.append(row)
        if row.get('filterEnabled') and row.get('defaultDeny') and row.get('tunnelPassPresent') is False:
            break
        time.sleep(.2)
    return observations


def observe(seconds, report_path):
    if os.geteuid() != 0 or not 10 <= seconds <= 86400:
        raise EvidenceFailure('observer-authorization')
    if command([PRODUCT/'GuardDaemon','--validate-payload','/']).returncode:
        raise EvidenceFailure('installed-payload')
    started = time.monotonic()
    report = {'phase':'observing','scope':'Actual installed runtime with independent observation, heartbeat and risk ages; no network or state mutations',
              'samples':0,'nonOpenSamples':0,'riskRenewals':[],'failures':[]}
    counts = Counter()
    observation_ages = Counter()
    baseline = None
    session = None
    previous_risk = None
    previous_proof = None
    checked_at = 0
    saved_at = 0
    try:
        while time.monotonic() - started < seconds:
            evidence, intent, fence, checks = sample()
            identity = binding_digest(intent)
            if baseline is None:
                baseline,session,previous_risk = identity,evidence['session'],evidence['risk']
                previous_proof = evidence['observed']
            checks['configuration-unchanged'] = identity == baseline
            checks['session-unchanged'] = evidence['session'] == session
            if evidence['phase'] == 'OPEN':
                checks['observation-monotonic'] = evidence['observed'] >= previous_proof
            now = time.monotonic()
            if now - checked_at >= 5:
                checks['exact-kernel-readback'] = kernel_matches(fence)
                checked_at = now
            report['samples'] += 1
            counts[evidence['phase']] += 1
            if evidence['phase'] != 'OPEN':
                report['nonOpenSamples'] += 1
            observation_ages[str(int(time.time()) - evidence['observed']) if evidence['observed'] else 'unavailable'] += 1
            failed = [name for name,valid in checks.items() if not valid]
            if failed:
                report['failures'].append({'seconds':round(now-started,3),'checks':failed,'state':evidence['phase'],
                    'proofAge':int(time.time())-evidence['observed'] if evidence['observed'] else None})
                raise EvidenceFailure('installed-runtime-requirement')
            if evidence['risk'] > previous_risk:
                report['riskRenewals'].append({'seconds':round(now-started,3),
                    'oldEvidenceAgeAtRenewal':evidence['risk']-previous_risk})
            elif evidence['risk'] < previous_risk:
                raise EvidenceFailure('risk-time-regressed')
            previous_risk = evidence['risk']
            previous_proof = evidence['observed']
            if now - saved_at >= 30:
                report.update(seconds=round(now-started,3),states=dict(counts),
                              observationAgeCounts=dict(observation_ages),
                              kernelGenerationRetries=PF_READBACK['generationRetries'])
                write_report(report_path, report)
                saved_at = now
            time.sleep(.4)
        report['phase'] = 'passed'
    except Exception as error:
        report['phase'] = 'failed'
        # Exception text can include paths or provider data. Only fixed local
        # categories from this module may enter the shared result.
        report['failure'] = str(error) if isinstance(error,EvidenceFailure) else type(error).__name__
    finally:
        if report['phase'] == 'failed':
            report['failureBoundary'] = failure_boundary()
            # Capture immediately: a later inspection could lose the bounded
            # transport history while the live worker continues recovering.
            try:
                rows = private_text(RUNTIME/'health-events', 65536).splitlines()[-60:]
                report['healthRounds'] = [row for row in rows if len(row.split('|')) == 17]
            except Exception:
                report['healthHistoryUnavailable'] = True
            try:
                rows = private_text(RUNTIME/'transport-events', 65536).splitlines()[-60:]
                categories = {'none','resolution','connect','http','timeout','tls-handshake','tls-peer-closed','tls-verification','empty-response','transfer','other','unavailable'}
                report['transportCategories'] = [row for row in rows if len(row.split('|')) == 5 and
                    all(re.fullmatch(r'[0-9]{1,12}', value) for value in row.split('|')[:2]) and
                    all(value in categories for value in row.split('|')[2:])]
            except Exception:
                report['transportHistoryUnavailable'] = True
        report.update(seconds=round(time.monotonic()-started,3),states=dict(counts),
                      observationAgeCounts=dict(observation_ages),
                      kernelGenerationRetries=PF_READBACK['generationRetries'])
        write_report(report_path, report)
    return 0 if report['phase'] == 'passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds',type=int,required=True)
    parser.add_argument('--report',type=Path,required=True)
    options = parser.parse_args()
    raise SystemExit(observe(options.seconds,options.report))

