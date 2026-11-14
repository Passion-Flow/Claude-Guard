"""Bounded, opt-in installed continuity control using real provider replies.

Run only from the reviewed, root-owned acceptance directory with exact payload
pins. Terminate only the current worker's two selected health requests. Never change PF,
routes, caches, risk, time or approval, and never inject an address response.
"""
from pathlib import Path
import json
import runpy
import threading
import time

ROOT = Path('/Library/PrivilegedHelperTools/org.claudeguard.stability-acceptance')


def observe(seconds=90, healthy_provider='independent', trace_operator=False):
    if healthy_provider not in ('primary','backup','independent'):
        raise ValueError('provider-selection')
    if trace_operator and healthy_provider != 'independent':
        raise ValueError('operator-selection')
    result_path = Path('/var/tmp/org.claudeguard-provider-' + healthy_provider +
                       ('-operator' if trace_operator else '') + '.json')
    if not 30 <= seconds <= 300:
        raise ValueError('bounded-duration')
    control = runpy.run_path(str(ROOT / 'controller.py'))
    controller = control['Controller']()
    failure = control['AcceptanceFailure']
    entry = {'case': 'only-' + healthy_provider + '-available', 'phase': 'preparing'}
    controller.report['cases'].append(entry)
    stop = threading.Event()
    injections = {'terminated': 0, 'error': None}
    thread = None
    report = {'phase': 'preparing', 'scope': 'Real single-provider continuity; unchanged production approval and evidence lifetimes', 'healthyProvider': healthy_provider,
              'traceOperatorLoss': trace_operator}
    report['postFaultContinuous'] = False
    began = time.monotonic()
    report['startedAt'] = time.time()
    diagnostic_rows = {'health-events': [], 'transport-events': []}
    diagnostic_seen = {'health-events': set(), 'transport-events': set()}
    def retain_transport_rows():
        for name in diagnostic_rows:
            try:
                for row in (control['RUNTIME'] / name).read_text().splitlines():
                    expected = 17 if name == 'health-events' else 5
                    if len(row.split('|')) != expected or row in diagnostic_seen[name]:
                        continue
                    diagnostic_seen[name].add(row)
                    diagnostic_rows[name].append(row)
                diagnostic_rows[name][:] = diagnostic_rows[name][-400:]
            except OSError:
                report['diagnosticReadUnavailable'] = True
    try:
        evidence, intent = controller.wait_open(entry, stable_seconds=5)
        report['beforeRequest'] = control['anonymous_request'](controller.config['uid'])
        if not report['beforeRequest']['httpResponse']:
            raise failure('service-positive-control-unavailable')
        worker = control['selected_process']('worker', intent)
        session = evidence['session']
        original_risk = evidence['risk']
        def resolution_stamp():
            fields = (control['RUNTIME'] / 'independent-address').read_text().strip().split('|')
            if (len(fields) != 4 or fields[3] != 'checkip.amazonaws.com' or
                not fields[1].isdigit() or not fields[2].isdigit() or
                not 0 <= int(fields[2]) <= 600 or not 0 < int(fields[1]) <= int(time.time())):
                raise failure('independent-resolution-context')
            return int(fields[1]), int(fields[2])
        if trace_operator:
            resolved_at, ttl = resolution_stamp()
            # Observe beyond the actual existing TTL, never rewrite its cache.
            seconds = max(seconds, max(0, resolved_at + ttl - int(time.time())) + 20)
            if seconds > 620 or int(time.time()) - original_risk + seconds >= 3580:
                raise failure('operator-control-window-unavailable')
            report['initialResolutionRemainingSeconds'] = max(0, resolved_at + ttl - int(time.time()))
        fault_at = time.monotonic()
        fault_epoch = int(time.time())
        report['faultStartedAt'] = time.time()
        retain_transport_rows()
        observations = set()
        resolutions = set()
        def interrupt():
            try:
                while not stop.is_set() and time.monotonic() - fault_at < seconds:
                    injections['terminated'] += control['terminate_health_requests'](
                        worker, healthy_provider=healthy_provider, trace_operator=trace_operator)
                    stop.wait(.15)
            except Exception as error:
                injections['error'] = type(error).__name__
        thread = threading.Thread(target=interrupt, daemon=True)
        thread.start()
        report['phase'] = 'observing'
        control['write_json'](result_path, report, public=True)
        while time.monotonic() - fault_at < seconds:
            current, _, fence, checks, sealed = controller.snapshot(entry)
            retain_transport_rows()
            if current['session'] != session or sealed or not all(checks.values()):
                report['failedChecks'] = [key for key, value in checks.items() if not value]
                raise failure('continuous-open-not-established')
            if not controller.runtime['kernel_matches'](fence):
                raise failure('kernel-readback')
            for line in (control['RUNTIME'] / 'health-events').read_text().splitlines():
                fields = line.split('|')
                if len(fields) == 17 and int(fields[0]) >= fault_epoch and fields[4] == healthy_provider and fields[{'primary':10,'backup':13,'independent':16}[healthy_provider]] == '1':
                    observations.add(fields[6])
            if trace_operator:
                resolved_at, _ = resolution_stamp()
                if resolved_at > fault_epoch:
                    resolutions.add(resolved_at)
            time.sleep(.4)
        report['healthyProviderObservations'] = len(observations)
        report['riskTimestampUnchanged'] = current['risk'] == original_risk
        if injections['terminated'] < 2 or not observations:
            raise failure('selective-loss-or-healthy-control-missing')
        if trace_operator:
            report['independentResolutionsDuringLoss'] = len(resolutions)
            if not resolutions:
                raise failure('independent-dns-renewal-not-observed')
        stop.set()
        thread.join(timeout=20)
        if thread.is_alive() or injections['error']:
            raise failure('fault-control')
        # The end of injection must not hide a delayed seal followed by recovery.
        # Require the same OPEN session throughout a full original identity lease
        # plus observation margin before claiming continuity.
        tail_started = time.monotonic()
        while time.monotonic() - tail_started < 15:
            current, _, fence, checks, sealed = controller.snapshot(entry)
            retain_transport_rows()
            if current['session'] != session or sealed or not all(checks.values()):
                report['failedChecks'] = [key for key, value in checks.items() if not value]
                raise failure('post-fault-continuity-not-established')
            if not controller.runtime['kernel_matches'](fence):
                raise failure('post-fault-kernel-readback')
            time.sleep(.4)
        report['postFaultContinuous'] = True
        report['postFaultSeconds'] = round(time.monotonic() - tail_started, 3)
        report['afterRequest'] = control['anonymous_request'](controller.config['uid'])
        if not report['afterRequest']['httpResponse']:
            raise failure('service-after-control-unavailable')
        report['phase'] = 'passed'
    except Exception as error:
        report['phase'] = 'failed'
        report['failure'] = str(error) if isinstance(error, (failure, controller.runtime['EvidenceFailure'])) else type(error).__name__
    finally:
        stop.set()
        if thread is not None:
            thread.join(timeout=20)
        retain_transport_rows()
        report['transportDiagnostics'] = diagnostic_rows
        report['endedAt'] = time.time()
        report['injection'] = injections
        report['seconds'] = round(time.monotonic() - began, 3)
        report['observations'] = entry
        report['kernelGenerationRetries'] = controller.runtime['PF_READBACK']['generationRetries']
        if report['phase'] == 'failed':
            report['failureBoundary'] = controller.runtime['failure_boundary']()
        control['write_json'](result_path, report, public=True)
    return 0 if report['phase'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(observe())
