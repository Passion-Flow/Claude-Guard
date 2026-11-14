"""Root-only packet metadata controls against the installed production filter.

Never installed by the product. The positive control connects only to the
already approved node. Negative controls bind explicitly to its physical
interface. Only synthetic example.invalid queries are generated. Captures
select the individual test flow; addresses and payloads are never retained.
"""
from pathlib import Path
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import subprocess
import threading
import time

ANCHOR = 'com.apple/00000.org.claudeguard.runtime'
RUNTIME = Path('/var/run/org.claudeguard.runtime')
PRODUCT = Path('/Library/PrivilegedHelperTools/org.claudeguard')


def run(args):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=8,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})


def block_counter():
    result = run(['/sbin/pfctl', '-a', ANCHOR, '-vvsr'])
    if result.returncode:
        raise RuntimeError('rule-counter-unavailable')
    selected = False
    for line in result.stdout.decode().splitlines():
        if line.startswith('@'):
            selected = 'label "CG_BLOCK"' in line
        if selected:
            match = re.search(r'Packets:\s+([0-9]+)', line)
            if match:
                return int(match[1])
    raise RuntimeError('block-counter-unavailable')


def packet(interface, destination, port, protocol='udp', positive=False):
    address = ipaddress.ip_address(destination)
    ipv6 = address.version == 6
    before = block_counter()
    channel = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,
                            socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    channel.settimeout(5 if positive else 1.5)
    channel.setsockopt(socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP,
                       125 if ipv6 else 25, socket.if_nametoindex(interface))
    channel.bind(('::' if ipv6 else '', 0))
    source_port = channel.getsockname()[1]
    expression = f'dst host {address} and {protocol} and dst port {int(port)} and src port {source_port}'
    logger = subprocess.Popen(['/usr/sbin/tcpdump', '-p', '-n', '-l', '-s', '96', '-i', interface, expression],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    ready = threading.Event()
    capture = {'headers': 0, 'dropped': None}
    def headers():
        for line in logger.stdout:
            if re.match(r'^\d\d:\d\d:\d\d[.]\d+ IP6? ', line):
                capture['headers'] += 1
    def metadata():
        for line in logger.stderr:
            if f'listening on {interface}' in line:
                ready.set()
            match = re.match(r'^([0-9]+) packets dropped by kernel', line)
            if match:
                capture['dropped'] = int(match[1])
    threads = [threading.Thread(target=fn, daemon=True) for fn in (headers, metadata)]
    for thread in threads:
        thread.start()
    result = {'family': address.version, 'protocol': protocol, 'positive': positive,
              'destinationPort': port, 'responseReceived': False, 'socketError': None}
    try:
        if not ready.wait(3):
            raise RuntimeError('physical-capture-not-ready')
        query_id = os.urandom(2)
        query = query_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x07example\x07invalid\x00\x00\x01\x00\x01'
        try:
            if protocol == 'tcp':
                channel.connect((str(address), port))
                if positive or port != 53:
                    result['responseReceived'] = True
                else:
                    channel.sendall(struct.pack('!H', len(query)) + query)
                    response = channel.recv(4096)
                    result['responseReceived'] = len(response) >= 14 and response[2:4] == query_id
            else:
                channel.sendto(query, (str(address), port))
                response, sender = channel.recvfrom(4096)
                result['responseReceived'] = len(response) >= 12 and response[:2] == query_id and sender[0] == str(address)
        except OSError as error:
            result['socketError'] = error.errno if error.errno is not None else 'timeout'
        time.sleep(.2)
    finally:
        channel.close()
        logger.send_signal(signal.SIGINT)
        try:
            logger.wait(timeout=3)
        except subprocess.TimeoutExpired:
            logger.kill()
            logger.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
    result['physicalTapHeaders'] = capture['headers']
    result['captureDroppedPackets'] = capture['dropped']
    result['aggregateBlockCounterIncrease'] = block_counter() - before
    return result


def probe(expected_phase):
    if os.geteuid() != 0 or expected_phase not in ('OPEN', 'LOCKED'):
        raise RuntimeError('packet-control-authorization')
    intent = json.loads((PRODUCT / 'state/intent.json').read_text())
    route = intent['route']
    if not all(intent.get(name) is True for name in ('armed', 'approved', 'persistent')):
        raise RuntimeError('approved-production-required')
    status = (RUNTIME / 'evidence').read_text().strip().split('|')
    if status[2] != expected_phase:
        raise RuntimeError('expected-phase-required')
    # A packet-tunnel provider can bind its node socket to an underlay while
    # the ordinary, unscoped route for the same address still names the VPN.
    # Intersect current active physical links with the actual bootstrap rules.
    nwi = run(['/usr/sbin/scutil', '--nwi'])
    rules = run(['/sbin/pfctl', '-a', ANCHOR, '-sr'])
    active = set(re.findall(r'^\s*(en[0-9]+)\s*:', nwi.stdout.decode(), re.M))
    allowed = set(re.findall(r'^pass out quick on (en[0-9]+) .*label "CG_PEER_OUT"$', rules.stdout.decode(), re.M))
    interfaces = sorted(active & allowed)
    if len(interfaces) != 1 or route['transport'] != 'tcp':
        raise RuntimeError('supported-physical-node-control-required')
    interface = interfaces[0]
    began = time.time()
    positive = packet(interface, route['peer'], int(route['port']), 'tcp', True)
    results = []
    for destination in ('223.5.5.5', '2606:4700:4700::1111'):
        for protocol, port in (('udp', 53), ('tcp', 53), ('tcp', 853), ('tcp', 443), ('udp', 443)):
            results.append(packet(interface, destination, port, protocol))
    after = (RUNTIME / 'evidence').read_text().strip().split('|')
    stable = after[1] == status[1] and after[2] == expected_phase
    positive_verified = (positive['responseReceived'] and positive['physicalTapHeaders'] > 0
                         and positive['captureDroppedPackets'] == 0)
    for row in results:
        row['noMatchingPhysicalHeadersObserved'] = row['physicalTapHeaders'] == 0 and row['captureDroppedPackets'] == 0
        row['positiveControlVerifiedForFamily'] = positive_verified and row['family'] == positive['family']
        # The aggregate counter is corroboration, not attribution to a specific
        # socket. Describe the observed boundary without claiming a wire tap.
        row['classified'] = ('unavailable-path' if row['socketError'] in (49, 50, 65) and not row['responseReceived'] else
            'no-physical-egress-observed' if row['positiveControlVerifiedForFamily'] and stable and row['noMatchingPhysicalHeadersObserved'] and
            row['aggregateBlockCounterIncrease'] > 0 and not row['responseReceived'] else 'inconclusive')
    return {'scope': 'Individual physical test-flow header captures and aggregate PF block counts; positive control is only the approved node, not general underlay access',
            'phase': expected_phase, 'startedAt': began, 'seconds': round(time.time() - began, 3),
            'sameSessionAndPhase': stable, 'positiveControlVerified': positive_verified,
            'positiveControl': positive, 'negativeControls': results}


if __name__ == '__main__':
    raise SystemExit('Use only a reviewed, hash-pinned root controller')
