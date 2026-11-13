"""Opt-in development fixture: change only the selected VMess host, then restore.

Requires explicit operator approval for configuration-file access. Never part of
installed Guard. Credentials and opaque payloads are neither decoded nor logged.
The backup stays mode 0600 inside the application's own private group container.
"""
from pathlib import Path
import copy
import hashlib
import ipaddress
import json
import os
import plistlib
import stat
import sys
import tempfile
import time

BASE = Path.home() / 'Library/Group Containers/group.com.liguangming.Shadowrocket'
ARCHIVE = BASE / 'ServerManager'
PREFERENCES = BASE / 'Library/Preferences/group.com.liguangming.Shadowrocket.plist'


def read(path, limit=4194304):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= limit
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            value = stream.read(limit + 1)
        assert len(value) <= limit
        return value
    finally:
        os.close(fd)


def selected(data, selection):
    value = plistlib.loads(data)
    objects = value['$objects']
    def scalar(item, depth=0):
        assert depth <= 5
        if isinstance(item, plistlib.UID): return scalar(objects[item.data], depth + 1)
        if isinstance(item, dict) and 'NS.string' in item: return scalar(item['NS.string'], depth + 1)
        return item
    matches = [r for r in objects if isinstance(r, dict) and 'uuid' in r and scalar(r['uuid']) == selection]
    assert len(matches) == 1
    return value, matches[0], scalar


def replace_host(data, selection, expected, replacement):
    value, row, scalar = selected(data, selection)
    assert scalar(row['host']) == expected
    original = copy.deepcopy(value)
    objects = value['$objects']
    old = objects[row['host'].data]
    if isinstance(old, str):
        new = replacement
    else:
        assert isinstance(old, dict) and 'NS.string' in old
        new = copy.deepcopy(old)
        if isinstance(new['NS.string'], plistlib.UID):
            new['NS.string'] = plistlib.UID(len(objects))
            objects.append(replacement)
        else:
            assert isinstance(new['NS.string'], str)
            new['NS.string'] = replacement
    old_reference = row['host']
    row['host'] = plistlib.UID(len(objects))
    objects.append(new)
    encoded = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
    checked, target, resolve = selected(encoded, selection)
    assert resolve(target['host']) == replacement
    # The original graph is unchanged except this single metadata reference;
    # appended string objects do not alter credential or payload objects.
    restored_graph = copy.deepcopy(checked)
    restored_graph['$objects'] = restored_graph['$objects'][:len(original['$objects'])]
    restored_row = next(r for r in restored_graph['$objects'] if isinstance(r, dict) and r.get('uuid') == row['uuid'])
    restored_row['host'] = old_reference
    assert restored_graph == original
    return encoded


def atomic_replace(path, expected, replacement):
    assert read(path) == expected
    metadata = path.stat()
    fd, temporary = tempfile.mkstemp(prefix='.ClaudeGuard-', dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        with os.fdopen(fd, 'wb') as stream:
            stream.write(replacement); stream.flush(); os.fsync(stream.fileno())
        assert read(path) == expected
        os.replace(temporary, path)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def stage(route_path):
    cfg = json.loads(read(Path(route_path), 16384))
    return stage_configuration(cfg)


def stage_configuration(cfg):
    assert ipaddress.ip_address(cfg['peer']).version == 4 and ipaddress.ip_address(cfg['peer']).is_global
    prefs = plistlib.loads(read(PREFERENCES, 65536))
    assert prefs['group.com.liguangming.GlobalRoutingMethod'] == 'Proxy'
    selection = prefs['group.com.liguangming.SelectedServerUUID']
    if 'profileSelection' in cfg:
        assert selection == cfg['profileSelection'], 'Selected profile changed before the test'
    current = read(ARCHIVE)
    value, row, scalar = selected(current, selection)
    assert scalar(row['type']).lower() == 'vmess'
    assert scalar(row['tls']) in (False, 0, '0') and scalar(row['allowInsecure']) in (False, 0, '0')
    assert scalar(row['alterId']) == '0' and scalar(row['method']) in ('chacha20-poly1305', 'aes-128-gcm')
    host = scalar(row['host'])
    if 'profileHostHash' in cfg:
        assert hashlib.sha256(host.encode()).hexdigest() == cfg['profileHostHash'], 'Profile host changed before the test'
    if 'port' in cfg:
        assert scalar(row['port']) == str(cfg['port']), 'Profile port changed before the test'
    planned = replace_host(current, selection, host, cfg['peer'])
    directory = Path(tempfile.mkdtemp(prefix='.ClaudeGuard-Test-', dir=BASE));directory.chmod(0o700)
    for name, data in [('original', current), ('planned', planned)]:
        fd=os.open(directory/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(data)
    manifest = {'selection':selection,'originalHost':host,'temporaryHost':cfg['peer'],'originalHash':hashlib.sha256(current).hexdigest()}
    path = directory/'manifest.json';path.write_text(json.dumps(manifest));path.chmod(0o600)
    return path


def apply(path):
    manifest=json.loads(read(path, 16384));directory=path.parent
    prefs=plistlib.loads(read(PREFERENCES,65536));assert prefs['group.com.liguangming.SelectedServerUUID']==manifest['selection']
    original=read(directory/'original');assert hashlib.sha256(original).hexdigest()==manifest['originalHash']
    atomic_replace(ARCHIVE,original,read(directory/'planned'))


def restore(path):
    if not path.exists():return
    manifest=json.loads(read(path,16384));current=read(ARCHIVE)
    _,row,scalar=selected(current,manifest['selection'])
    host=scalar(row['host'])
    if host==manifest['temporaryHost']:
        replacement=replace_host(current,manifest['selection'],host,manifest['originalHost'])
        atomic_replace(ARCHIVE,current,replacement)
    else:
        assert host==manifest['originalHost'], 'Host changed by another actor; no overwrite performed'
    for name in ['original','planned','manifest.json']:(path.parent/name).unlink()
    path.parent.rmdir()


if __name__ == '__main__':
    operation=sys.argv[1]
    if operation=='stage':
        result=stage(sys.argv[2]);print(result)
    elif operation=='stage-stdin':
        encoded=sys.stdin.buffer.read(16385)
        assert len(encoded)<=16384
        result=stage_configuration(json.loads(encoded));print(result)
    elif operation=='apply':
        apply(Path(sys.argv[2]));print('PASS: one temporary host reference applied; credentials unchanged')
    elif operation=='restore':
        restore(Path(sys.argv[2]));print('PASS: original host restored; test backup removed')
    elif operation=='auto-restore':
        path=Path(sys.argv[2]);deadline=time.monotonic()+1200
        while path.exists() and time.monotonic()<deadline:time.sleep(2)
        if path.exists():restore(path)
    else:raise SystemExit(64)
