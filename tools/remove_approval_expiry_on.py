#!/usr/bin/env python3
"""Explicit migration: remove ONLY active approval expiry, keep PF/peers unchanged.

Patches only endpoints.py in the installed zipapp with the reviewed None-expiry
implementation. No app/helper binary update, VPN command, PF mutation or renewal
of other profiles. Requires explicit root --remove-expiry-on approval.
"""
import copy
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = Path('/Library/Application Support/V2BoxGuard')
BACKEND = Path('/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend')
CONFIG = BASE / 'approved.json'
OLD_HASH = '17e9a57cf0ecdde169b071dfcd7f93cd93fd6bcb274fe43cbacbff66421501d4'
NEW_HASH = '957f5756dd96c4e81eb2d4b243d80517fa50e8cec1eaeac531c745f8fe729d5f'


def sha(data): return hashlib.sha256(data).hexdigest()


def rewrite_backend(original, module):
    if sha(module) != NEW_HASH: raise RuntimeError('unreviewed replacement module')
    prefix = b'#!/usr/bin/python3 -I\n'
    if not original.startswith(prefix): raise RuntimeError('unexpected zipapp entrypoint')
    with zipfile.ZipFile(io.BytesIO(original)) as old:
        names = old.namelist()
        if len(names) != len(set(names)): raise RuntimeError('duplicate archive entries')
        if sha(old.read('endpoints.py')) != OLD_HASH: raise RuntimeError('unreviewed installed module')
        output = io.BytesIO(); output.write(prefix)
        with zipfile.ZipFile(output, 'w') as new:
            for entry in old.infolist():
                new.writestr(copy.copy(entry), module if entry.filename == 'endpoints.py' else old.read(entry.filename))
        result = output.getvalue()
        with zipfile.ZipFile(io.BytesIO(result)) as new:
            if new.namelist() != names: raise RuntimeError('archive membership changed')
            for name in names:
                if name != 'endpoints.py' and new.read(name) != old.read(name):
                    raise RuntimeError('unrelated module changed')
        return result


def permanent_config(raw):
    value = json.loads(raw)
    entry = value['inventory']['profiles'][value['profile']]
    if entry['expires_at'] is None: raise RuntimeError('approval already has no expiry')
    entry['expires_at'] = None
    result = json.dumps(value, indent=2).encode() + b'\n'
    # Compare everything except the explicitly authorized field.
    check = json.loads(result)
    check['inventory']['profiles'][check['profile']]['expires_at'] = json.loads(raw)['inventory']['profiles'][value['profile']]['expires_at']
    if check != json.loads(raw): raise RuntimeError('unrelated configuration changed')
    return result


def atomic(path, raw, mode):
    fd, name = tempfile.mkstemp(prefix='.expiry-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode); out.write(raw); out.flush(); os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


def checked_status(u):
    # The running menu/helper may briefly own runtime.lock. Retry READS only.
    for attempt in range(4):
        try:
            u['status'](require_feature=True)
            return
        except subprocess.CalledProcessError:
            if attempt == 3: raise
            time.sleep(0.5)


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ['--remove-expiry-on']:
        raise RuntimeError('root and explicit removal approval required')
    u = runpy.run_path(str(ROOT / 'tools/update_app_on.py'))
    before = u['protection'](); checked_status(u); u['require_same'](before)
    original, config = BACKEND.read_bytes(), CONFIG.read_bytes()
    replacement = rewrite_backend(original, (ROOT / 'src/endpoints.py').read_bytes())
    permanent = permanent_config(config)
    archive = Path(tempfile.mkdtemp(prefix='.expiry-removal-', dir=BASE)); archive.chmod(0o700)
    atomic(archive / 'old-backend', original, 0o600)
    atomic(archive / 'old-approval.json', config, 0o600)
    expected = dict(before); expected['approval'] = sha(permanent)
    lockfd = os.open(BASE / 'state/runtime.lock', os.O_WRONLY | os.O_NOFOLLOW)
    with os.fdopen(lockfd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        u['require_same'](before)
        if BACKEND.read_bytes() != original or CONFIG.read_bytes() != config:
            raise RuntimeError('preimage changed')
        stopped = False
        try:
            stopped = True
            u['run'](['/bin/launchctl', 'bootout', u['LABEL']])
            u['require_same'](before)
            atomic(BACKEND, replacement, 0o755)  # New code still accepts numeric old approval.
            atomic(CONFIG, permanent, 0o600)
            u['require_same'](expected)
            u['run'](['/bin/launchctl', 'bootstrap', 'system', u['PLIST']])
            u['require_same'](expected)
        except BaseException:
            if stopped:
                try: u['run'](['/bin/launchctl', 'bootout', u['LABEL']])
                except Exception: pass
                atomic(CONFIG, config, 0o600)
                atomic(BACKEND, original, 0o755)
                u['run'](['/bin/launchctl', 'bootstrap', 'system', u['PLIST']])
            raise
    checked_status(u); u['require_same'](expected)
    print('Active endpoint approval now has no expiry. Exact endpoints, PF rules, intent and token retained. No VPN stop/start or app relaunch.')
    print('Private pre-change backup:', archive)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Expiry removal stopped:', type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
