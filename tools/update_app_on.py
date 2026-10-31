#!/usr/bin/env python3
"""Explicit app/backend update with PF retained. --check-only never stages/writes.

No PF enable/disable/load/flush, VPN commands, intent/config/token restoration,
helper-binary replacement, rights registration or app launch. Requires separately
approved --update-on. Old helper is restarted only to reload its client pin.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

BASE = Path('/Library/Application Support/V2BoxGuard')
KIT = Path(__file__).resolve().parents[1] / '.build/development-kit'
HELPER = Path('/Library/PrivilegedHelperTools/org.v2boxkillswitch.helper')
PLIST = Path('/Library/LaunchDaemons/org.v2boxkillswitch.helper.plist')
BACKEND = Path('/Library/PrivilegedHelperTools/org.v2boxkillswitch.backend')
LABEL = 'system/org.v2boxkillswitch.helper'
TARGETS = {'backend': BACKEND, 'app': BASE / 'V2BoxGuard.app', 'pin': BASE / 'client-pin'}
# Existing filtering, ownership and fixed backend entrypoint must be IDENTICAL.
CORE = ('__main__.py', 'controller.py', 'policy.py', 'pf_driver.py', 'token_store.py',
        'endpoints.py', 'gateways.py', 'backend_api.py')


def run(args):
    return subprocess.run([str(x) for x in args], capture_output=True, text=True,
                          check=True, timeout=30,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})


def trusted(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('untrusted installed path')
    if not directory and info.st_nlink != 1:
        raise RuntimeError('hard-linked installed file')


def digest(path):
    trusted(path)
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024: raise RuntimeError('oversized protected record')
    return hashlib.sha256(raw).hexdigest()


def signature(path):
    run(['/usr/bin/codesign', '--verify', '--strict', path])
    result = run(['/usr/bin/codesign', '-d', '--verbose=4', path])
    match = re.search(r'(?m)^CDHash=([a-f0-9]{40})$', result.stderr)
    if not match: raise RuntimeError('missing code signature')
    return match.group(1)


def compatible(old, new):
    with zipfile.ZipFile(old) as left, zipfile.ZipFile(new) as right:
        for archive in (left, right):
            if len(archive.namelist()) != len(set(archive.namelist())):
                raise RuntimeError('ambiguous duplicate backend entries')
        for name in CORE:
            if left.read(name) != right.read(name):
                raise RuntimeError('filtering/ownership module changed; On update refused')


def protection():
    intent = json.loads((BASE / 'state/intent.json').read_text())
    if (not isinstance(intent, dict) or set(intent) != {'version', 'enabled'}
            or type(intent['version']) is not int or intent['version'] != 1
            or intent['enabled'] is not True):
        raise RuntimeError('intent is not strictly On')
    info = run(['/sbin/pfctl', '-s', 'info']).stdout
    if 'Status: Enabled' not in info: raise RuntimeError('PF is not enabled')
    rules = run(['/sbin/pfctl', '-a', 'com.p30arena.v2box-killswitch', '-sr']).stdout
    if not rules.strip(): raise RuntimeError('project anchor is empty')
    return {'root': run(['/sbin/pfctl', '-sr']).stdout, 'anchor': rules,
            'intent': digest(BASE / 'state/intent.json'), 'approval': digest(BASE / 'approved.json'),
            'token': digest(BASE / 'state/pf-token.json'), 'pf_config': digest(Path('/etc/pf.conf')),
            'helper': digest(HELPER), 'helper_plist': digest(PLIST)}


def require_same(expected, snapshot=protection):
    if snapshot() != expected: raise RuntimeError('protection/configuration changed; update stopped')


def status(require_feature=False):
    value = json.loads(run([BACKEND, 'status']).stdout)
    if (value.get('state') != 'on' or value.get('policy_mode') != 'approved'
            or value.get('can_enable') != 'true' or value.get('can_disable') != 'true'):
        raise RuntimeError('exact approved enforcement not verified')
    if require_feature and value.get('can_auto_connect') != 'true':
        raise RuntimeError('new app reconnect capability unavailable')


def apply(staged, backup, expected, *, targets=TARGETS, runner=run, snapshot=protection):
    """Caller owns runtime.lock. Artifact-only rollback NEVER restores PF/intent.

    A single stopped-helper window, no candidate execution until it is over.
    This local function is not a privileged RPC or a caller-controlled command API.
    """
    moved = []
    stopped = False
    try:
        require_same(expected, snapshot)
        # Set before bootout: a command failure can still leave the service stopped.
        stopped = True
        runner(['/bin/launchctl', 'bootout', LABEL])
        require_same(expected, snapshot)
        for name, target in targets.items():
            require_same(expected, snapshot)
            os.replace(target, backup / name)
            moved.append(name)
            os.replace(staged / name, target)
        require_same(expected, snapshot)
        runner(['/bin/launchctl', 'bootstrap', 'system', PLIST])
        require_same(expected, snapshot)
    except BaseException:
        if stopped:
            # If rollback itself fails, stop and retain all backups. Never open
            # connectivity to make recovery appear successful.
            try: runner(['/bin/launchctl', 'bootout', LABEL])
            except Exception: pass
            for name in reversed(moved):
                target = targets[name]
                if target.exists():
                    if target.is_dir(): shutil.rmtree(target)
                    else: target.unlink()
                os.replace(backup / name, target)
            runner(['/bin/launchctl', 'bootstrap', 'system', PLIST])
        raise


def prepare(helper_hash):
    stage = Path(tempfile.mkdtemp(prefix='.on-app-update-', dir=BASE))
    stage.chmod(0o700)
    new, old = stage / 'new', stage / 'old'
    new.mkdir(mode=0o700); old.mkdir(mode=0o700)
    app = KIT / 'V2BoxGuard.app'; backend = KIT / 'org.v2boxkillswitch.backend'
    if any(p.is_symlink() for p in [app, *app.rglob('*'), backend]):
        raise RuntimeError('symlink in candidate artifact')
    shutil.copytree(app, new / 'app')
    shutil.copyfile(backend, new / 'backend'); (new / 'backend').chmod(0o755)
    for p in [new / 'app', *(new / 'app').rglob('*')]:
        p.chmod(p.stat().st_mode & ~0o022)
    signature(new / 'app')
    # Keep the CURRENT helper binary, not the development kit's newer helper.
    info_path = new / 'app/Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes()); info['GuardHelperCDHash'] = helper_hash
    info_path.write_bytes(plistlib.dumps(info))
    run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime',
         '--timestamp=none', new / 'app'])
    (new / 'pin').write_text(signature(new / 'app') + '\n'); (new / 'pin').chmod(0o600)
    compatible(BACKEND, new / 'backend')
    return new, old


def main():
    if os.geteuid() != 0 or sys.argv[1:] not in (['--check-only'], ['--update-on']):
        raise RuntimeError('root and explicit check-only/update-on flag required')
    for directory in [BASE, BASE / 'state', BACKEND.parent, PLIST.parent]: trusted(directory, True)
    for path in [HELPER, PLIST, BACKEND, BASE / 'client-pin']: trusted(path)
    trusted(BASE / 'V2BoxGuard.app', True)
    daemon = plistlib.loads(PLIST.read_bytes())
    if (daemon.get('Label') != 'org.v2boxkillswitch.helper'
            or daemon.get('ProgramArguments') != [str(HELPER), '--serve']
            or daemon.get('MachServices') != {'org.v2boxkillswitch.helper': True}):
        raise RuntimeError('unexpected installed helper launch configuration')
    helper_hash = signature(HELPER)
    app_hash = signature(BASE / 'V2BoxGuard.app')
    info = plistlib.loads((BASE / 'V2BoxGuard.app/Contents/Info.plist').read_bytes())
    if info.get('GuardHelperCDHash') != helper_hash or (BASE / 'client-pin').read_text().strip() != app_hash:
        raise RuntimeError('installed mutual pins do not match')
    compatible(BACKEND, KIT / 'org.v2boxkillswitch.backend')
    before = protection(); status(); require_same(before)
    if sys.argv[1:] == ['--check-only']:
        print('Read-only On preflight passed: exact approved enforcement, pins and identical filtering modules. No artifacts staged or updated.')
        return
    new, old = prepare(helper_hash)  # Stage/verify BEFORE taking the runtime lock.
    lockfd = os.open(BASE / 'state/runtime.lock', os.O_WRONLY | os.O_NOFOLLOW)
    with os.fdopen(lockfd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        apply(new, old, before)
    # Do not invoke backend while holding its runtime lock. Failure here leaves
    # PF retained and backups intact; no guessed rollback of live state.
    status(require_feature=True); require_same(before)
    if signature(HELPER) != helper_hash or signature(BASE / 'V2BoxGuard.app') != (BASE / 'client-pin').read_text().strip():
        raise RuntimeError('post-update pins not verified; backups retained')
    print('App/backend/client pin updated; PF, intent, approval, token and helper binary retained. Auto-reconnect defaults Off.')
    print('Backup retained at', old)
    print('Quit/reopen the menu app to use the new client. No app launch or VPN operation performed.')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('On-preserving update stopped:', type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
