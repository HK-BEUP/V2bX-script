#!/usr/bin/env python3
"""Exact observation patch gate, ONLY on a fresh GitHub-hosted amd64 VM.

Never run on customer servers. Build transfers only public source/binaries;
root fixture credentials remain in the disposable VM, never in artifacts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request
import zipfile

REPO = 'HK-BEUP/V2bX-script'
BRANCH = 'refs/heads/beup/observation-amd64-20260913'
ROOT = Path('/root/beup-systemd-qa')
PATCH_SHA = '3c6d649998c78696ca57b74cca2a64b4610793548c7f95933a98b626711b081a'
CORE_SHA = '3b2c6f655458685afeaf0aaa2981f4e2e5ffb42b3c3566ae70061bf90545ae60'
BINARY_SHA = 'b765ee0045ba3c509938337f574e32b0ac49633312afaca42655b70b36a79254'
CORE_URL = 'https://github.com/HK-BEUP/V2bX/releases/download/v25.12.2-beup-observe-rc.1/V2bX-linux-64.zip'
SOURCES = {
    'build.py': 'b8aede6eedba3e7825eef72cab019c067f077265371053db963708cbe706323f',
    'patch.py': 'bbe9d978eed4aedaa304be027d95239814cee8b77f67fd0b66b7afdb6aae39c4',
    'agent/main.go': '67f3881beaf4f84b170db30d73a9034c0b6f4074dc8ad19f14e18567f5e9af76',
    'agent/go.mod': 'ec355f817d9f10d616b73a3584270b60f7d5a265ebb6fd52f4ca0e8f92696193',
}
AGENTS = {'x86_64': 'd9575895c675aa6d643d7a418b73d8dd72cbbb6ed8de68b4db621ff6c5cf0527',
          'aarch64': 'e36e3ff7d2ad2e24d4e75bcf95f113ba4b26a7b275a6064e3469795f8db773eb'}
UNITS = ('beup-observe-renew.timer', 'beup-observe-renew.service', 'beup-qa-client.service',
         'V2bX.service', 'beup-qa-fixture.service')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def guard(env, system, machine, pid1):
    required = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': REPO, 'GITHUB_REF': BRANCH}
    if any(env.get(k) != v for k, v in required.items()) or (system, machine, pid1) != ('Linux', 'x86_64', 'systemd'):
        raise RuntimeError('fresh GitHub-hosted amd64 test branch required')


def fresh():
    for p in (ROOT, Path('/etc/V2bX'), Path('/usr/local/V2bX'), Path('/etc/beup-observe'),
              Path('/usr/local/lib/beup-observe'), Path('/usr/local/.backups/beup-observe'),
              Path('/etc/systemd/system/V2bX.service.d'),
              Path('/usr/local/share/ca-certificates/beup-disposable-qa.crt')):
        if p.exists() or p.is_symlink():
            raise RuntimeError('refuse existing proxy or fixture state')
    for unit in UNITS:
        p = subprocess.run(['systemctl', 'show', unit, '-p', 'LoadState', '--value'],
                           capture_output=True, text=True, timeout=10)
        if p.stdout.strip() != 'not-found':
            raise RuntimeError('refuse existing systemd unit')


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def inspect_patch(path):
    if sha(path) != PATCH_SHA:
        raise RuntimeError('rebuilt archive differs from original patch')
    with zipfile.ZipFile(path) as z:
        names = ['agent-x86_64', 'agent-aarch64', 'patch.py', 'manifest.json']
        if sorted(z.namelist()) != sorted(names):
            raise RuntimeError('unexpected patch members')
        m = json.loads(z.read('manifest.json'))
        if m['agents'] != AGENTS or m['patch_sha256'] != SOURCES['patch.py']:
            raise RuntimeError('patch manifest mismatch')
        for machine, want in AGENTS.items():
            if hashlib.sha256(z.read('agent-' + machine)).hexdigest() != want:
                raise RuntimeError('agent differs from original artifact')
        if hashlib.sha256(z.read('patch.py')).hexdigest() != SOURCES['patch.py']:
            raise RuntimeError('installer differs from original artifact')


def build(source, temp):
    if os.geteuid() == 0:
        raise RuntimeError('compile as unprivileged runner')
    for name, want in SOURCES.items():
        if sha(source / name) != want:
            raise RuntimeError('fixed source mismatch')
    version = subprocess.run(['go', 'version'], capture_output=True, text=True, check=True).stdout
    if version.strip() != 'go version go1.26.5 linux/amd64':
        raise RuntimeError('original Go toolchain required')
    dest = temp / 'beup-observation-input'
    dest.mkdir(mode=0o700)
    # A separate directory avoids adding Git VCS stamping to the original build.
    clean = Path(tempfile.mkdtemp(prefix='beup-observe-build-', dir=temp))
    for name in SOURCES:
        p = clean / name
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, p)
    env = dict(os.environ, GOENV='off', GOFLAGS='', GOWORK='off', GOTOOLCHAIN='local')
    p = subprocess.run(['/usr/bin/python3', str(clean / 'build.py')], env=env,
                       capture_output=True, text=True, timeout=300)
    if p.returncode:
        raise RuntimeError('rebuild failed')
    reply = json.loads(p.stdout)
    package = Path(reply['bundle']) / 'beup-observation-patch-local.zip'
    inspect_patch(package)
    shutil.copyfile(package, dest / 'patch.zip')
    # No installer execution: fixed public HTTPS release + exact SHA before extraction.
    req = urllib.request.Request(CORE_URL, headers={'User-Agent': 'BEUP-isolated-amd64-QA'})
    with urllib.request.urlopen(req, timeout=60) as r:
        if not r.geturl().startswith('https://'):
            raise RuntimeError('HTTPS required')
        data = r.read(134217729)
    if len(data) > 134217728 or hashlib.sha256(data).hexdigest() != CORE_SHA:
        raise RuntimeError('core archive mismatch')
    (dest / 'core.zip').write_bytes(data)
    save(temp / 'beup-observation-results/build.json', {
        'ok': True, 'patch_sha256': sha(dest / 'patch.zip'), 'core_zip_sha256': CORE_SHA,
        'agents': AGENTS, 'source_sha256': SOURCES, 'toolchain': version.strip(),
        'exact_original_patch': True, 'published': False})
    print(json.dumps({'ok': True, 'phase': 'build', 'exact_original_patch': True}), flush=True)


def run(source, temp):
    if os.geteuid() != 0:
        raise RuntimeError('disposable runner root required')
    fresh()  # ALL refusal checks before the first system file write.
    dest = temp / 'beup-observation-input'
    inspect_patch(dest / 'patch.zip')
    if sha(dest / 'core.zip') != CORE_SHA:
        raise RuntimeError('fixed core mismatch')
    os.umask(0o077)
    ROOT.mkdir(mode=0o700)
    result = {'ok': False, 'architecture': platform.machine(), 'runner': 'github-hosted',
              'commit': os.environ.get('GITHUB_SHA'), 'patch_sha256': PATCH_SHA,
              'core_zip_sha256': CORE_SHA, 'enforcement': False,
              'production_operations': False, 'started_at': time.time()}
    try:
        for name in ('fixture.py', 'acceptance.py'):
            shutil.copyfile(source / name, ROOT / name)
        package = ROOT / 'package'
        package.mkdir()
        with zipfile.ZipFile(dest / 'patch.zip') as z:
            for name in z.namelist():
                p = package / name
                p.write_bytes(z.read(name))
                p.chmod(0o755 if name.startswith('agent-') else 0o600)
        program = Path('/usr/local/V2bX/V2bX')
        program.parent.mkdir()
        conf = Path('/etc/V2bX')
        conf.mkdir(mode=0o700)
        with zipfile.ZipFile(dest / 'core.zip') as z:
            data = z.read('V2bX')
            if hashlib.sha256(data).hexdigest() != BINARY_SHA:
                raise RuntimeError('core binary mismatch')
            program.write_bytes(data)
            program.chmod(0o755)
            for name in ('geoip.dat', 'geosite.dat'):
                (conf / name).write_bytes(z.read(name))
        (ROOT / 'DISPOSABLE_VM_ONLY').write_text('GitHub-hosted amd64 synthetic QA only\n')
        for phase in ('setup', 'test'):
            proc = subprocess.Popen(['/usr/bin/python3', str(ROOT / 'acceptance.py'), phase],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for line in proc.stdout:
                # Child emits assertion names/counts only; no private raw logs.
                item = json.loads(line)
                print(json.dumps(item), flush=True)
            rc = proc.wait(timeout=30)
            name = 'setup-results.json' if phase == 'setup' else 'results.json'
            value = json.loads((ROOT / name).read_text())
            result[phase] = value
            if rc or not value.get('ok'):
                raise RuntimeError('synthetic lifecycle assertion failed')
        result['ok'] = True
    except Exception as exc:
        result['failure_type'] = type(exc).__name__
    finally:
        for unit in UNITS:
            subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=30)
        result['test_services_stopped'] = all(subprocess.run(
            ['systemctl', 'is-active', '--quiet', unit], capture_output=True, timeout=10).returncode != 0
            for unit in UNITS)
        result['finished_at'] = time.time()
        result['ok'] = result['ok'] and result['test_services_stopped']
        # Do not export root fixture files, backups, tickets, leases or journals.
        save(temp / 'beup-observation-results/systemd.json', result)
    print(json.dumps({'ok': result['ok'], 'phase': 'lifecycle'}), flush=True)
    return 0 if result['ok'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('build', 'run'))
    args = parser.parse_args()
    guard(os.environ, platform.system(), platform.machine(), Path('/proc/1/comm').read_text().strip())
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    source = Path(__file__).resolve().parent
    if args.phase == 'build':
        build(source, temp)
        return 0
    return run(source, temp)


if __name__ == '__main__':
    raise SystemExit(main())
