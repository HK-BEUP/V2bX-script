#!/usr/bin/env python3
"""Actual systemd + released V2bX + exact patch/agent acceptance in a VM.

Run only in the disposable guest created for this suite, never a customer node.
Assertions/results contain synthetic counts and hashes, never credentials.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import termios
import time
import urllib.request

from fixture import BODY, ROOT, setup, write

PACKAGE = ROOT / 'package'
BACKUPS = Path('/usr/local/.backups/beup-observe')
DATA = Path('/etc/beup-observe')
PROGRAM = Path('/usr/local/V2bX/V2bX')
BINARY_SHAS = {
    'aarch64': 'cfc490da0bafe2fc8dcd2639b15f6d519350a7b5c4c2f1e392e0730c10511338',
    'x86_64': 'b765ee0045ba3c509938337f574e32b0ac49633312afaca42655b70b36a79254',
}
BINARY_SHA = BINARY_SHAS.get(os.uname().machine)
checks = []
transcripts = []
last_step = 'initialize'


def check(name, success, detail=None):
    global last_step
    last_step = name
    item = {'name': name, 'ok': bool(success)}
    if detail is not None:
        item['detail'] = detail
    checks.append(item)
    print(json.dumps(item), flush=True)
    if not success:
        raise AssertionError(name)


def command(args, timeout=95):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def systemctl(*args):
    return command(['systemctl', *args])


def props(unit='V2bX'):
    out = systemctl('show', unit, '-p', 'ActiveState', '-p', 'MainPID', '-p', 'NRestarts').stdout
    return dict(line.split('=', 1) for line in out.splitlines() if '=' in line)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected():
    files = [PROGRAM, Path('/etc/systemd/system/V2bX.service')]
    files += sorted(p for p in Path('/etc/V2bX').rglob('*') if p.is_file())
    return {str(p): [sha(p), stat.S_IMODE(p.stat().st_mode), p.stat().st_uid, p.stat().st_gid] for p in files}


def recv(sock, size):
    result = b''
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise ConnectionError('synthetic proxy closed')
        result += part
    return result


def proxy():
    with socket.create_connection(('127.0.0.1', 11080), timeout=8) as sock:
        sock.sendall(b'\x05\x01\x00')
        if recv(sock, 2) != b'\x05\x00':
            return False
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', 18080))
        head = recv(sock, 4)
        if head[:2] != b'\x05\x00':
            return False
        recv(sock, {1: 4, 4: 16}.get(head[3], 0) + 2)
        # Keep the HTTP Host inside the guest too: normal Xray sniffing may
        # route by Host even when SOCKS requested a loopback IP.
        sock.sendall(b'GET /qa/proxy HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nConnection: close\r\n\r\n')
        response = b''
        while True:
            part = sock.recv(65536)
            if not part:
                break
            response += part
        return b'200 OK' in response and response.endswith(BODY)


def wait_for(predicate, timeout=75, traffic=False):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return True
        if traffic:
            try:
                if not proxy():
                    return False
            except (OSError, ConnectionError):
                return False
        time.sleep(1)
    return False


def stats():
    return json.loads((ROOT / 'stats.json').read_text())


def control(**changes):
    path = ROOT / 'control.json'
    write(path, json.loads(path.read_text()) | changes)


def ticket():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request('http://127.0.0.1:18080/qa/ticket', data=b'{}')
    with opener.open(req, timeout=5) as response:
        return json.load(response)


def patch(args, enrollment=None, interrupt=False):
    """Exercise the real CLI hidden prompt; never pass a ticket in argv/env."""
    argv = ['/usr/bin/python3', str(PACKAGE / 'patch.py'), *args]
    if enrollment is None and not interrupt:
        result = command(argv)
        transcripts.append(result.stdout + result.stderr)
        return result.returncode, result.stdout + result.stderr
    before_pid = props()['MainPID']
    before_backups = set(BACKUPS.glob('patch-*')) if BACKUPS.exists() else set()
    pid, fd = os.forkpty()
    if pid == 0:
        os.execv(argv[0], argv)
    output = b''
    sent = False
    interrupted_backup = None
    until = time.monotonic() + 100
    try:
        while time.monotonic() < until:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    part = os.read(fd, 32768)
                except OSError:
                    part = b''
                output += part
            if enrollment is not None and not sent and '隐藏输入' in output.decode(errors='replace'):
                if termios.tcgetattr(fd)[3] & termios.ECHO:
                    raise RuntimeError('hidden prompt unexpectedly echoes')
                encoded = base64.urlsafe_b64encode(json.dumps(enrollment).encode()).rstrip(b'=')
                os.write(fd, encoded + b'\n')
                sent = True
            if interrupt and sent:
                for candidate in set(BACKUPS.glob('patch-*')) - before_backups:
                    receipt = candidate / 'record.json'
                    if not receipt.exists():
                        continue
                    record = json.loads(receipt.read_text())
                    state = props()
                    if (record['status'] == 'activating' and state['ActiveState'] == 'active'
                            and state['MainPID'] not in ('0', before_pid)):
                        interrupted_backup = candidate
                        os.kill(pid, signal.SIGKILL)  # Only this test-owned installer child.
                        _, status = os.waitpid(pid, 0)
                        pid = None
                        check('interrupt_hits_real_health_window', os.WIFSIGNALED(status))
                        transcripts.append(output.decode(errors='replace'))
                        return -signal.SIGKILL, str(interrupted_backup)
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                pid = None
                transcript = output.decode(errors='replace')
                transcripts.append(transcript)
                return os.waitstatus_to_exitcode(status), transcript
        raise TimeoutError('test-owned patch CLI timed out')
    finally:
        os.close(fd)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def receipt(kind='patch'):
    return max(BACKUPS.glob(kind + '-*'), key=lambda p: p.stat().st_mtime_ns)


def all_managed_removed():
    return (not Path('/usr/local/lib/beup-observe').exists()
            and not Path('/etc/systemd/system/V2bX.service.d/90-beup-observe.conf').exists()
            and not Path('/etc/systemd/system/beup-observe-renew.timer').exists()
            and not Path('/etc/systemd/system/beup-observe-renew.service').exists())


def bootstrap(provision=True):
    check('systemd_pid1', Path('/proc/1/comm').read_text().strip() == 'systemd')
    check('native_supported_architecture', os.uname().machine in BINARY_SHAS)
    check('released_binary_sha256', sha(PROGRAM) == BINARY_SHA)
    if provision:
        setup()
    else:
        check('retry_existing_synthetic_fixture', (ROOT / 'secret.json').is_file()
              and not (ROOT / 'baseline.json').exists() and not DATA.exists())
    check('private_guest_ca_installed', command(['update-ca-certificates']).returncode == 0)
    check('unit_reload', systemctl('daemon-reload').returncode == 0)
    check('fixture_started', systemctl('start', 'beup-qa-fixture').returncode == 0)
    check('fixture_ready', wait_for(lambda: (ROOT / 'stats.json').exists(), timeout=15))
    check('real_server_started', systemctl('start', 'V2bX').returncode == 0)
    check('real_client_started', systemctl('start', 'beup-qa-client').returncode == 0)
    time.sleep(3)
    check('baseline_authenticated_proxy', proxy())
    write(ROOT / 'baseline.json', protected())


def acceptance():
    baseline = json.loads((ROOT / 'baseline.json').read_text())
    check('fresh_baseline_unchanged', protected() == baseline)
    state = props()
    code, out = patch(['plan'])
    plan = json.loads(out)
    check('plan_is_read_only', code == 0 and not plan['requires_upgrade']
          and plan['requires_restart'] and props() == state and protected() == baseline)
    enrollment = ticket()
    code, _ = patch(['apply'], enrollment)
    check('restart_permission_required', code != 0 and props() == state and not DATA.exists())
    wrong = enrollment | {'node_ids': [8]}
    code, _ = patch(['apply', '--restart'], wrong)
    check('different_node_refused_before_stop', code != 0 and props() == state and not DATA.exists())
    code, out = patch(['apply', '--restart'], enrollment)
    check('real_cli_install', code == 0, {'exit_code': code})
    check('binary_config_original_unit_preserved', protected() == baseline)
    check('proxy_after_install', proxy())
    installed = json.loads((DATA / 'installed.json').read_text())
    check('durable_installed_receipt', installed['status'] == 'installed' and not installed['upgraded'])
    check('private_credentials', stat.S_IMODE(DATA.stat().st_mode) == 0o700 and all(
        stat.S_IMODE((DATA / p).stat().st_mode) == 0o600 and (DATA / p).stat().st_uid == 0
        for p in ('client.json', 'settings.json', 'lease.json', 'installed.json')))
    check('timer_enabled_and_active', systemctl('is-enabled', '--quiet', 'beup-observe-renew.timer').returncode == 0
          and props('beup-observe-renew.timer')['ActiveState'] == 'active')
    hardening = systemctl('show', 'beup-observe-renew.service', '-p', 'NoNewPrivileges',
        '-p', 'PrivateTmp', '-p', 'ProtectHome', '-p', 'ProtectSystem', '-p', 'MemoryMax').stdout
    check('real_renewal_unit_hardening', all(x in hardening for x in (
        'NoNewPrivileges=yes', 'PrivateTmp=yes', 'ProtectHome=yes', 'ProtectSystem=strict', 'MemoryMax=134217728')))
    stable = props()
    previous = stats()['renew']
    started = time.monotonic()
    check('natural_systemd_timer_renews', wait_for(lambda: stats()['renew'] > previous, 145, traffic=True),
          {'wait_seconds': round(time.monotonic() - started, 2)})
    check('renew_does_not_restart_proxy', props() == stable and proxy())
    check('actual_authenticated_core_report', wait_for(lambda: stats()['attributed_requests'] > 0, 70, traffic=True))
    check('report_identity_and_unknown_metrics', stats()['bad_subject'] == 0
          and stats()['bad_signature'] == 0 and stats()['null_metrics_verified'] > 0)
    code, _ = patch(['apply', '--restart', '--resume'])
    check('duplicate_install_refused', code != 0 and props() == stable)

    control(renew_status=503)
    check('unavailable_renewal_fails_only_agent', systemctl('start', 'beup-observe-renew.service').returncode != 0
          and stats()['renew_rejected'] > 0 and props() == stable and proxy())
    control(renew_status=200, ingest_status=503)
    rejected = stats()['ingest_rejected']
    check('core_503_failure_does_not_stop_proxy', wait_for(lambda: stats()['ingest_rejected'] >= rejected + 2,
          70, traffic=True) and props() == stable and proxy())
    control(renew_status=403, ingest_status=403)
    check('revoked_renewal_does_not_stop_proxy', systemctl('start', 'beup-observe-renew.service').returncode != 0
          and props() == stable and proxy())
    control(renew_status=200, ingest_status=200)
    check('renewal_recovers_without_proxy_restart', systemctl('start', 'beup-observe-renew.service').returncode == 0
          and props() == stable and proxy())

    code, _ = patch(['remove'])
    check('remove_restart_permission_required', code != 0 and props() == stable)
    code, out = patch(['remove', '--restart'])
    check('real_cli_remove', code == 0)
    retired = receipt('remove') / 'retired-observation-data'
    check('removal_recoverable_private_quarantine', retired.is_dir() and (retired / 'client.json').is_file()
          and stat.S_IMODE(retired.parent.stat().st_mode) == 0o700 and not DATA.exists())
    check('remove_preserves_proxy_and_config', proxy() and protected() == baseline and all_managed_removed())
    check('timer_disabled_after_remove', systemctl('is-enabled', '--quiet', 'beup-observe-renew.timer').returncode != 0
          and props('beup-observe-renew.timer')['ActiveState'] != 'active')

    write(ROOT / 'fail-activation', b'synthetic failpoint')
    code, _ = patch(['apply', '--restart'], ticket())
    check('real_failed_activation_rolls_back', code != 0 and all_managed_removed() and proxy()
          and protected() == baseline and json.loads((receipt() / 'record.json').read_text())['status'] == 'rolled_back')
    (ROOT / 'fail-activation').unlink()
    check('failed_activation_keeps_resume_credentials', (DATA / 'client.json').is_file())
    code, _ = patch(['apply', '--restart', '--resume'])
    check('resume_without_new_ticket', code == 0 and proxy() and protected() == baseline)
    code, _ = patch(['remove', '--restart'])
    check('remove_resumed_patch', code == 0 and proxy() and all_managed_removed())

    code, backup = patch(['apply', '--restart'], ticket(), interrupt=True)
    check('forced_interruption_receipt', code == -signal.SIGKILL
          and json.loads((Path(backup) / 'record.json').read_text())['status'] == 'activating'
          and not (DATA / 'installed.json').exists())
    stable = props()
    code, _ = patch(['recover', '--backup', backup])
    check('recover_restart_permission_required', code != 0 and props() == stable)
    managed = Path('/etc/systemd/system/V2bX.service.d/90-beup-observe.conf')
    original = managed.read_bytes()
    write(managed, original + b'# synthetic operator drift\n', 0o644)
    code, _ = patch(['recover', '--backup', backup, '--restart'])
    check('operator_drift_refused_before_stop', code != 0 and props() == stable
          and managed.read_bytes() == original + b'# synthetic operator drift\n')
    write(managed, original, 0o644)  # Restore only the exact test-injected bytes.
    code, _ = patch(['recover', '--backup', backup, '--restart'])
    check('interrupted_install_recovers', code == 0 and proxy() and all_managed_removed()
          and protected() == baseline)
    code, _ = patch(['apply', '--restart', '--resume'])
    check('recovered_install_can_resume', code == 0 and proxy())
    code, _ = patch(['remove', '--restart'])
    check('final_removal_keeps_service', code == 0 and proxy() and all_managed_removed()
          and protected() == baseline and props()['NRestarts'] == '0')
    secret = json.loads((ROOT / 'secret.json').read_text())
    transcript = '\n'.join(transcripts)
    for file in BACKUPS.glob('*/**/client.json'):
        client = json.loads(file.read_text())
        check('device_key_not_in_cli_output', client['device_key'] not in transcript)
    check('fixture_secrets_not_in_cli_output', all(value not in transcript for value in secret.values()))
    check('final_released_binary_sha256', sha(PROGRAM) == BINARY_SHA)
    return {'counts': stats(), 'protected_files': baseline, 'binary_sha256': sha(PROGRAM),
            'server_state': props(), 'synthetic_panel_only': True, 'real_laravel_fpm': False,
            'real_customer_acceptance': False, 'enforcement': False}


if __name__ == '__main__':
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir() or not (ROOT / 'DISPOSABLE_VM_ONLY').is_file():
        raise SystemExit('disposable QA VM marker and Linux/systemd root required')
    result = {'ok': False, 'checks': checks, 'architecture': os.uname().machine}
    try:
        if sys.argv[1] in ('setup', 'verify-setup'):
            bootstrap(provision=sys.argv[1] == 'setup')
        else:
            result.update(acceptance())
        result['ok'] = True
    except Exception as error:
        result['failure'] = {'step': last_step, 'type': type(error).__name__}
        # Logs stay private inside the guest; failure text may include no secrets.
    finally:
        write(ROOT / ('setup-results.json' if sys.argv[1] != 'test' else 'results.json'), result)
        print(json.dumps({'ok': result['ok'], 'checks': len(checks), 'failure': result.get('failure')}), flush=True)
    raise SystemExit(0 if result['ok'] else 1)
