#!/usr/bin/env python3
"""Synthetic loopback panel for a disposable, native Linux/systemd VM only.

No production roster, key, hostname, payload or account is accepted as input.
Secrets are generated inside the guest and never included in exported results.
This is a protocol fixture, not a substitute for the real Laravel/FPM gate.
"""
import base64
import datetime
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import threading
import time
import urllib.parse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from cryptography.x509.oid import NameOID

ROOT = Path('/root/beup-systemd-qa')
HOST = 'observer.example.test'
BASE = 'https://' + HOST + ':18444'
ENDPOINT = BASE + '/api/v1/attack-guard/observation'
NODE = 'synthetic-systemd-amd64' if os.uname().machine == 'x86_64' else 'synthetic-systemd-arm64'
UID = 700001
BODY = b'BEUP synthetic loopback proxy request OK\n'


def write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        data = json.dumps(data, separators=(',', ':')).encode()
    elif isinstance(data, str):
        data = data.encode()
    temporary = path.with_name('.' + path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as handle:
        os.fchmod(handle.fileno(), mode)
        handle.write(data)
    os.replace(temporary, path)


def raw(key, private=False):
    if private:
        return key.private_bytes(serialization.Encoding.Raw,
                                 serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def setup():
    if ROOT.exists() and (ROOT / 'secret.json').exists():
        raise RuntimeError('fixture already initialized')
    ROOT.mkdir(mode=0o700, exist_ok=True)
    ROOT.chmod(0o700)
    sign = ed25519.Ed25519PrivateKey.generate()
    reality = x25519.X25519PrivateKey.generate()
    private = {'api_key': secrets.token_hex(32), 'uuid': str(uuid.uuid4()),
               'reality_private': b64(raw(reality, True)),
               'reality_public': b64(raw(reality.public_key())),
               'short_id': secrets.token_hex(8), 'sign_private': raw(sign, True).hex(),
               'sign_public': raw(sign.public_key()).hex(),
               'observation_key': secrets.token_hex(32), 'key_id': secrets.token_hex(8),
               'subject': secrets.token_hex(16)}
    write(ROOT / 'secret.json', private)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable BEUP QA CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=10))
          .not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=10))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    write(ROOT / 'tls.key', key.private_bytes(serialization.Encoding.PEM,
          serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    write(ROOT / 'tls.crt', cert.public_bytes(serialization.Encoding.PEM))
    write('/usr/local/share/ca-certificates/beup-disposable-qa.crt',
          ca.public_bytes(serialization.Encoding.PEM), 0o644)
    with open('/etc/hosts', 'a') as hosts:
        hosts.write('\n127.0.0.1 ' + HOST + '\n')
    server = {'Log': {'Level': 'warn', 'Output': ''},
              'Cores': [{'Type': 'xray', 'Log': {'Level': 'warning'}}],
              'Nodes': [{'Core': 'xray', 'ApiHost': BASE, 'ApiKey': private['api_key'],
                         'NodeID': 7, 'NodeType': 'vless', 'Timeout': 3,
                         'ListenIP': '127.0.0.1', 'SendIP': '127.0.0.1',
                         'DeviceOnlineMinTraffic': 0, 'MinReportTraffic': 0}]}
    write('/etc/V2bX/config.json', server)
    # The exact released binary provides both proxy ends; no second core build.
    write(ROOT / 'client-in.json', [{'listen': '127.0.0.1', 'port': 11080,
          'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}])
    write(ROOT / 'client-out.json', [{'protocol': 'vless', 'settings': {'vnext': [{
          'address': '127.0.0.1', 'port': 18443, 'users': [{'id': private['uuid'],
          'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]}, 'streamSettings': {
          'network': 'tcp', 'security': 'reality', 'realitySettings': {
          'serverName': HOST, 'fingerprint': 'chrome',
          'publicKey': private['reality_public'], 'shortId': private['short_id']}}}])
    write(ROOT / 'client.json', {'Log': {'Level': 'warn', 'Output': ''}, 'Nodes': [],
          'Cores': [{'Type': 'xray', 'Log': {'Level': 'warning'},
                     'InboundConfigPath': str(ROOT / 'client-in.json'),
                     'OutboundConfigPath': str(ROOT / 'client-out.json')}]})
    write(ROOT / 'failpoint.py', 'import os,sys\nfrom pathlib import Path\n'
          'sys.exit(1 if os.getenv("BEUP_OBSERVATION_CONFIG") and '
          'Path("/root/beup-systemd-qa/fail-activation").exists() else 0)\n')
    # Fault injection is installed before the protected baseline is captured.
    write('/etc/systemd/system/V2bX.service', '[Unit]\nDescription=Disposable real V2bX QA\n'
          'After=network.target beup-qa-fixture.service\n[Service]\nType=simple\nUser=root\n'
          'ExecStartPre=/usr/bin/python3 /root/beup-systemd-qa/failpoint.py\n'
          'ExecStart=/usr/local/V2bX/V2bX server\nRestart=no\n'
          'LimitNOFILE=65536\n[Install]\nWantedBy=multi-user.target\n', 0o644)
    write('/etc/systemd/system/beup-qa-client.service', '[Unit]\nDescription=Synthetic proxy client\n'
          '[Service]\nType=simple\nUser=root\nExecStart=/usr/local/V2bX/V2bX server '
          '-c /root/beup-systemd-qa/client.json\nRestart=no\n', 0o644)
    write('/etc/systemd/system/beup-qa-fixture.service', '[Unit]\nDescription=Synthetic loopback panel\n'
          '[Service]\nType=simple\nUser=root\nExecStart=/usr/bin/python3 '
          '/root/beup-systemd-qa/fixture.py serve\nRestart=no\n', 0o644)
    write(ROOT / 'control.json', {'renew_status': 200, 'ingest_status': 200, 'lease_seconds': 900})


class Fixture:
    def __init__(self):
        self.secret = json.loads((ROOT / 'secret.json').read_text())
        self.sign = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.secret['sign_private']))
        self.lock = threading.Lock()
        self.device = None
        self.code = None
        self.expiry = 0
        self.sequence = 0
        self.stats = {key: 0 for key in ('config', 'users', 'proxy_requests', 'enroll', 'renew',
                     'renew_rejected', 'ingest_rejected', 'authenticated_reports',
                     'attributed_requests', 'null_metrics_verified', 'bad_signature', 'bad_subject')}
        self.stats['reports'] = []

    def persist(self):
        write(ROOT / 'stats.json', self.stats)

    def issue(self):
        self.code = secrets.token_hex(32)
        self.expiry = int(time.time()) + 600
        # Independent installations represent a new synthetic enrollment.
        self.device = None
        return {'node': NODE, 'code': self.code, 'expires_at': self.expiry,
                'public_key': self.secret['sign_public'], 'endpoint': ENDPOINT,
                'api_host': BASE, 'node_ids': [7], 'observation_only': True}

    def envelope(self):
        self.sequence += 1
        now = int(time.time())
        control = json.loads((ROOT / 'control.json').read_text())
        claims = {'version': 1, 'node': NODE, 'sequence': self.sequence, 'issued_at': now,
                  'expires_at': now + control['lease_seconds'], 'identity_revision': 'qa-systemd-v1',
                  'endpoint': ENDPOINT, 'key_id': self.secret['key_id'],
                  'observation_key': self.secret['observation_key'],
                  'bindings': {'[' + BASE + ']-vless:7': {str(UID): self.secret['subject']}}}
        payload = json.dumps(claims, separators=(',', ':')).encode()
        signature = self.sign.sign(b'BEUP-OBSERVATION-REGISTRY-V1\n' + payload)
        return {'data': {'observation_only': True, 'renew_after_seconds': 120,
                        'envelope': {'payload': base64.b64encode(payload).decode(),
                                     'signature': signature.hex()}}}


def serve():
    fixture = Fixture()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def answer(self, value, status=200):
            payload = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain' if isinstance(value, bytes) else 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            with fixture.lock:
                if parsed.path == '/qa/health':
                    return self.answer({'ok': True})
                if parsed.path == '/qa/proxy':
                    fixture.stats['proxy_requests'] += 1
                    fixture.persist()
                    return self.answer(BODY)
                query = urllib.parse.parse_qs(parsed.query)
                if query.get('token') != [fixture.secret['api_key']] or query.get('node_id') != ['7']:
                    return self.answer({'error': 'synthetic authentication'}, 403)
                if parsed.path == '/api/v1/server/UniProxy/config':
                    fixture.stats['config'] += 1
                    self.answer({'server_port': 18443, 'network': 'tcp', 'network_settings': {}, 'tls': 2,
                        'flow': 'xtls-rprx-vision', 'tls_settings': {'server_name': HOST,
                        'dest': '127.0.0.1', 'server_port': '18444',
                        'short_id': fixture.secret['short_id'], 'private_key': fixture.secret['reality_private']},
                        'base_config': {'push_interval': 60, 'pull_interval': 60}, 'routes': []})
                elif parsed.path == '/api/v1/server/UniProxy/user':
                    fixture.stats['users'] += 1
                    self.answer({'users': [{'id': UID, 'uuid': fixture.secret['uuid'],
                                            'speed_limit': 500, 'device_limit': 0}]})
                elif parsed.path == '/api/v1/server/UniProxy/alivelist':
                    self.answer({'alive': {}})
                else:
                    self.answer({}, 404)
                fixture.persist()

        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            if size > 1024 * 1024:
                return self.answer({}, 413)
            body = self.rfile.read(size)
            parsed = urllib.parse.urlparse(self.path)
            with fixture.lock:
                control = json.loads((ROOT / 'control.json').read_text())
                if parsed.path == '/qa/ticket':
                    # Loopback-only, root-only VM fixture; not a production admin endpoint.
                    return self.answer(fixture.issue())
                data = json.loads(body or b'{}')
                if parsed.path.startswith('/api/v1/attack-guard/delivery/'):
                    action = parsed.path.rsplit('/', 1)[-1]
                    credential = self.headers.get('Authorization', '').removeprefix('Bearer ')
                    if data.get('node') != NODE:
                        return self.answer({}, 403)
                    if action == 'enroll':
                        if credential != fixture.code or time.time() > fixture.expiry:
                            return self.answer({}, 403)
                        device = data.get('device_key', '')
                        if len(device) != 64 or fixture.device not in (None, device):
                            return self.answer({}, 403)
                        fixture.device = device
                        fixture.stats['enroll'] += 1
                    elif action == 'renew':
                        if credential != fixture.device or control['renew_status'] != 200:
                            fixture.stats['renew_rejected'] += 1
                            fixture.persist()
                            return self.answer({}, control['renew_status'] if control['renew_status'] != 200 else 403)
                        fixture.stats['renew'] += 1
                    else:
                        return self.answer({}, 404)
                    fixture.persist()
                    return self.answer(fixture.envelope())
                if parsed.path == '/api/v1/attack-guard/observation':
                    stamp = self.headers.get('X-Guard-Timestamp', '')
                    key_id = self.headers.get('X-Guard-Key-Id', '')
                    canonical = '\n'.join(['POST', parsed.path, NODE, key_id, stamp, hashlib.sha256(body).hexdigest()])
                    expected = hmac.new(fixture.secret['observation_key'].encode(), canonical.encode(), hashlib.sha256).hexdigest()
                    valid = (self.headers.get('X-Guard-Node') == NODE and key_id == fixture.secret['key_id']
                             and stamp.isdigit() and abs(int(stamp) - time.time()) < 60
                             and hmac.compare_digest(self.headers.get('X-Guard-Signature', ''), expected))
                    if not valid:
                        fixture.stats['bad_signature'] += 1
                        fixture.persist()
                        return self.answer({}, 403)
                    if control['ingest_status'] != 200:
                        fixture.stats['ingest_rejected'] += 1
                        fixture.persist()
                        return self.answer({}, control['ingest_status'])
                    subjects = data.get('subjects', [])
                    if data.get('complete') is not False or any(item['subject'] != fixture.secret['subject'] for item in subjects):
                        fixture.stats['bad_subject'] += 1
                        fixture.persist()
                        return self.answer({}, 422)
                    requests = 0
                    for item in subjects:
                        metrics = item['metrics']
                        if any(metrics.get(key) is not None for key in ('failed_connections', 'udp_packets', 'bytes_out', 'bytes_in')):
                            return self.answer({}, 422)
                        fixture.stats['null_metrics_verified'] += 1
                        requests += metrics['proxy_requests']
                    fixture.stats['authenticated_reports'] += 1
                    fixture.stats['attributed_requests'] += requests
                    fixture.stats['reports'].append({'uid': UID, 'proxy_requests': requests,
                                                    'complete': data['complete'], 'subjects': len(subjects)})
                    fixture.persist()
                    return self.answer({'data': {'observation_only': True}})
                if parsed.path.startswith('/api/v1/server/UniProxy/'):
                    return self.answer({'data': True})
                return self.answer({}, 404)

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        def handle_error(self, *_):
            pass  # Deliberately failed handshakes must not log credentials or payloads.

    tls = Server(('127.0.0.1', 18444), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(ROOT / 'tls.crt'), str(ROOT / 'tls.key'))
    # This stdlib fixture implements HTTP/1.1, not HTTP/2. Advertising h2 makes
    # the real Go panel client correctly reject its non-HTTP/2 response.
    context.set_alpn_protocols(['http/1.1'])
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    plain = Server(('127.0.0.1', 18080), Handler)
    fixture.persist()
    threading.Thread(target=tls.serve_forever, daemon=True).start()
    plain.serve_forever()


if __name__ == '__main__':
    import sys
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise SystemExit('disposable Linux/systemd root required')
    setup() if sys.argv[1] == 'setup' else serve()
