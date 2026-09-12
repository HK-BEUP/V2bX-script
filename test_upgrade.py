import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import upgrade as u
import initconfig

VERSION='v25.12.2-beup-observe-local.2'

class Service:
    def __init__(self,active=True,health=None): self.running=active;self.calls=[];self.health=list(health or [True]);self.on_stop=None
    def active(self): return self.running
    def validate(self): pass
    def stop(self):
        self.calls.append('stop');self.running=False
        if self.on_stop: self.on_stop()
    def start(self): self.calls.append('start');self.running=True
    def healthy(self): self.calls.append('healthy');return self.health.pop(0) if self.health else True
    def reload(self): self.calls.append('reload')

class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp' if Path('/private/tmp').exists() else None)
        self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()/'host';self.root.mkdir()
        self.program=self.root/'usr/local/V2bX';self.program.mkdir(parents=True)
        (self.program/'V2bX').write_bytes(b'old-executable');(self.program/'operator.txt').write_text('keep')
        self.config=self.root/'etc/V2bX';self.config.mkdir(parents=True)
        self.c=initconfig.make_config('https://panel.example','synthetic-only','42,43')
        (self.config/'config.json').write_text(json.dumps(self.c));(self.config/'cert.pem').write_text('synthetic-cert');(self.config/'route.json').write_text('operator-routes')
        self.unit=self.root/'etc/systemd/system/V2bX.service';self.unit.parent.mkdir(parents=True);self.unit.write_text('operator-unit')
        self.command=self.root/'usr/bin/V2bX';self.command.parent.mkdir(parents=True);self.command.write_text('old-manager');self.command.chmod(0o755)
        self.service=Service();self.before=u.tree_hash(self.config)
        elf=bytearray(40);elf[:6]=b'\x7fELF\x02\x01';elf[18:20]=(62).to_bytes(2,'little')
        self.entries={n:b'synthetic' for n in u.MANAGED};self.entries['V2bX']=bytes(elf)
        self.entries['config.json']=json.dumps({'Cores':[{'Type':'xray'}],'Nodes':[]}).encode()
        self.entries['RELEASE.json']=json.dumps({'version':VERSION,'cores':['xray'],'profile':'VLESS+TCP+REALITY+Vision','binary_sha256':hashlib.sha256(elf).hexdigest()}).encode()
        self.archive=Path(self.tmp.name)/'package.zip'
    def pack(self,link=None):
        with zipfile.ZipFile(self.archive,'w') as z:
            for n,b in self.entries.items():
                if n==link:
                    i=zipfile.ZipInfo(n);i.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(i,b)
                else:z.writestr(n,b)
        return u.digest(self.archive)
    def run_upgrade(self,sha=None,machine='x86_64',probe=None):
        return u.transaction(self.archive,sha or self.pack(),VERSION,self.root,self.service,machine,probe or (lambda *_:None))
    def unchanged(self):
        self.assertEqual((self.program/'V2bX').read_bytes(),b'old-executable')
        self.assertEqual(u.tree_hash(self.config),self.before);self.assertEqual(self.unit.read_text(),'operator-unit')
        self.assertEqual(self.command.read_text(),'old-manager')
    def test_success_preserves_config_and_operator_files(self):
        result=self.run_upgrade();self.assertTrue(result['config_unchanged']);self.assertEqual(u.tree_hash(self.config),self.before)
        self.assertEqual((self.program/'operator.txt').read_text(),'keep');self.assertEqual(self.unit.read_text(),'operator-unit')
        backup=Path(result['backup']);self.assertEqual((backup/'program/V2bX').read_bytes(),b'old-executable')
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode),0o700);self.assertEqual(u.tree_hash(backup/'config'),self.before)
    def test_hash_mismatch_no_stop(self):
        self.pack()
        with self.assertRaises(ValueError):self.run_upgrade('0'*64)
        self.unchanged();self.assertEqual(self.service.calls,[])
    def test_bad_arch_no_stop(self):
        with self.assertRaises(ValueError):self.run_upgrade(machine='aarch64')
        self.unchanged();self.assertEqual(self.service.calls,[])
    def test_zip_traversal(self):
        self.entries['../escape']=b'x'
        with self.assertRaises(ValueError):self.run_upgrade()
        self.unchanged();self.assertFalse((self.root/'escape').exists())
    def test_zip_symlink(self):
        sha=self.pack('V2bX')
        with self.assertRaises(ValueError):self.run_upgrade(sha)
        self.unchanged()
    def test_wrong_version(self):
        meta=json.loads(self.entries['RELEASE.json']);meta['version']='other';self.entries['RELEASE.json']=json.dumps(meta).encode()
        with self.assertRaises(ValueError):self.run_upgrade()
        self.unchanged()
    def test_other_core(self):
        self.c['Cores'][0]['Type']='sing';(self.config/'config.json').write_text(json.dumps(self.c))
        with self.assertRaises(ValueError):self.run_upgrade()
        self.assertEqual(self.service.calls,[])
    def test_include_rejected(self):
        self.c['Nodes'][0]['Include']='https://untrusted.example';(self.config/'config.json').write_text(json.dumps(self.c))
        with self.assertRaises(ValueError):self.run_upgrade()
        self.assertEqual(self.service.calls,[])
    def test_probe_fail_no_stop(self):
        def fail(*_):raise RuntimeError('probe failed')
        with self.assertRaises(RuntimeError):self.run_upgrade(probe=fail)
        self.unchanged();self.assertEqual(self.service.calls,[])
    def test_start_failure_rolls_back(self):
        self.service.health=[False,True]
        with self.assertRaisesRegex(RuntimeError,'稳定启动'):self.run_upgrade()
        self.unchanged();self.assertTrue(self.service.active());self.assertEqual(self.service.calls,['stop','start','healthy','stop','start','healthy'])
    def test_stopped_remains_stopped(self):
        self.service.running=False;self.run_upgrade();self.assertFalse(self.service.running);self.assertEqual(self.service.calls,[])
    def test_operator_edit_during_preparation(self):
        def edit(*_):(self.config/'route.json').write_text('new-operator-value')
        with self.assertRaises(RuntimeError):self.run_upgrade(probe=edit)
        self.assertEqual(self.service.calls,[]);self.assertEqual((self.config/'route.json').read_text(),'new-operator-value')
    def test_operator_edit_after_stop(self):
        self.service.on_stop=lambda:(self.config/'route.json').write_text('operator-edited')
        with self.assertRaises(RuntimeError):self.run_upgrade()
        self.assertTrue(self.service.active());self.assertEqual((self.config/'route.json').read_text(),'operator-edited')
        self.assertEqual((self.program/'V2bX').read_bytes(),b'old-executable')
    def test_command_write_failure_restores(self):
        real=os.replace
        def fail(src,dst):
            if Path(dst).name=='v2bx':raise OSError('injected failure')
            return real(src,dst)
        with patch('upgrade.os.replace',side_effect=fail),self.assertRaises(OSError):self.run_upgrade()
        self.unchanged();self.assertTrue(self.service.active())
    def test_interruption_restores(self):
        self.service.health=[True]
        def interrupt():raise KeyboardInterrupt()
        self.service.on_stop=interrupt
        with self.assertRaises(KeyboardInterrupt):self.run_upgrade()
        self.unchanged();self.assertTrue(self.service.active())
    def test_comments_and_escaped_input(self):
        c=initconfig.make_config('https://example.com/base','synthetic-"-\\-token','5')
        (self.config/'config.json').write_text('// comment\n'+json.dumps(c)+'/* tail */')
        self.assertEqual(u.load_config(self.config/'config.json'),c)
    def test_config_symlink_refused(self):
        (self.config/'outside').symlink_to('/tmp')
        with self.assertRaises(ValueError):self.run_upgrade()
        self.assertEqual(self.service.calls,[])
    def test_missing_member(self):
        del self.entries['upgrade.py']
        with self.assertRaises(ValueError):self.run_upgrade()
        self.unchanged()
    def test_fresh_install_no_autostart(self):
        import shutil
        shutil.rmtree(self.program);shutil.rmtree(self.config);self.unit.unlink();self.command.unlink();self.service.running=False
        self.run_upgrade();self.assertFalse(self.service.running);self.assertEqual(u.load_config(self.config/'config.json')['Nodes'],[])
        self.assertEqual(stat.S_IMODE((self.config/'config.json').stat().st_mode),0o600)
    def test_bad_wizard_input(self):
        for host,ids in [('http://example.com','1'),('https://a:b@example.com','1'),('https://example.com','1,1'),('https://example.com','0')]:
            with self.subTest(host=host,ids=ids),self.assertRaises(ValueError):initconfig.make_config(host,'synthetic',ids)

class HealthTests(unittest.TestCase):
    def test_no_ports_is_not_healthy(self):
        from types import SimpleNamespace
        s=u.Systemd();s.required_ports={'tcp:expected'}
        with patch.object(s,'call',return_value=SimpleNamespace(stdout='ActiveState=active\nMainPID=42\nNRestarts=0\nExecMainStartTimestampMonotonic=123\n')),patch.object(s,'listening',return_value=set()),patch('upgrade.time.sleep'):
            self.assertFalse(s.healthy())
    def test_stable_ports_are_healthy(self):
        from types import SimpleNamespace
        s=u.Systemd();s.required_ports={'tcp:expected'}
        with patch.object(s,'call',return_value=SimpleNamespace(stdout='ActiveState=active\nMainPID=42\nNRestarts=0\nExecMainStartTimestampMonotonic=123\n')),patch.object(s,'listening',return_value={'tcp:expected'}),patch('upgrade.time.sleep'):
            self.assertTrue(s.healthy())
    def test_restart_is_not_healthy(self):
        from types import SimpleNamespace
        s=u.Systemd();s.required_ports={'tcp:expected'}
        states=[SimpleNamespace(stdout='ActiveState=active\nMainPID=42\n'),SimpleNamespace(stdout='ActiveState=active\nMainPID=43\n')]
        with patch.object(s,'call',side_effect=states),patch.object(s,'listening',return_value={'tcp:expected'}),patch('upgrade.time.sleep'):
            self.assertFalse(s.healthy())

class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self,mode):
        import io
        payload=io.BytesIO()
        with zipfile.ZipFile(payload,'w') as z:z.writestr('upgrade.py',b'# synthetic helper')
        data=payload.getvalue();name='V2bX-linux-64.zip';checksum=hashlib.sha256(data).hexdigest()
        sums=checksum+'  '+name+'\n'
        if mode=='duplicate':sums+=sums
        if mode=='missing':sums=''
        if mode=='corrupt':data+=b'bad'
        class Response(io.BytesIO):
            def geturl(self):return 'https://github.com/synthetic'
        def fetch(req,**_):
            url=req.full_url
            self.assertTrue(url.startswith('https://github.com/HK-BEUP/V2bX/releases/download/'))
            if mode=='network':raise OSError('synthetic network failure')
            return Response(sums.encode() if url.endswith('SHA256SUMS') else data)
        code=Path(__file__).with_name('install.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
        original_umask=os.umask(0o077);os.umask(original_umask)
        try:
            with patch('sys.argv',['-',VERSION]),patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'),patch('os.path.isdir',return_value=True),patch('urllib.request.urlopen',side_effect=fetch),patch('subprocess.run') as run:
                if mode=='ok':exec(compile(code,'bootstrap','exec'),{});self.assertEqual(run.call_count,1)
                else:
                    with self.assertRaises((SystemExit,OSError)):exec(compile(code,'bootstrap','exec'),{})
                    run.assert_not_called()
        finally:os.umask(original_umask)
    def test_verified_bootstrap(self):self.run_bootstrap('ok')
    def test_corrupt_download(self):self.run_bootstrap('corrupt')
    def test_duplicate_sum(self):self.run_bootstrap('duplicate')
    def test_missing_sum(self):self.run_bootstrap('missing')
    def test_network_failure(self):self.run_bootstrap('network')

if __name__=='__main__':unittest.main()
