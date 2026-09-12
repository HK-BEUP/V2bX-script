#!/usr/bin/env python3
"""Independent, opt-in observation patch. CLI has fixed production paths.
No node/customer configuration edits; tests inject private roots and fake services.
"""
import argparse
import base64
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

VERSION = 'v25.12.2-beup-observe-rc.1'
RELEASES = {
    'x86_64': ('V2bX-linux-64.zip','3b2c6f655458685afeaf0aaa2981f4e2e5ffb42b3c3566ae70061bf90545ae60','b765ee0045ba3c509938337f574e32b0ac49633312afaca42655b70b36a79254'),
    'aarch64': ('V2bX-linux-arm64-v8a.zip','c9c1eea26a11e3775623529518690f722396c2797268192bf71d8c4348c4a4b9','cfc490da0bafe2fc8dcd2639b15f6d519350a7b5c4c2f1e392e0730c10511338'),
}
DROP = '[Service]\nEnvironment=BEUP_OBSERVATION_CONFIG=/etc/beup-observe/settings.json\n'
UNIT = '''[Unit]
Description=HK-BEUP observation lease renewal (no proxy control)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=/usr/local/lib/beup-observe/agent renew
TimeoutStartSec=20
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/beup-observe
MemoryMax=128M
'''
TIMER = '''[Unit]
Description=HK-BEUP observation lease renewal timer
[Timer]
OnBootSec=60
OnUnitActiveSec=120
RandomizedDelaySec=10
Unit=beup-observe-renew.service
[Install]
WantedBy=timers.target
'''
TARGETS = {
 'etc/systemd/system/V2bX.service.d/90-beup-observe.conf':DROP,
 'etc/systemd/system/beup-observe-renew.service':UNIT,
 'etc/systemd/system/beup-observe-renew.timer':TIMER,
}
class PatchError(Exception): pass
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()
def plain(p):
    for item in [p]+list(p.parents):
        if item.is_symlink(): raise PatchError('路径包含符号链接，保持原服务')
def atomic(p,data,mode=0o600):
    plain(p);p.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.beup-patch-',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,p)
        directory_fd=os.open(p.parent,os.O_RDONLY)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    finally:
        if os.path.exists(name): os.unlink(name)
def tree(p):
    out={}
    for f in [p]+sorted(p.rglob('*')):
        plain(f)
        if f.is_file():
            s=f.stat();out[str(f.relative_to(p))]=[sha(f),stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid]
    return out
def config(p):
    raw=p.read_text();out=[];i=0;quoted=False;escaped=False
    while i<len(raw):
        ch=raw[i]
        if quoted:
            out.append(ch)
            if escaped: escaped=False
            elif ch=='\\': escaped=True
            elif ch=='"': quoted=False
            i+=1;continue
        if ch=='"': quoted=True
        elif raw[i:i+2]=='//':
            end=raw.find('\n',i);i=len(raw) if end<0 else end;continue
        elif raw[i:i+2]=='/*':
            end=raw.find('*/',i+2)
            if end<0:raise PatchError('配置注释不完整')
            out.append(' ');i=end+2;continue
        out.append(ch);i+=1
    c=json.loads(''.join(out))
    if not c.get('Cores') or any(x.get('Type')!='xray' for x in c['Cores']):raise PatchError('仅支持已核验的 Xray 核心')
    nodes=c.get('Nodes')
    if not isinstance(nodes,list) or not nodes:raise PatchError('请先完成原节点配置')
    descriptors=[]
    for n in nodes:
        api=n.get('ApiConfig',n);opt=n.get('Options',n)
        if n.get('Include') or api.get('NodeType')!='vless' or opt.get('Core','xray') not in ('','xray'):raise PatchError('仅支持无 Include 的 VLESS/Xray 配置')
        nodeid=api.get('NodeID');host=api.get('ApiHost')
        if type(nodeid)!=int or nodeid<=0 or not isinstance(host,str) or not api.get('ApiKey'):raise PatchError('节点必需配置不完整')
        descriptors.append((host,nodeid))
    if len(set(descriptors))!=len(descriptors):raise PatchError('节点配置重复')
    return sorted(descriptors)
def probe(binary):
    r=subprocess.run([str(binary),'version'],capture_output=True,text=True,timeout=15)
    if r.returncode:raise PatchError('原程序版本自检失败')
    return VERSION if VERSION in r.stdout else next((v for v in ('v0.4.0','v0.4.1') if re.search(re.escape(v)+r'(?![0-9.])',r.stdout)),None)
class Systemd:
    def call(self,*args,check=True):
        return subprocess.run(['systemctl',*args],check=check,capture_output=True,text=True,timeout=90)
    def active(self):return self.call('is-active','--quiet','V2bX',check=False).returncode==0
    def ports(self,pid):
        result=set();inodes=set()
        for f in Path('/proc/%s/fd'%pid).iterdir():
            try:s=os.readlink(f)
            except FileNotFoundError:continue
            if s.startswith('socket:['):inodes.add(s[8:-1])
        for fam in ('tcp','tcp6'):
            for line in Path('/proc/%s/net/%s'%(pid,fam)).read_text().splitlines()[1:]:
                f=line.split()
                if f[3]=='0A' and f[9] in inodes:result.add(fam+':'+f[1])
        return result
    def validate(self):
        cmd=self.call('show','V2bX','-p','ExecStart','--value').stdout
        if not re.search(r'argv\[\]=/usr/local/V2bX/V2bX server\s*;',cmd):raise PatchError('自定义启动方式需另行核对')
        user=self.call('show','V2bX','-p','User','--value').stdout.strip()
        if user not in ('','root'):raise PatchError('非 root 运行方式需另行核对')
        self.required=set()
        if self.active():
            self.required=self.ports(int(self.call('show','V2bX','-p','MainPID','--value').stdout))
            if not self.required:raise PatchError('原服务没有可验证的 TCP 监听')
    def stop(self):self.call('stop','V2bX')
    def start(self):self.call('start','V2bX')
    def reload(self):self.call('daemon-reload')
    def healthy(self):
        previous=None;stable=0
        for _ in range(60):
            time.sleep(1)
            raw=self.call('show','V2bX','-p','ActiveState','-p','MainPID','-p','NRestarts').stdout
            s=dict(x.split('=',1) for x in raw.splitlines() if '=' in x)
            if s.get('ActiveState')!='active' or s.get('MainPID')=='0':return False
            if previous is not None and raw!=previous:return False
            previous=raw
            stable=stable+1 if self.required.issubset(self.ports(int(s['MainPID']))) else 0
            if stable>=15:return True
        return False
    def timer_start(self):self.call('enable','--now','beup-observe-renew.timer')
    def timer_stop(self):
        self.call('disable','--now','beup-observe-renew.timer',check=False)
        self.call('stop','beup-observe-renew.service',check=False)
def invoke_agent(binary,action,ticket=None):
    r=subprocess.run([str(binary),action],input=json.dumps(ticket).encode() if ticket else None,capture_output=True,timeout=20)
    if r.returncode:raise PatchError('采集认证或租约校验失败，未输出凭据')
class Patch:
    def __init__(self,root,package,service,machine,agent=invoke_agent,version_probe=probe):
        self.root=Path(root);self.package=Path(package);self.svc=service;self.machine=machine;self.agent=agent;self.probe=version_probe
        self.program=self.root/'usr/local/V2bX/V2bX';self.conf=self.root/'etc/V2bX'
        self.data=self.root/'etc/beup-observe';self.lib=self.root/'usr/local/lib/beup-observe'
    def protected_units(self):
        base=self.root/'etc/systemd/system';paths=[base/'V2bX.service']
        dropins=base/'V2bX.service.d';plain(dropins)
        if dropins.exists():paths+=sorted(dropins.rglob('*'))
        result={}
        for p in paths:
            plain(p)
            if p.is_file() and str(p.relative_to(self.root)) not in TARGETS:
                s=p.stat();result[str(p.relative_to(self.root))]=[sha(p),stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid]
        return result
    def unchanged(self):
        return tree(self.conf)==self.before and sha(self.program)==self.binary_before and self.protected_units()==self.units_before
    def plan(self):
        if self.machine not in RELEASES:raise PatchError('仅支持 amd64/arm64')
        for p in [self.program,self.conf,self.data,self.lib,*[self.root/x for x in TARGETS]]:plain(p)
        if not self.program.is_file():raise PatchError('未安装 V2bX；本补丁不会新建节点')
        self.descriptors=config(self.conf/'config.json');self.before=tree(self.conf)
        self.units_before=self.protected_units()
        self.svc.validate();self.was_active=self.svc.active()
        self.binary_before=sha(self.program);self.needs_upgrade=self.binary_before!=RELEASES[self.machine][2]
        if self.needs_upgrade and self.probe(self.program) not in ('v0.4.0','v0.4.1'):raise PatchError('未核验版本，停止且不自动覆盖')
        if (self.data/'installed.json').exists():raise PatchError('已安装采集补丁；续签自动进行，无需重复安装')
        for rel in TARGETS:
            if (self.root/rel).exists():raise PatchError('专属服务文件已存在，先核对或恢复前次操作')
        if self.lib.exists():raise PatchError('采集程序目录已存在，先核对前次操作')
        return {'requires_upgrade':self.needs_upgrade,'requires_restart':self.was_active,'node_count':len(self.descriptors),'proxy_config_unchanged':True}
    def verify_package(self):
        m=json.loads((self.package/'manifest.json').read_text())
        agent=self.package/('agent-'+self.machine)
        if sha(agent)!=m['agents'][self.machine]:raise PatchError('补丁程序校验失败')
        if sha(self.package/'patch.py')!=m['patch_sha256']:raise PatchError('补丁脚本校验失败')
        return agent
    def fetch_binary(self,stage):
        name,expected,binaryhash=RELEASES[self.machine]
        class HTTPSOnly(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,req,fp,code,msg,headers,newurl):
                if not newurl.startswith('https://'):raise PatchError('升级下载不允许降级 HTTP')
                return super().redirect_request(req,fp,code,msg,headers,newurl)
        opener=urllib.request.build_opener(HTTPSOnly)
        url='https://github.com/HK-BEUP/V2bX/releases/download/'+VERSION+'/'+name
        with opener.open(url,timeout=45) as r:
            payload=r.read(67108865)
        if len(payload)>67108864 or hashlib.sha256(payload).hexdigest()!=expected:raise PatchError('升级包 SHA256 不符，未停止原服务')
        archive=stage/'upgrade.zip';archive.write_bytes(payload)
        with zipfile.ZipFile(archive) as z:
            if z.namelist().count('V2bX')!=1 or z.getinfo('V2bX').file_size>134217728:raise PatchError('升级包成员不符')
            b=z.read('V2bX')
        if hashlib.sha256(b).hexdigest()!=binaryhash or b[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(b[18:20],'little')!={'x86_64':62,'aarch64':183}[self.machine]:raise PatchError('升级程序校验失败')
        p=stage/'V2bX';p.write_bytes(b);p.chmod(0o755)
        if self.probe(p)!=VERSION:raise PatchError('新程序版本自检失败')
        return p
    def apply(self,ticket,allow_upgrade=False,restart=False):
        self.plan()
        if self.needs_upgrade and not allow_upgrade:raise PatchError('旧版必须明确允许升级；尚未改动')
        if self.was_active and not restart:raise PatchError('首次启用需要明确允许短暂重启；尚未改动')
        resume=ticket is None
        if resume:
            client=self.data/'client.json';plain(client)
            if not client.is_file() or client.stat().st_mode&0o077 or client.stat().st_uid!=os.geteuid():raise PatchError('没有安全的接入记录可恢复')
            ticket=json.loads(client.read_text())
        if sorted((ticket.get('api_host'),x) for x in ticket.get('node_ids',[]))!=self.descriptors:raise PatchError('注册码对应的节点与本机配置不一致')
        helper=self.verify_package()
        backups=self.root/'usr/local/.backups/beup-observe';plain(backups);backups.mkdir(parents=True,exist_ok=True,mode=0o700)
        backup=Path(tempfile.mkdtemp(prefix='patch-',dir=backups));backup.chmod(0o700)
        shutil.copy2(self.program,backup/'original-V2bX');shutil.copytree(self.conf,backup/'proxy-config')
        oldunit=self.root/'etc/systemd/system/V2bX.service'
        if oldunit.exists():shutil.copy2(oldunit,backup/'V2bX.service')
        record={'status':'prepared','backup':str(backup),'machine':self.machine,'binary_before':self.binary_before,'upgraded':self.needs_upgrade,'was_active':self.was_active,'config_before':self.before,'units_before':self.units_before,'required_ports':sorted(getattr(self.svc,'required',set())),'managed':{}}
        atomic(backup/'record.json',json.dumps(record).encode())
        upgraded=False;stopped=False
        try:
            with tempfile.TemporaryDirectory(prefix='stage-',dir=backup) as temp:
                target=self.fetch_binary(Path(temp)) if self.needs_upgrade else None
                if self.data.exists():
                    plain(self.data)
                    if stat.S_IMODE(self.data.stat().st_mode)!=0o700:raise PatchError('采集目录权限不安全')
                else:self.data.mkdir(mode=0o700)
                # Authentication and signature verification happen before proxy stop.
                self.agent(helper,'renew' if resume else 'enroll',None if resume else ticket)
                if not self.unchanged():raise PatchError('原配置、启动单元或程序发生并发变化，取消切换')
                contents={**{k:v.encode() for k,v in TARGETS.items()},
                    'usr/local/lib/beup-observe/agent':helper.read_bytes(),
                    'usr/local/lib/beup-observe/patch.py':(self.package/'patch.py').read_bytes()}
                record['managed']={p:hashlib.sha256(v).hexdigest() for p,v in contents.items()}
                record['status']='activating';atomic(backup/'record.json',json.dumps(record).encode())
                self.lib.mkdir(parents=True,mode=0o755)
                if self.was_active:stopped=True;self.svc.stop()
                if not self.unchanged():raise PatchError('切换前内容漂移，取消')
                if target:atomic(self.program,target.read_bytes(),0o755);upgraded=True
                for p,v in contents.items():atomic(self.root/p,v,0o755 if p.endswith('/agent') else 0o644)
                self.svc.reload()
                if self.was_active:
                    self.svc.start()
                    if not self.svc.healthy():raise PatchError('启用后服务检查失败')
                self.agent(self.lib/'agent','check')
                self.svc.timer_start()
                if tree(self.conf)!=self.before:raise PatchError('节点配置发生变化，需核对')
                record['status']='installed';atomic(backup/'record.json',json.dumps(record).encode());atomic(self.data/'installed.json',json.dumps(record).encode())
        except BaseException:
            if record['managed']:self.svc.timer_stop()
            if stopped:self.svc.stop()
            restore_binary=self.needs_upgrade and sha(self.program)!=self.binary_before
            self.rollback_files(record,backup,restore_binary=restore_binary)
            self.svc.reload()
            if stopped:
                self.svc.start()
                if not self.svc.healthy():raise PatchError('回退后仍异常，请检查受控备份')
            record['status']='rolled_back';atomic(backup/'record.json',json.dumps(record).encode())
            raise
        return {'installed':True,'backup':str(backup),'upgraded':self.needs_upgrade,'config_unchanged':True,'observation_only':True,'client_acceptance_required':self.was_active}
    def recover(self,backup,restart=False):
        # Explicit rollback of an interrupted activation, never a generic restore.
        # Operator configuration drift blocks recovery before any service action.
        backup=Path(backup);plain(backup)
        base=self.root/'usr/local/.backups/beup-observe'
        if backup.parent!=base or not re.fullmatch(r'patch-[A-Za-z0-9_-]+',backup.name):raise PatchError('恢复仅允许本补丁的明确备份目录')
        receipt=backup/'record.json';plain(receipt)
        if not receipt.is_file() or receipt.stat().st_mode&0o077 or receipt.stat().st_uid!=os.geteuid():raise PatchError('恢复回执不安全')
        record=json.loads(receipt.read_text())
        if (self.data/'installed.json').exists():raise PatchError('已有安装回执，请核对后使用 remove，不恢复中断事务')
        expected=set(TARGETS)|{'usr/local/lib/beup-observe/agent','usr/local/lib/beup-observe/patch.py'}
        if record.get('status') not in ('activating','installed') or record.get('machine')!=self.machine or record.get('backup')!=str(backup) or set(record.get('managed',{}))!=expected or type(record.get('was_active'))!=bool or type(record.get('upgraded'))!=bool:raise PatchError('仅恢复中断的启用事务；已安装版本请使用 remove')
        for rel,h in record['managed'].items():
            p=self.root/rel;plain(p)
            if not isinstance(h,str) or not re.fullmatch('[a-f0-9]{64}',h) or (p.exists() and sha(p)!=h):raise PatchError('补丁已被人工修改，停止自动恢复')
        if tree(self.conf)!=record.get('config_before') or self.protected_units()!=record.get('units_before'):raise PatchError('原配置或启动单元已改变，停止自动恢复')
        original=backup/'original-V2bX';plain(original);plain(self.program)
        before=record['binary_before'];current=sha(self.program)
        if not original.is_file() or sha(original)!=before or current not in (before,RELEASES[self.machine][2]):raise PatchError('原程序或备份不匹配')
        replace=current!=before
        if replace and not record['upgraded']:raise PatchError('不是本次升级的程序，停止')
        if (record['was_active'] or self.svc.active()) and not restart:raise PatchError('恢复原服务需要明确允许重启')
        if not record['was_active'] and self.svc.active():raise PatchError('原本停止的服务已被外部启动，先人工核对')
        self.svc.validate()
        required=record.get('required_ports')
        if not isinstance(required,list) or any(not isinstance(x,str) for x in required):raise PatchError('原监听记录不完整')
        self.svc.required=set(required)
        self.svc.timer_stop()
        if record['was_active']:self.svc.stop()
        self.rollback_files(record,backup,restore_binary=replace)
        self.svc.reload()
        if record['was_active']:
            self.svc.start()
            if not self.svc.healthy():raise PatchError('恢复后服务检查失败，请保留备份排查')
        record['status']='rolled_back';atomic(receipt,json.dumps(record).encode())
        return {'recovered':True,'backup':str(backup),'proxy_config_unchanged':True,'resume_enrollment_available':(self.data/'client.json').exists()}
    def rollback_files(self,record,backup,restore_binary=False):
        # Validate the whole set before removing any managed file.
        for rel,want in record['managed'].items():
            p=self.root/rel;plain(p)
            if p.exists() and sha(p)!=want:raise PatchError('补丁文件被人工修改，不覆盖')
        if restore_binary:
            if sha(self.program)!=RELEASES[self.machine][2]:raise PatchError('新程序被修改，不自动回退')
            if sha(backup/'original-V2bX')!=record['binary_before']:raise PatchError('原程序备份校验失败')
        for rel in record['managed']:
            p=self.root/rel
            if p.exists():p.unlink()
        if restore_binary:
            atomic(self.program,(backup/'original-V2bX').read_bytes(),stat.S_IMODE((backup/'original-V2bX').stat().st_mode))
        if self.lib.exists() and not any(self.lib.iterdir()):self.lib.rmdir()
    def remove(self,restart=False):
        plain(self.data);record=json.loads((self.data/'installed.json').read_text())
        if record.get('status')!='installed' or set(record['managed'])!=set(TARGETS)|{'usr/local/lib/beup-observe/agent','usr/local/lib/beup-observe/patch.py'}:raise PatchError('安装回执无效')
        self.svc.validate();active=self.svc.active()
        if active and not restart:raise PatchError('撤除采集需明确允许短暂重启')
        for rel,h in record['managed'].items():
            p=self.root/rel;plain(p)
            if not p.is_file() or sha(p)!=h:raise PatchError('补丁已被修改，停止撤除')
        base=self.root/'usr/local/.backups/beup-observe';plain(base)
        backup=Path(tempfile.mkdtemp(prefix='remove-',dir=base));backup.chmod(0o700)
        for rel in record['managed']:
            p=backup/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(self.root/rel,p)
        self.svc.timer_stop()
        shutil.copytree(self.data,backup/'observation-data')
        try:
            if active:self.svc.stop()
            self.rollback_files(record,backup,False);self.svc.reload()
            if active:
                self.svc.start()
                if not self.svc.healthy():raise PatchError('撤除后服务检查失败')
            record['status']='removed';atomic(self.data/'installed.json',json.dumps(record).encode())
            # Recoverable quarantine, never delete device credentials or leases.
            self.data.rename(backup/'retired-observation-data')
        except BaseException:
            for rel,h in record['managed'].items():
                p=backup/rel
                if sha(p)!=h:raise PatchError('撤除回退备份不一致')
                target=self.root/rel
                if target.exists() and sha(target)!=h:raise PatchError('回退前检测到人工修改')
                atomic(target,p.read_bytes(),stat.S_IMODE(p.stat().st_mode))
            # A failed quarantine must not leave a "removed" receipt on an active patch.
            prior=backup/'observation-data/installed.json'
            atomic(self.data/'installed.json',prior.read_bytes())
            self.svc.reload()
            if active:
                self.svc.stop();self.svc.start()
                if not self.svc.healthy():raise PatchError('撤除回退后仍异常，请检查受控备份')
            self.svc.timer_start()
            raise
        return {'removed':True,'backup':str(backup),'v2bx_binary_preserved':True}
def ticket_prompt():
    raw=getpass.getpass('粘贴后台生成的采集接入码（隐藏输入）：')
    if len(raw)>16384:raise PatchError('接入码过长')
    try:return json.loads(base64.urlsafe_b64decode(raw+'='*((-len(raw))%4)))
    except Exception:raise PatchError('接入码无效') from None
def main():
    parser=argparse.ArgumentParser(description='HK-BEUP 独立采集补丁')
    parser.add_argument('action',choices=['plan','apply','remove','recover'])
    parser.add_argument('--allow-upgrade',action='store_true')
    parser.add_argument('--restart',action='store_true')
    parser.add_argument('--resume',action='store_true',help='使用本机已保存的专属凭据恢复未完成接入，不需重新领码')
    parser.add_argument('--backup',help='recover 所需的本补丁精确备份目录')
    args=parser.parse_args()
    if os.geteuid()!=0 or platform.system()!='Linux' or not Path('/run/systemd/system').is_dir():raise PatchError('仅支持 Linux/systemd root')
    os.umask(0o077)
    signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    patch=Patch(Path('/'),Path(__file__).resolve().parent,Systemd(),platform.machine())
    if args.action=='plan':result=patch.plan()
    else:
        lockpath=Path('/run/lock/beup-v2bx-upgrade.lock');plain(lockpath)
        fd=os.open(lockpath,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.action=='recover':
                if not args.backup:raise PatchError('恢复必须指定精确备份目录')
                result=patch.recover(args.backup,args.restart)
            elif args.action=='remove':result=patch.remove(args.restart)
            else:result=patch.apply(None if args.resume else ticket_prompt(),args.allow_upgrade,args.restart)
    print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as e:
        print(str(e) if isinstance(e,PatchError) else '补丁未完成；错误已脱敏，请保留备份并核对服务状态',file=sys.stderr);sys.exit(1)
