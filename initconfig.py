#!/usr/bin/env python3
"""New installations only. Never overwrite populated node configurations."""
import fcntl
import getpass
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit
from upgrade import digest, load_config, plain_path

def make_config(host,key,node_ids):
    u=urlsplit(host)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError('面板地址必须为 HTTPS，不含用户凭据、查询参数或片段')
    if not key or any(ord(c)<32 for c in key): raise ValueError('API Key 无效')
    ids=[int(n.strip()) for n in node_ids.split(',')]
    if not ids or len(set(ids))!=len(ids) or any(i<=0 for i in ids): raise ValueError('NodeID 必须为不重复正整数')
    return {'Log':{'Level':'info','Output':''},'Cores':[{'Type':'xray','Log':{'Level':'error'},'AssetPath':'/etc/V2bX/'}],
            'Nodes':[{'Core':'xray','ApiHost':host.rstrip('/'),'ApiKey':key,'NodeID':n,'NodeType':'vless','Timeout':30,
                      'ListenIP':'0.0.0.0','SendIP':'0.0.0.0','CertConfig':{'CertMode':'none'}} for n in ids]}

def main():
    if os.geteuid()!=0: raise SystemExit('需要 root')
    os.umask(0o077)
    path=Path('/etc/V2bX/config.json');plain_path(path)
    with open('/run/lock/beup-v2bx-upgrade.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if subprocess.run(['systemctl','is-active','--quiet','V2bX']).returncode==0:
            raise SystemExit('服务运行中；初始化不会修改正在使用的配置')
        baseline=digest(path) if path.exists() else None
        if path.exists() and load_config(path)['Nodes']: raise SystemExit('已有节点配置，拒绝重写；升级无需重新配置')
        print('仅初始化 VLESS + TCP + REALITY + Vision。TCP/REALITY/Vision 参数由面板节点下发。')
        c=make_config(input('HTTPS 面板地址：').strip(),getpass.getpass('API Key（不回显）：'),input('NodeID（多个用逗号分隔）：'))
        if input('确认写入新节点配置？输入 YES：')!='YES': return
        if (digest(path) if path.exists() else None)!=baseline: raise SystemExit('配置已变化，取消保存')
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if path.exists():
            backup=Path(tempfile.mkdtemp(prefix='init-',dir=path.parent));backup.chmod(0o700)
            (backup/'config.json').write_bytes(path.read_bytes())
            (backup/'SHA256SUMS').write_text(baseline+'  config.json\n')
        fd,tmp=tempfile.mkstemp(prefix='.config-',dir=path.parent)
        with os.fdopen(fd,'w') as f: json.dump(c,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        print('配置已保存，尚未启动。核对面板参数后执行 v2bx start；需要开机自启时执行 v2bx enable。')

if __name__=='__main__':
    try: main()
    except (ValueError,OSError): raise SystemExit('初始化失败；请核对输入和文件权限（未输出密钥）')
