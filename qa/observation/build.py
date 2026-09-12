#!/usr/bin/env python3
"""Build a LOCAL candidate delivery bundle. Does not publish or install anything."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

root=Path(__file__).resolve().parent
output=root/'artifacts';output.mkdir(exist_ok=True)
destination=Path(tempfile.mkdtemp(prefix='candidate-',dir=output))
manifest={'schema':1,'status':'local-candidate-not-published','agents':{}}
for machine,goarch in [('x86_64','amd64'),('aarch64','arm64')]:
    binary=destination/('agent-'+machine)
    env=os.environ.copy()
    env.update(GOOS='linux',GOARCH=goarch,CGO_ENABLED='0',GOTOOLCHAIN='local')
    subprocess.run(['go','build','-trimpath','-ldflags=-s -w -buildid=','-o',str(binary),'.'],cwd=root/'agent',env=env,check=True)
    manifest['agents'][machine]=hashlib.sha256(binary.read_bytes()).hexdigest()
    header=binary.read_bytes()[:20]
    if header[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(header[18:20],'little')!=({'amd64':62,'arm64':183}[goarch]):raise RuntimeError('unexpected executable format')
shutil.copy2(root/'patch.py',destination/'patch.py')
manifest['patch_sha256']=hashlib.sha256((destination/'patch.py').read_bytes()).hexdigest()
(destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
archive=destination/'beup-observation-patch-local.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for name in ['agent-x86_64','agent-aarch64','patch.py','manifest.json']:
        info=zipfile.ZipInfo(name,date_time=(2026,9,12,0,0,0))
        info.external_attr=(0o100755 if name.startswith('agent-') else 0o100644)<<16
        z.writestr(info,(destination/name).read_bytes(),compress_type=zipfile.ZIP_DEFLATED)
print(json.dumps({'bundle':str(destination),'zip_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'published':False}))
