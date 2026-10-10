#!/usr/bin/env python3
"""Sign an immutable Windows NSIS installer locally; never upload the private key."""
import argparse, hashlib, json, subprocess
from pathlib import Path
from datetime import datetime, timezone
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('installer',type=Path)
p.add_argument('--out-dir',type=Path,required=True)
p.add_argument('--notes-file',type=Path)
a=p.parse_args();root=Path(__file__).resolve().parent.parent
config=json.loads((root/'apps/desktop/src-tauri/tauri.windows.conf.json').read_text())
version=json.loads((root/'apps/desktop/src-tauri/tauri.conf.json').read_text())['version']
installer=a.installer.resolve();out=a.out_dir.resolve()
if installer.name!=f'foxVPN_{version}_x64-setup.exe' or not installer.read_bytes().startswith(b'MZ'):
 raise SystemExit('Expected the versioned Windows NSIS installer')
proof_path=installer.parent/'windows-core-startup.json'
if not proof_path.is_file():raise SystemExit('Installed-core startup proof from the Windows runner is required before signing')
proof=json.loads(proof_path.read_text(encoding='utf-8-sig'))
if proof.get('installer_sha256')!=hashlib.sha256(installer.read_bytes()).hexdigest() or proof.get('installer_version')!=version or proof.get('engine_version')!=version:
 raise SystemExit('Startup proof does not match this exact installer/version')
if len(proof.get('cores',[]))!=1 or len(set(proof['cores'][0].get('cases',[])))!=72 or not proof['cores'][0].get('legacy_rejected'):
 raise SystemExit('Incomplete installed-core startup proof')
ai_path=installer.parent/'windows-local-ai.json'
if not ai_path.is_file():raise SystemExit('Installed local AI worker proof is required before signing')
ai=json.loads(ai_path.read_text(encoding='utf-8'))
if ai.get('installer_sha256')!=hashlib.sha256(installer.read_bytes()).hexdigest() or ai.get('model_sha256')!='9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031':
 raise SystemExit('AI proof does not match this installer/pinned model')
if len(ai.get('inference',[]))!=6 or not all(ai.get(k) for k in ('corrupted_model_rejected','unknown_fields_rejected','oversized_input_rejected','parent_death_cleanup')):
 raise SystemExit('Incomplete installed local AI worker proof')
key=Path.home()/'.config/foxvpn-release/updater.key'
if not key.is_file() or not Path(str(key)+'.pub').is_file() or Path(str(key)+'.pub').read_text().strip()!=config['plugins']['updater']['pubkey']:
 raise SystemExit('Restore the original signing key; never replace it')
if not config['plugins']['updater'].get('requireSignedVersion'):
 raise SystemExit('Version-bound signatures are required')
if Path(str(installer)+'.sig').exists():raise SystemExit('Signature already exists; do not overwrite release assets')
result=subprocess.run([str(root/'apps/desktop/node_modules/.bin/tauri'),'signer','sign',
 '--private-key-path',str(key),'--app-version',version,str(installer)],capture_output=True,text=True)
if result.returncode:raise SystemExit('Signing failed; check the key/password environment locally')
out.mkdir(parents=True,exist_ok=True)
feed={'version':version,'notes':a.notes_file.read_text().strip() if a.notes_file else 'Обновление foxVPN для Windows.',
 'pub_date':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
 'platforms':{'windows-x86_64':{'url':f'https://github.com/kvashninsasha-gif/foxVPN/releases/download/v{version}/{installer.name}',
 'signature':Path(str(installer)+'.sig').read_text().strip()}}}
(out/'windows.json').write_text(json.dumps(feed,ensure_ascii=False,indent=2)+'\n')
print(f'Windows update {version} signed; private key stayed local')
