#!/usr/bin/env python3
"""校验发布包：清单指纹、参考源指纹、声明计数，以及页面能否由 data/ 逐字节重建。"""
import hashlib, json, pathlib, shutil, sys, tempfile

PKG = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / 'scripts'))
import agent_audit_versioning as av

HTML = 'AI-Agent安全审计图谱.html'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
fail = []

for line in (PKG / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines():
    digest, rel = line.split('  ', 1)
    if not (PKG / rel).is_file() or sha(PKG / rel) != digest:
        fail.append('清单不符: ' + rel)

meta = json.loads((PKG / 'data/metadata.json').read_text())
for rel, digest in meta['source_hashes'].items():
    if not (PKG / rel).is_file() or sha(PKG / rel) != digest:
        fail.append('参考源指纹不符: ' + rel)

with tempfile.TemporaryDirectory() as tmp:
    stage = pathlib.Path(tmp) / PKG.name
    shutil.copytree(PKG, stage, ignore=shutil.ignore_patterns('.git', '__pycache__', 'MANIFEST.sha256'))
    (stage / HTML).unlink()
    av.ROOT = stage
    data, _ = av.build()
    if sha(stage / HTML) != sha(PKG / HTML):
        fail.append('页面无法由 data/ 逐字节重建')

want = json.loads((PKG / 'expectations.json').read_text())['expectations']
cases = data['cases']
got = {'domains': len(data['domains']), 'objects': len(data['objects']),
       'cross_domain_objects': len(data['security_objects']), 'shared_views': len(data['security_views']),
       'risks': len(data['risks']), 'failure_modes': len(data['failure_modes']), 'links': len(data['links']),
       'technical_requirements': len(data['defense']['technical_requirements']),
       'joint_checks': len(data['defense']['joint_checks']),
       'safeguards': len(data['defense']['safeguards']), 'cases': len(cases),
       'case_object_mappings': sum(len(c.get('object_mappings', [])) for c in cases.values()),
       'case_references': sum(len(c['references']) for c in cases.values())}
for key, value in want.items():
    if got.get(key) != value:
        fail.append(f'计数不符 {key}: 声明 {value}，实际 {got.get(key)}')

print(json.dumps({'verdict': 'FAIL' if fail else 'PASS', 'failures': fail, 'counts': got},
                 ensure_ascii=False, indent=2))
sys.exit(1 if fail else 0)
