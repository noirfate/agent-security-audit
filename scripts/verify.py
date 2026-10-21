#!/usr/bin/env python3
"""校验发布包：参考源指纹、声明计数，以及索引、页面与知识包能否逐字节重建。"""
import hashlib, json, pathlib, shutil, sys, tempfile

PKG = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / 'scripts'))
import agent_audit_versioning as av
import package_skill

HTML = 'AI-Agent安全审计图谱.html'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
fail = []

meta = json.loads((PKG / 'data/metadata.json').read_text())
for rel, digest in meta['source_hashes'].items():
    if not (PKG / rel).is_file() or sha(PKG / rel) != digest:
        fail.append('参考源指纹不符: ' + rel)

with tempfile.TemporaryDirectory() as tmp:
    stage = pathlib.Path(tmp) / PKG.name
    shutil.copytree(PKG, stage, ignore=shutil.ignore_patterns('.git', '__pycache__', 'agent_audit'))
    for name in ('explorer-data.json', HTML):
        (stage / name).unlink(missing_ok=True)
    av.ROOT = stage
    data, _ = av.build()
    exported = package_skill.export(stage, data)
    for name in ('explorer-data.json', HTML):
        current = PKG / name
        if not current.is_file() or sha(stage / name) != sha(current):
            fail.append('产物无法由 data/ 与 ui/ 逐字节重建: ' + name)
    for name in ('framework.json', 'manifest.json'):
        current = PKG / 'skills/agent-security-audit/knowledge' / name
        if not current.is_file() or sha(exported / name) != sha(current):
            fail.append('独立知识包无法由规范数据重建: ' + name)

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
