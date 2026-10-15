#!/usr/bin/env python3
"""从 data/ 与 ui/ 重新生成 explorer-data.json、页面、manifest.json 与 MANIFEST.sha256。"""
import hashlib, json, pathlib, sys

PKG = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / 'scripts'))
import agent_audit_versioning as av

SKIP_DIRS = {'.git', '__pycache__'}


def tracked_files():
    """Everything that belongs to the package: no VCS metadata, no interpreter caches."""
    for path in sorted(PKG.rglob('*')):
        rel = path.relative_to(PKG)
        if path.is_file() and rel.name != 'MANIFEST.sha256' and rel.suffix not in {'.pyc', '.pyo'} \
                and not any(part in SKIP_DIRS for part in rel.parts):
            yield path, rel


def write_manifest():
    rows = [(hashlib.sha256(p.read_bytes()).hexdigest(), rel.as_posix()) for p, rel in tracked_files()]
    (PKG / 'MANIFEST.sha256').write_text(''.join(f'{d}  {r}\n' for d, r in rows), encoding='utf-8')
    return len(rows)


if __name__ == '__main__':
    data, targets = av.build()
    print(json.dumps({'objects': len(data['objects']), 'risks': len(data['risks']),
                      'cases': len(data['cases']), 'failure_modes': len(data['failure_modes']),
                      'outputs': [str(t.relative_to(PKG)) for t in targets],
                      'manifest_files': write_manifest()}, ensure_ascii=False))
