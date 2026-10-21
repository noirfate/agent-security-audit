#!/usr/bin/env python3
"""从 data/ 与 ui/ 重新生成 explorer-data.json、页面与 skill 知识包。"""
import json, pathlib, sys

PKG = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / 'scripts'))
import agent_audit_versioning as av
import package_skill

if __name__ == '__main__':
    data, targets = av.build()
    package_skill.export(PKG, data)
    print(json.dumps({'objects': len(data['objects']), 'risks': len(data['risks']),
                      'cases': len(data['cases']), 'failure_modes': len(data['failure_modes']),
                      'outputs': [str(t.relative_to(PKG)) for t in targets]}, ensure_ascii=False))
