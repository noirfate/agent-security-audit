#!/usr/bin/env python3
"""Publish a deterministic knowledge snapshot. Never called by an audit."""
import hashlib
import json
from pathlib import Path

import agent_audit_versioning as av


def export(package, data):
    package = Path(package)
    target = package / 'skills/agent-security-audit/knowledge'
    framework = {
        'bundle_schema': '1.0',
        'contract': av.read(package / 'data-contract.json'),
        'audit_profile': av.read(package / 'data/audit-profile.json'),
        'finding_schema': av.read(package / 'data/finding-schema.json'),
        **data,
    }
    raw = (json.dumps(framework, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    sources = sorted((package / 'data').glob('*.json')) + [package / 'data-contract.json']
    manifest = {
        'bundle_schema': '1.0',
        'framework_version': data['meta']['data_version'],
        'contract_schema': framework['contract']['schema_version'],
        'source_files_bundled': False,
        'source_note': 'sources/引用指向框架发布包的原件，不在独立skill内。外部链接与许可保留在meta中。',
        'source_hashes': {str(p.relative_to(package)): av.sha(p) for p in sources},
        'files': {'framework.json': hashlib.sha256(raw).hexdigest()},
    }
    target.mkdir(parents=True, exist_ok=True)
    (target / 'framework.json').write_bytes(raw)
    av.write(target / 'manifest.json', manifest)
    return target


if __name__ == '__main__':
    print(export(av.ROOT, av.compile_data()).relative_to(av.ROOT))
