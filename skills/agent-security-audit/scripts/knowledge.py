#!/usr/bin/env python3
"""Read-only, offline queries over the published or audit-pinned framework."""
# Importable under `python3 -I`, which clears the script directory from sys.path:
# the session rule is to read untrusted data with -I, and these scripts import
# their siblings, so without this they fail before doing anything.
import sys as _sys
from pathlib import Path as _Path
if str(_Path(__file__).resolve().parent) not in _sys.path:
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import sys

SKILL = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_bundle(directory=None):
    directory = Path(directory) if directory else SKILL / 'knowledge'
    manifest = read(directory / 'manifest.json')
    if manifest.get('bundle_schema') != '1.0' or manifest.get('contract_schema') != '3.0':
        raise ValueError('Unsupported knowledge contract; install a matching skill release.')
    if set(manifest.get('files', {})) != {'framework.json'}:
        raise ValueError('Invalid knowledge file list')
    fingerprint = digest(directory / 'framework.json')
    if fingerprint != manifest['files']['framework.json']:
        raise ValueError('Knowledge fingerprint mismatch; do not repair it during an audit.')
    data = read(directory / 'framework.json')
    if data.get('bundle_schema') != '1.0' or data['contract']['schema_version'] != '3.0':
        raise ValueError('Knowledge payload schema mismatch')
    return data, manifest, fingerprint


def baseline_dir(workspace, baseline_id):
    if len(baseline_id) != 64 or any(c not in '0123456789abcdef' for c in baseline_id):
        raise ValueError('Invalid baseline id')
    return Path(workspace) / 'baselines' / baseline_id


def objects(data):
    return {**data['objects'], **data['security_objects'], **data['security_views']}


def procedures(key=None, full=False):
    directory = SKILL / 'references' / 'procedures'
    catalog = read(directory / 'catalog.json')
    rows = [r for r in catalog if key is None or r['id'] == key or key in r['object_ids']]
    if full:
        if len(rows) != 1 or rows[0]['id'] != key:
            raise ValueError('procedure requires an exact method id')
        row = rows[0]
        path = (directory / row['file']).resolve()
        if directory.resolve() not in path.parents:
            raise ValueError('Procedure path escapes method directory')
        return {**row, 'content': path.read_text(encoding='utf-8')}
    return rows


def brief(workspace, state, unit, data=None):
    """Markdown projection of the framework for one unit: only what its objects need.

    A full `object` query is 19-24 KB and a multi-repo target touches dozens of
    objects, so a worker that queries them itself spends its whole window before
    reading any code. The brief is cut once, by the dispatcher, from the pinned
    baseline. Linked risk IDs and names provide optional lookups; risk and case
    texts stay out of the prompt and are never evidence about the target.
    """
    data = data or load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))[0]
    objs = objects(data)
    object_ids = [oid for oid in unit.get('object_ids') or [] if oid in objs]
    lines = ['FM 的 statement 确定审计问题；以下前提、判据、取证要求和步骤均为非穷尽参考。'
             '模型结合目标决定如何检查并记录证据、反证或缺口；不要求逐条满足参考字段。', '']
    if any(m.get('risk_ids') for m in data['failure_modes'].values()
           if m['object_id'] in object_ids):
        directory = (baseline_dir(workspace, state['framework']['baseline_id'])
                     if workspace is not None else SKILL / 'knowledge')
        query_workspace = str(Path(workspace).resolve()) if workspace is not None else '<WORKSPACE>'
        command = shlex.join(['python3', str(SKILL / 'scripts' / 'knowledge.py'),
                              '--workspace', query_workspace, 'risk', '<风险ID>'])
        lines += ['关联风险链接指向知识包中的 `risks[风险ID]`。按需了解定义、机制、影响或防护时，'
                  '用下列命令替换 `<风险ID>`，只读取该条风险及其关联：', '',
                  '```bash', command, '```', '',
                  '风险内容用于帮助理解 FM 命题，不限定命题范围，也不是目标证据；'
                  '是否读取由模型判断，无须逐风险交阅读记录或另建检查任务。', '',
                  '[risk-catalogue]: <%s>' % (directory / 'framework.json').resolve(), '']
    methods = []
    if unit.get('kind') == 'cross':
        lines += ['### 系统级联合核查（全部 %d 项）' % len(data['defense']['joint_checks']), '']
        for check in data['defense']['joint_checks']:
            lines += ['- **%s**（%s）：%s' % (check['name'], check.get('location', ''),
                                             '；'.join(check.get('checks', []))),
                      '  取证：%s；范围：%s' % ('；'.join(check.get('evidence', [])), check.get('scope', ''))]
        lines.append('')
    for oid in object_ids:
        obj = objs[oid]
        lines += ['### %s %s' % (oid, obj['name']), '', obj['definition'], '']
        if obj.get('responsibilities'):
            lines += ['职责：' + '；'.join(obj['responsibilities']), '']
        if obj.get('technical_audit_focus'):
            lines += ['取证重点：' + '；'.join(obj['technical_audit_focus']), '']
        for boundary in obj.get('boundaries', []):
            lines.append('- 边界：%s（相邻对象：%s）'
                         % (boundary['description'], '、'.join(boundary.get('object_ids', []))))
        if obj.get('boundaries'):
            lines.append('')
        mapping = data['defense']['object_mappings'].get(oid) or {}
        for tid in mapping.get('technical_requirement_ids', []):
            requirement = data['defense']['technical_requirements'][tid]
            lines += ['- 技术要求 %s：%s' % (tid, '；'.join(requirement.get('requirements', []))),
                      '  核查：%s；取证：%s' % ('；'.join(requirement.get('checks', [])),
                                               '；'.join(requirement.get('evidence', []))),
                      '  可见性边界：%s' % requirement.get('visibility_boundary', '')]
        if mapping.get('technical_requirement_ids'):
            lines.append('')
        for mode in [m for m in data['failure_modes'].values() if m['object_id'] == oid]:
            lines += ['#### %s（在攻击路径中的角色：%s）' % (mode['id'], mode.get('role', '未标')), '',
                      mode['statement'], '']
            if mode.get('risk_ids'):
                lines.append('- 关联风险（按需查阅）：' + '；'.join(
                    '[%s · %s][risk-catalogue]' % (
                        rid, data['risks'][rid].get('name_zh') or data['risks'][rid].get('name_en') or rid)
                    for rid in mode['risk_ids']))
            lines += ['- 参考适用前提：' + ' / '.join(mode['applicability_conditions']),
                      '- 参考失效判据：' + ' / '.join(mode['failure_criteria']),
                      '- 建议取证材料：' + '；'.join(mode.get('evidence_requirements', [])),
                      '- 参考技术要求：' + (mode.get('requirement') or ''),
                      '- 参考核查步骤：' + '；'.join(mode.get('checks', [])),
                      '- 参考检测信号：' + '；'.join(mode.get('detection_signals', [])), '']
        for row in procedures(oid):
            if row['id'] not in methods:
                methods.append(row['id'])
        joint = [c['name'] for c in data['defense']['joint_checks']
                 if oid in c.get('object_ids', []) or obj.get('canonical_id') in c.get('object_ids', [])]
        if joint:
            lines += ['相关联合核查（落成本地检查时引用名称，不要伪造 FM 编号）：' + '、'.join(joint), '']
    if not object_ids and unit.get('kind') != 'cross':
        lines += ['（本单元尚未映射框架对象：%s。没有合适命题时用本地检查，不要硬套编号。）'
                  % (unit.get('mapping_note') or '待裁决'), '']
    for mid in methods:
        row = procedures(mid, full=True)
        lines += ['### 专项方法 · %s' % row['title'], '', row['content'].strip(), '']
    for row in state.get('route_excluded', []):
        if row['object_id'] in object_ids:
            lines.append('> %s 已按画像裁剪出本轮计划（维度：%s）。这不是不适用判定。'
                         % (row['object_id'], '、'.join(row['dimensions'])))
    return '\n'.join(lines)


def query(data, kind, key=None, limit=10, projection='full'):
    objs = objects(data)
    if kind == 'overview':
        return {'version': data['meta']['data_version'], 'layers': data['layers'],
                'domains': data['domains'],
                'objects': [{'id': k, 'name': v['name'], 'definition': v['definition'],
                             'canonical_id': v.get('canonical_id')} for k, v in objs.items()],
                'counts': {k: len(data[k]) for k in ('failure_modes', 'risks', 'cases')},
                'source_files_bundled': False}
    if kind == 'object':
        obj = objs[key]
        fms = [m for m in data['failure_modes'].values() if m['object_id'] == key]
        cases = []
        for cid, case in data['cases'].items():
            mappings = [m for m in case.get('object_mappings', []) if m['object_id'] == key]
            if mappings:
                cases.append({'id': cid, 'title': case.get('name_zh') or case['title'], 'mappings': mappings})
        profile = data['defense']['object_mappings'][key]
        requirements = [data['defense']['technical_requirements'][tid]
                        for tid in profile.get('technical_requirement_ids', [])]
        joint = [c for c in data['defense']['joint_checks'] if key in c.get('object_ids', [])
                 or obj.get('canonical_id') in c.get('object_ids', [])]
        if projection == 'brief':
            return {'object': {k: obj[k] for k in ('id', 'name', 'definition', 'layer_id',
                                                   'responsibilities', 'technical_audit_focus',
                                                   'boundaries') if k in obj},
                    'failure_modes': fms, 'procedures': [p['id'] for p in procedures(key)],
                    'technical_requirements': requirements,
                    'joint_checks': [c['name'] for c in joint], 'case_count': len(cases),
                    'projection': 'brief：保留命题的 risk_ids；风险与案例全文按需单独查 risk 或 case'}
        return {'object': obj, 'failure_modes': fms, 'procedures': procedures(key),
                'risk_links': [{k: r[k] for k in ('risk_id', 'failure_mode_id', 'role', 'object_id')}
                               for r in data['links'] if r['object_id'] == key],
                'defense_profile': profile,
                'technical_requirements': requirements,
                'joint_checks': joint,
                'cases': cases[:limit], 'case_count': len(cases)}
    if kind == 'mode':
        mode = data['failure_modes'][key]
        return {'mode': mode, 'risk_links': [r for r in data['links'] if r['failure_mode_id'] == key]}
    if kind == 'risk':
        return {'risk': data['risks'][key], 'links': [r for r in data['links'] if r['risk_id'] == key]}
    if kind == 'case':
        return data['cases'][key]
    if kind == 'joint':
        return data['defense']['joint_checks']
    if kind == 'profile':
        return data['audit_profile']
    if kind == 'schema':
        return data['finding_schema']
    if kind in {'procedures', 'procedure'}:
        return procedures(key, full=kind == 'procedure')
    if kind == 'search':
        hits = []
        for label, records in [('object', objs), ('mode', data['failure_modes']),
                               ('risk', data['risks']), ('case', data['cases'])]:
            for rid, row in records.items():
                if key.casefold() in json.dumps(row, ensure_ascii=False).casefold():
                    hits.append({'kind': label, 'id': rid, 'title': row.get('name_zh') or row.get('name')
                                 or row.get('statement') or row.get('title')})
        return {'total': len(hits), 'results': hits[:limit]}
    raise ValueError('Unknown query')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, help='Read the target audit’s pinned baseline')
    parser.add_argument('--limit', type=int, default=10)
    parser.add_argument('kind', choices=['verify', 'overview', 'object', 'mode', 'risk', 'case', 'joint', 'profile', 'schema', 'search', 'procedures', 'procedure', 'brief'])
    parser.add_argument('key', nargs='?')
    parser.add_argument('--brief', action='store_true',
                        help='Project an object query down to what one unit needs')
    args = parser.parse_args()
    try:
        if args.limit < 1:
            raise ValueError('limit must be positive')
        directory = None
        if args.workspace:
            state = read(args.workspace / 'audit.json')
            directory = baseline_dir(args.workspace, state['framework']['baseline_id'])
        data, manifest, fingerprint = load_bundle(directory)
        if args.kind in {'object', 'mode', 'risk', 'case', 'search', 'procedure', 'brief'} and not args.key:
            raise ValueError('This query requires an id or search text')
        if args.kind == 'brief':
            if not args.workspace:
                raise ValueError('brief reads the target record; pass --workspace')
            unit = next((u for u in state.get('units', []) if u['id'] == args.key), None)
            if unit is None:
                raise ValueError('Unknown unit: ' + str(args.key))
            print(brief(args.workspace, state, unit, data))
            return 0
        result = ({'valid': True, 'baseline_id': fingerprint, **manifest} if args.kind == 'verify'
                  else query(data, args.kind, args.key, args.limit, 'brief' if args.brief else 'full'))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
