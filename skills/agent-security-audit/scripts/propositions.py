#!/usr/bin/env python3
"""Show proposition checks with their instance, baseline, scope and evidence context.
Only explicitly requested reconciliation tasks block closure; verdict differences do not."""
# Importable under `python3 -I`, which clears the script directory from sys.path:
# the session rule is to read untrusted data with -I, and these scripts import
# their siblings, so without this they fail before doing anything.
import sys as _sys
from pathlib import Path as _Path
if str(_Path(__file__).resolve().parent) not in _sys.path:
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
import json
import sys
from collections import defaultdict
from pathlib import Path

VERDICT_ORDER = ('confirmed', 'not_established', 'insufficient_evidence', 'not_applicable')


def survey(state):
    """One row per framework proposition that any check refers to."""
    instances = {i['id']: i for i in state.get('instances', [])}
    by_mode = defaultdict(list)
    for check in state.get('checks', []):
        mode = check.get('failure_mode_id')
        if not mode:
            continue
        owners = sorted({instances[i]['unit_id'] for i in check.get('instance_ids') or []
                         if i in instances and instances[i].get('unit_id')})
        by_mode[mode].append({
            'check_id': check['id'], 'units': owners,
            'instance_ids': sorted(check.get('instance_ids') or []),
            'applicability': check.get('applicability'), 'verdict': check.get('verdict'),
            'status': check.get('status'), 'baseline_id': check.get('baseline_id'),
            'scope': check.get('scope'), 'criteria': check.get('criteria'),
            'evidence_ids': check.get('evidence_ids') or [],
            'counterevidence_ids': check.get('counterevidence_ids') or [],
            'explanation': check.get('explanation'),
        })
    accounted = {row.get('failure_mode_id'): row
                 for row in state.get('reconciliations', [])}
    out = []
    for mode in sorted(by_mode):
        judged = by_mode[mode]
        verdicts = sorted({row['verdict'] for row in judged if row['verdict']},
                          key=lambda v: VERDICT_ORDER.index(v) if v in VERDICT_ORDER else 9)
        row = {'failure_mode_id': mode, 'checks': judged,
               'judged_times': len(judged), 'verdicts': verdicts,
               'divergent': len(verdicts) > 1,
               'units': sorted({u for r in judged for u in r['units']}),
               'account': accounted.get(mode)}
        out.append(row)
    return out


def uninstantiated(workspace, state):
    """Objects a unit declared whose propositions were never turned into checks.

    `seed` expands instance x mapped object x proposition, so a unit that declares an
    object without a matching instance gets **no checks for that object at all** — and
    nothing notices, because every check that does exist is complete. That is the same
    shrinking denominator as an object nobody ruled out: the claim reads as coverage
    while the questions were never asked. Missing instances are a legitimate state, but
    then the unit has to say so in its mapping note or a scope note.
    """
    from knowledge import baseline_dir, load_bundle
    data, _, _ = load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))
    by_object = {}
    for mode in data['failure_modes'].values():
        by_object.setdefault(mode['object_id'], set()).add(mode['id'])
    instances = {i['id']: i for i in state.get('instances', [])}
    judged = {}
    for check in state.get('checks', []):
        mode = check.get('failure_mode_id')
        if not mode:
            continue
        for iid in check.get('instance_ids') or []:
            owner = (instances.get(iid) or {}).get('unit_id')
            if owner:
                judged.setdefault(owner, set()).add(mode)
    problems = []
    for unit in state.get('units', []):
        if unit['kind'] == 'cross' or unit['status'] not in {'merged', 'reviewed'}:
            continue
        if str(unit.get('mapping_note') or '').strip():
            continue
        for oid in unit.get('object_ids') or []:
            missing = sorted(by_object.get(oid, set()) - judged.get(unit['id'], set()))
            if missing:
                problems.append('%s 声明了 %s，但其 %d 条命题从未实例化为检查（首条 %s）'
                                % (unit['id'], oid, len(missing), missing[0]))
    return problems


def reconciliation_key(row):
    return (row.get('failure_mode_id'), tuple(sorted(row.get('check_ids') or [])), row.get('by'))


def unaccounted(workspace, state):
    """Show verdict differences; block only explicit, still-open model requests.

    Same mode does not establish same instance, scope, version or evidence. No verdict
    automatically defeats another. A model records status=open to request reconciliation
    and status=complete plus an explanation to close that same set of checks.
    """
    differences = ['%s：%s（%s）' % (r['failure_mode_id'], ' / '.join(r['verdicts']),
                                  '、'.join(r['units']) or '未归属单元')
                   for r in survey(state) if r['divergent']]
    latest = {reconciliation_key(r): r for r in state.get('reconciliations', [])}
    missing = ['%s：%s（%s）' % (r.get('failure_mode_id'), r.get('reason') or '',
                              '、'.join(r.get('check_ids') or []))
               for r in latest.values() if r.get('status') == 'open']
    return {'settled': [], 'deferred': [], 'missing': missing, 'differences': differences}


def _objects_by_mode(workspace, state):
    """`{failure mode: its objects}` from the pinned baseline, empty when unreadable."""
    try:
        from knowledge import baseline_dir, load_bundle
        data, _, _ = load_bundle(baseline_dir(
            workspace, state['framework']['baseline_id']))
    except (OSError, ValueError, KeyError):
        return {}
    out = {}
    for mid, row in (data.get('failure_modes') or {}).items():
        ids = row.get('object_ids') or ([row.get('object_id')] if row.get('object_id') else [])
        out[mid] = {str(o) for o in ids if o}
    return out


def render(state):
    """The per-proposition section the report writer includes."""
    rows = survey(state)
    divergent = [r for r in rows if r['divergent']]
    lines = ['## 按命题对账', '',
             '命题按框架对象定义，而工作按文件划分，所以同一条命题会被每个实例各判一次。',
             '裁决不同本身不是错误——一条命题可以在某个组件上成立、对另一个组件不适用；',
             '以下差异供模型比较实例、scope、基线与证据；仅明确登记的 open 对账任务阻断收口。', '',
             '- 被引用的框架命题：%d 条' % len(rows),
             '- 判过多次的：%d 条' % len([r for r in rows if r['judged_times'] > 1]),
             '- 裁决有分歧的：%d 条，其中已说明 %d 条'
             % (len(divergent), len([r for r in divergent if r['account']])), '']
    if not divergent:
        lines += ['本轮没有分歧裁决。', '']
        return '\n'.join(lines)
    lines += ['| 命题 | 裁决 | 判定处 | 说明 |', '|---|---|---|---|']
    for row in divergent:
        where = '、'.join('%s@%s' % (c['check_id'], '/'.join(c['units']) or '?')
                          for c in row['checks'])
        account = (row['account'] or {}).get('explanation') or '未请求对账或尚未完成；见 reconciliations 原记录'
        lines.append('| %s | %s | %s | %s |'
                     % (row['failure_mode_id'], ' / '.join(row['verdicts']),
                        where, account.replace('\n', ' ')[:200]))
    lines.append('')
    return '\n'.join(lines)


def main():
    """`propositions.py <workspace>` prints the survey; exit 1 when accounts are missing."""
    if len(sys.argv) != 2:
        print(json.dumps({'error': 'usage: propositions.py <workspace>'}, ensure_ascii=False), file=sys.stderr)
        return 2
    workspace = Path(sys.argv[1])
    path = workspace / 'audit.json'
    try:
        state = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    rows = survey(state)
    missing = unaccounted(workspace, state)['missing']
    print(json.dumps({
        'propositions': len(rows),
        'judged_more_than_once': len([r for r in rows if r['judged_times'] > 1]),
        'divergent': len([r for r in rows if r['divergent']]),
        'unaccounted': missing,
        'rows': [{k: v for k, v in r.items() if k != 'checks'} for r in rows if r['divergent']],
    }, ensure_ascii=False, indent=2))
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
