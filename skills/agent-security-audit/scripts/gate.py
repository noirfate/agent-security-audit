#!/usr/bin/env python3
"""Hard gates. Each row is an object that can be traced to closure, not a verdict word.

`validate` checks internal record consistency. These gates check explicit completion
and scope records, not whether the analysis really supports them. Models must still
judge scope, evidence and conclusions. The report also uses these mechanical completion
fields; passing them is not proof of a complete or correct security analysis.

Exit codes are two different directions, and conflating them wastes a round:
  0  every gate passed
  1  read fine, contents are not closed yet  -> fix the records
  2  could not read or parse the workspace   -> fix the path or the file
Run it as it is. Piping it hands the pipeline's exit code to the caller and the gate
passes silently.
"""
# Importable under `python3 -I`, which clears the script directory from sys.path:
# the session rule is to read untrusted data with -I, and these scripts import
# their siblings, so without this they fail before doing anything.
import sys as _sys
from pathlib import Path as _Path
if str(_Path(__file__).resolve().parent) not in _sys.path:
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
import json
import sys
from pathlib import Path

from knowledge import read
from units import census, partition_errors

ROWS = ('G1 单元划分是分区', 'G2 单元内文件与维度处置完整', 'G3 原始索引仅供参考',
        'G4 EXT 入口全覆盖', 'G5 跨边界连接有归属', 'G6 队列冻结未被破坏',
        'G7 发现与记录去向完整', 'G8 覆盖声明与分母一致')


def _row(rid, title, ok, detail, skipped=False):
    return {'id': rid, 'title': title, 'status': 'skip' if skipped else ('pass' if ok else 'fail'),
            'detail': detail}


def evaluate(workspace, state, prepare_report=False):
    from records import summary
    workspace = Path(workspace)
    units = state.get('units', [])
    working = [u for u in units if u['kind'] != 'cross']
    queue = state.get('queue', {}) or {}
    counts = summary(state, workspace)
    rows = []

    if not units:
        rows.append(_row('G1', ROWS[0], False, '没有任何单元：先跑 plan'))
        return rows
    errors = partition_errors(state)
    recount = census(state)
    stored = queue.get('census') or {}
    drift = [k for k in ('enumerated', 'in_units', 'unit_file_count_sum')
             if stored.get(k) is not None and stored.get(k) != recount.get(k)]
    if drift:
        errors.append('stored census differs from the recount on: ' + ', '.join(drift))
    rows.append(_row('G1', ROWS[0], not errors,
                     '材料 %d，入单元 %d，单元 file_count 合计 %d'
                     % (recount['enumerated'], recount['in_units'], recount['unit_file_count_sum'])
                     if not errors else '; '.join(errors[:4])))

    from units import completion_errors
    incomplete = [error for unit in units
                  for error in completion_errors(unit, require_merged=True)]
    rows.append(_row('G2', ROWS[1], not incomplete,
                     '所有单元（含 cross）已合入，文件分母与六个维度都有记录'
                     if not incomplete else '；'.join(incomplete)))

    rows.append(_row('G3', ROWS[2], True,
                     '可选检索不构成覆盖分母；正式任务由 G2/G7/G8 核对', skipped=True))

    owner = {mid: unit['id'] for unit in working for mid in unit['material_ids']}
    merged = {u['id'] for u in units if u['status'] in {'merged', 'reviewed'}}
    complete_checks = {}
    for check in state['checks']:
        for iid in check['instance_ids']:
            complete_checks.setdefault(iid, []).append(check['status'])
    # Exposure is read off the UNIT, not the instance. Instances carry no exposure in
    # practice: the worker contract asks for it on findings and the orchestration
    # adjudicates it per unit, so an instance-based check reports "0 EXT instances" and
    # passes forever. A gate that cannot fire is worse than no gate.
    ext_problems = []
    ext_units = [u for u in working if u['exposure'] == 'EXT']
    for unit in ext_units:
        owned = set(unit['material_ids'])
        instances = [i for i in state['instances'] if owned & set(i.get('material_ids', []))]
        if unit['id'] not in merged:
            ext_problems.append(unit['id'] + ' 是 EXT 单元但尚未合入')
            continue
        if not instances:
            ext_problems.append(unit['id'] + ' 已合入但没有登记任何实例')
        for instance in instances:
            if 'complete' not in complete_checks.get(instance['id'], []):
                ext_problems.append('%s/%s 没有任何已完成检查' % (unit['id'], instance['id']))
    ext_total = len(ext_units)
    rows.append(_row('G4', ROWS[3], not ext_problems,
                     'EXT 单元 %d 个全部已合入，其实例都有已完成检查' % ext_total if not ext_problems
                     else '共 %d 条：%s' % (len(ext_problems), '；'.join(ext_problems[:4]))))

    instance_home = {}
    for unit in working:
        for instance in state['instances']:
            if set(instance.get('material_ids', [])) & set(unit['material_ids']):
                instance_home.setdefault(instance['id'], set()).add(unit['id'])
    covered_connections = {cid for unit in units if unit['kind'] == 'cross'
                           for cid in (unit.get('seed') or {}).get('connection_ids', [])}
    uncovered = []
    for edge in state['connections']:
        if edge['id'] in covered_connections:
            continue
        left = instance_home.get(edge['from_instance'], set())
        right = instance_home.get(edge['to_instance'], set())
        if not (left & right):
            uncovered.append(edge['id'])
    rows.append(_row('G5', ROWS[4], not uncovered,
                     '跨单元连接 %d 条都有归属' % len(state['connections']) if not uncovered
                     else '%d 条跨边界连接既不在同一单元内、也没有阶段二单元认领：%s'
                     % (len(uncovered), '、'.join(uncovered[:4]))))

    frozen = []
    if queue.get('phase1_frozen') is None:
        frozen.append('一阶段未冻结：单元划分与对象裁决还没收口')
    else:
        declared_p1 = queue['phase1_frozen']
        working = [u for u in units if u['kind'] != 'cross']
        if declared_p1.get('units') != len(working):
            frozen.append('一阶段冻结时 %s 个单元，现有 %d 个'
                          % (declared_p1.get('units'), len(working)))
    for phase in (2, 3):
        key = 'phase%d_rows_frozen' % phase
        declared = queue.get(key)
        actual = len([u for u in units if u['phase'] == phase])
        if declared is None:
            if phase == 2 or actual or not queue.get('legacy_freeze_contract'):
                frozen.append('%s阶段未冻结（现有 %d 行）' % ('二三'[phase - 2], actual))
        elif declared != actual:
            frozen.append('%s阶段冻结值 %d != 现有行数 %d' % ('二三'[phase - 2], declared, actual))
    if queue.get('phase3_rows_frozen') is not None and not queue.get('phase3_critic'):
        frozen.append('phase3_critic 为空：质问环节没做过')
    if queue.get('phase3_rows_frozen') is not None and not queue.get('legacy_freeze_contract'):
        from units import CROSS_TYPES
        present_types = {u.get('cross_type') for u in units if u['kind'] == 'cross'}
        for kind in CROSS_TYPES:
            choice = (queue.get('cross_scope') or {}).get(kind) or {}
            if choice.get('decision') not in ('needed', 'not_needed') or not choice.get('reason'):
                frozen.append('缺 cross_scope 裁决：' + kind)
            elif (choice['decision'] == 'needed') != (kind in present_types):
                frozen.append('cross_scope 与正式单元不一致：' + kind)
    rows.append(_row('G6', ROWS[5], not frozen,
                     # Named by the phase each count belongs to. These read 「阶段一 / 阶段二」
                     # from the old two-stage vocabulary, so G6 — the row a reader checks
                     # the frozen counts against — reported phase 3's four rows as phase
                     # two's, one phase out of step with the record it certifies.
                     ('旧契约 %s 冻结，未按新契约验证；' % queue['legacy_freeze_contract']
                      if queue.get('legacy_freeze_contract') else '') +
                     '二阶段 %s 行、三阶段 %s 行，与冻结值一致'
                     % (queue.get('phase2_rows_frozen'), queue.get('phase3_rows_frozen'))
                     if not frozen else '；'.join(frozen)))

    reviewed = {r['finding_id'] for r in state.get('reviews', [])}
    # `needs_evidence` is a legitimate review decision, and its result IS a finding left
    # at `needs_review`. Demanding zero such findings makes the gate punish the honest
    # verdict: the only ways to green it are to push an unproven conclusion to current,
    # or to drop it. What must not exist is a finding nobody reviewed at all.
    insufficient = {r['finding_id'] for r in state.get('reviews', [])
                    if r.get('decision') == 'needs_evidence'}
    record_problems = []
    pending = [f['id'] for f in state['findings']
               if f['status'] == 'needs_review' and f['id'] not in insufficient]
    if pending:
        record_problems.append('待复核发现（无任何复核记录）：' + '、'.join(pending[:4]))
    missing_review = [f['id'] for f in state['findings']
                      if f['status'] == 'withdrawn' and f['id'] not in reviewed]
    if missing_review:
        record_problems.append('撤销但无复核记录：' + '、'.join(missing_review[:4]))
    unfinished_checks = [c['id'] for c in state['checks'] if c['status'] != 'complete']
    if unfinished_checks:
        record_problems.append('未完成检查 %d 条：%s'
                               % (len(unfinished_checks), '、'.join(unfinished_checks[:4])))
    if not state['instances']:
        record_problems.append('没有任何实例')
    if not state['checks']:
        record_problems.append('没有任何检查')
    if state.get('pending_framework'):
        record_problems.append('有待采纳的框架版本，先决定引用基线')
    if counts['unreadable_materials'] or counts['enumeration_errors']:
        record_problems.append('不可读材料 %d、枚举错误 %d'
                               % (counts['unreadable_materials'], counts['enumeration_errors']))
    from records import correction_errors
    record_problems.extend(correction_errors(state.get('corrections', [])))
    from propositions import unaccounted, uninstantiated
    try:
        never_asked = uninstantiated(workspace, state)
    except (OSError, ValueError, KeyError) as exc:
        never_asked = ['读不到钉住的基线，无法核对命题分母：%s' % exc]
    if never_asked:
        record_problems.append('命题分母不全：' + '；'.join(never_asked[:3]))
    divergent = unaccounted(workspace, state)
    if divergent['missing']:
        record_problems.append('模型明确请求的对账任务尚未完成：'
                               + '；'.join(divergent['missing'][:3]))
    if divergent['deferred'] and state['queue'].get('phase3_rows_frozen') is not None:
        # Closed at the gate, not at `freeze --phase 3`. Requiring it there deadlocked:
        # the account comes from the joint unit's product, dispatching that unit requires
        # the phase-3 freeze, and the freeze demanded the account. Freeze settles the row
        # set; the gate judges whether delivery is complete.
        record_problems.append('命题裁决的分歧答了「等三阶段 joint 段裁决」，而 joint 段'
                               '已派出却仍无对账说明：' + '；'.join(divergent['deferred'][:3]))
    elif divergent['deferred']:
        # Not an omission: these objects are cross-cutting, the joint segment is where
        # they get settled, and phase 3 refuses to freeze until a joint unit covers them.
        record_problems.append('命题裁决有分歧、等三阶段 joint 段裁决（%d 条，不在二阶段补写）：%s'
                               % (len(divergent['deferred']),
                                  '；'.join(divergent['deferred'][:3])))
    open_todos = [str(t.get('id')) for t in state.get('report_todos', [])
                  if t.get('status') == 'open']
    if open_todos and not prepare_report:
        record_problems.append('呈现要求未闭合：' + '、'.join(open_todos[:4]))
    rows.append(_row('G7', ROWS[6], not record_problems,
                     '发现、检查与材料读取都有去向' if not record_problems
                     else '；'.join(record_problems[:4])))

    accounted = {mid for unit in state['coverage'] if unit['status'] in {'reviewed', 'excluded'}
                 for mid in unit['material_ids']}
    noted = {mid for row in state.get('scope_notes', []) for mid in row.get('material_ids', [])}
    left = sorted({mid for mid, row in state['materials'].items()
                   if row['status'] == 'present'} - accounted - noted)
    coverage_problems = []
    if left:
        coverage_problems.append('%d 条材料既无已完成覆盖、也不在残余前沿清单里：%s'
                                 % (len(left), '、'.join(left[:4])))
    # The object denominator, alongside the material one. Declared objects plus objects
    # ruled out with a basis must be the framework's whole set: an object nobody
    # mentioned would otherwise shrink the coverage claim's denominator silently.
    try:
        from units import _framework_object_ids
        everything = set(_framework_object_ids(workspace, state))
    except (OSError, ValueError, KeyError) as exc:
        coverage_problems.append('读不到钉住的基线，无法核对对象分母：%s' % exc)
        everything = set()
    if everything:
        declared = {oid for unit in units for oid in unit.get('object_ids') or []}
        ruled_out = {str(row.get('subject')) for row in state.get('object_scope', [])
                     if row.get('decision') == 'not_involved' and str(row.get('reason') or '').strip()}
        unspoken = sorted(everything - declared - ruled_out)
        if unspoken:
            coverage_problems.append('%d 个框架对象既没被任何单元声明、也没判过不涉及：%s'
                                     % (len(unspoken), '、'.join(unspoken[:6])))
    rows.append(_row('G8', ROWS[7], not coverage_problems,
                     '覆盖声明与材料、对象两个分母都一致' if not coverage_problems
                     else '；'.join(coverage_problems[:3])))
    return rows


def run(workspace, state, prepare_report=False):
    from records import validate
    structural = validate(workspace, state)
    rows = evaluate(workspace, state, prepare_report=prepare_report)
    failed = [r['id'] for r in rows if r['status'] == 'fail']
    return {'gate': 'FAIL' if structural or failed else 'PASS',
            'purpose': 'report_preparation' if prepare_report else 'final',
            'pending_report_todos': [str(t.get('id')) for t in state.get('report_todos', [])
                                     if t.get('status') == 'open'],
            'structural_errors': structural, 'failed': failed, 'rows': rows,
            'note': '脚本能核的只有做没做、数对不对；想得够不够靠 queue_critic 与复核，'
                    '两件事不互相冒充。'}


def main(argv):
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] != '--prepare'):
        print('usage: gate.py <workspace> [--prepare]', file=sys.stderr)
        return 2
    workspace = Path(argv[1]).expanduser().resolve()
    try:
        state = read(workspace / 'audit.json')
    except (OSError, ValueError) as exc:
        print(json.dumps({'gate': 'UNREADABLE', 'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    try:
        result = run(workspace, state, prepare_report=len(argv) == 3)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({'gate': 'ERROR', 'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['gate'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
