#!/usr/bin/env python3
"""Record one adjudication, and put its answer where the record keeps it.

`plan` asks the questions the files cannot answer — on a multi-repo target that is around
sixty of them. Answering used to mean hand-editing `audit.json` in two places at once:
the decision row, and whatever field actually holds the answer (the unit's exposure, its
depth, its objects, a row in `object_scope`, a path in `exclusions`). Every other write
path here refuses hand editing for exactly the reasons that apply here too — the
reviewer contract says it in so many words — so the one step with sixty edits and no
command was the one most likely to be done wrong.

One answer, one call, both places. The value range is checked against the same constants
the validator uses, so a typo is refused here rather than discovered at the gate.
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

from units import DECISION_KINDS, DEPTHS, EXPOSURES, CROSS_TYPES


def _unit(state, uid):
    unit = next((u for u in state.get('units', []) if u['id'] == uid), None)
    if unit is None:
        raise ValueError('Unknown unit: ' + str(uid))
    return unit


def _framework_objects(workspace, state):
    from knowledge import baseline_dir, load_bundle, objects
    data, _, _ = load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))
    return set(objects(data))


def _apply(workspace, state, decision, resolution, reason):
    """Write the answer into the field that holds it. Returns what it touched."""
    kind, subject = decision['kind'], str(decision['subject'])
    if kind == 'partition':
        if subject != 'queue' or resolution != 'accept':
            raise ValueError('partition:queue takes accept')
        state.setdefault('queue', {}).update(partition_confirmed=True, partition_reason=reason)
        return 'queue.partition_confirmed'
    if kind == 'cross_scope':
        if subject not in CROSS_TYPES or resolution not in ('needed', 'not_needed'):
            raise ValueError('cross_scope requires a cross type and needed|not_needed')
        state.setdefault('queue', {}).setdefault('cross_scope', {})[subject] = {
            'decision': resolution, 'reason': reason}
        return 'queue.cross_scope.' + subject
    if kind == 'object_scope':
        if resolution not in {'involved', 'not_involved'}:
            raise ValueError('object_scope takes involved or not_involved, not ' + resolution)
        if subject not in _framework_objects(workspace, state):
            raise ValueError('%s is not an object in the pinned baseline' % subject)
        rows = state.setdefault('object_scope', [])
        rows[:] = [r for r in rows if str(r.get('subject')) != subject]
        if resolution == 'not_involved':
            rows.append({'id': 'OS-' + subject, 'subject': subject,
                         'decision': 'not_involved', 'reason': reason})
            return 'object_scope[%s]' % subject
        return ('object_scope[%s] 记为涉及；还要让某个单元声明它，否则闸门 G8 仍然报缺'
                % subject)
    if kind == 'exposure':
        if resolution not in EXPOSURES or resolution == 'unknown':
            raise ValueError('exposure takes one of %s'
                             % ', '.join(e for e in EXPOSURES if e != 'unknown'))
        unit = _unit(state, subject)
        unit['exposure'] = resolution
        unit['exposure_reason'] = reason
        return '%s.exposure' % subject
    if kind == 'depth':
        if resolution not in DEPTHS:
            raise ValueError('depth takes one of ' + ', '.join(DEPTHS))
        unit = _unit(state, subject)
        unit['depth'] = resolution
        unit['depth_reason'] = reason
        return '%s.depth' % subject
    if kind == 'object_mapping':
        unit = _unit(state, subject)
        objects = [part.strip() for part in resolution.split(',') if part.strip()]
        if objects == ['none']:
            unit['object_ids'] = []
            unit['mapping_note'] = reason
            return '%s.mapping_note' % subject
        # Checked against the pinned baseline here rather than at seed time: an object
        # id that does not exist would otherwise be accepted as an answer and only fail
        # much later, when the typo is no longer obvious.
        known = _framework_objects(workspace, state)
        stray = [oid for oid in objects if oid not in known]
        if stray:
            raise ValueError('这些对象不在钉住的基线里：%s（不映射任何对象时写 none）'
                             % '、'.join(stray))
        unit['object_ids'] = objects
        unit['mapping_note'] = ''
        # The reason needs a durable home like every other adjudication's: it lived only
        # in the decision row, and the row disappears on the next recompute. A real run
        # lost the written reasons for 99 units that way.
        unit['mapping_reason'] = reason
        return '%s.object_ids' % subject
    if kind == 'cluster_representative':
        cluster = next((c for c in state.get('clusters', []) if c['id'] == subject), None)
        if cluster is None:
            raise ValueError('Unknown cluster: ' + subject)
        if resolution == 'none':
            cluster.update(decision='declined', decision_reason=reason, representative_unit_id=None)
            return '%s.decision' % subject
        if resolution not in cluster['member_unit_ids']:
            raise ValueError('%s is not a member of %s' % (resolution, subject))
        cluster.update(decision='accepted', decision_reason=reason)
        cluster['representative_unit_id'] = resolution
        return '%s.representative_unit_id' % subject
    if kind == 'out_of_scope_candidate':
        if resolution == 'in_scope':
            return '（留在范围内，无字段改动）'
        if resolution != 'out_of_scope':
            raise ValueError('out_of_scope_candidate takes in_scope or out_of_scope')
        target_id, _, directory = subject.partition(':')
        target = next((t for t in state['targets'] if t['id'] == target_id), None)
        if target is None:
            raise ValueError('Unknown target in subject: ' + subject)
        path = str(Path(target['path']) / directory) if directory else target['path']
        if path not in state['exclusions']:
            state['exclusions'].append(path)
        return 'exclusions += %s（改完要 refresh 重新枚举）' % path
    if kind == 'cross_cutting_objects':
        queue = state.setdefault('queue', {})
        if resolution.strip().lower() == 'none':
            queue['joint_objects'] = 'none'
        else:
            from units import _object_scatter
            known = {row['object'] for row in _object_scatter(state)}
            named = [part.strip() for part in resolution.replace('、', ',').split(',')
                     if part.strip()]
            stray = [oid for oid in named if oid not in known]
            if stray:
                raise ValueError('这些对象不在散布清单里：%s（清单里的是 %s）'
                                 % ('、'.join(stray), '、'.join(sorted(known)) or '空'))
            queue['joint_objects'] = ','.join(named)
        queue['joint_objects_reason'] = reason
        return 'queue.joint_objects'
    if kind == 'oversized_unit':
        raise ValueError('Legacy hit threshold is no longer a decision; refresh pending decisions')
    # `unassigned_material` changes the partition itself, which is what `plan --split`
    # and the unit's material list are for. Recording the answer without moving the
    # materials would leave the decision answered and the work undone.
    raise ValueError('%s 要改的是划分本身：用 plan --split 或调整单元材料，'
                     '通过 plan --apply 提交明确划分' % kind)


def decide(workspace, state, decision_id, resolution, reason):
    from audit import save
    if not str(reason or '').strip():
        raise ValueError('每条裁决都要给理由')
    rows = state.get('pending_decisions') or []
    decision = next((d for d in rows if d['id'] == decision_id), None)
    if decision is None and ':' in decision_id:
        # Also addressable as `<kind>:<subject>`. The generated numbers shift on every
        # recompute and an answered question leaves the list entirely, so there was no
        # way to correct an answer afterwards: a real run found a misjudged unit after
        # 204 decisions and had to rebuild the whole partition to redo them.
        kind, _, subject = decision_id.partition(':')
        decision = next((d for d in rows
                         if d['kind'] == kind and str(d['subject']) == subject), None)
        if decision is None and kind in DECISION_KINDS:
            decision = {'id': decision_id, 'kind': kind, 'subject': subject,
                        'question': '（已不在清单里，按 类型:主体 重新作答）',
                        'resolution': None, 'reason': ''}
            rows.append(decision)
            state['pending_decisions'] = rows
    if decision is None:
        raise ValueError('Unknown decision: %s（现有 %d 条；也可以写 <类型>:<主体>，'
                         '例如 object_mapping:U-SH07）' % (decision_id, len(rows)))
    touched = _apply(Path(workspace), state, decision, resolution, reason.strip())
    decision['resolution'] = resolution
    decision['reason'] = reason.strip()
    save(Path(workspace), state)
    return {'decision': decision_id, 'kind': decision['kind'],
            'subject': decision['subject'], 'resolution': resolution,
            'recorded_in': touched,
            'remaining': len([d for d in rows if not d.get('resolution')])}


def main():
    if len(sys.argv) != 5:
        print(json.dumps({'error': 'usage: decide.py <workspace> <DEC-id> <resolution> <reason>'},
                         ensure_ascii=False), file=sys.stderr)
        return 2
    from knowledge import read
    workspace = Path(sys.argv[1])
    try:
        state = read(workspace / 'audit.json')
        print(json.dumps(decide(workspace, state, sys.argv[2], sys.argv[3], sys.argv[4]),
                         ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
