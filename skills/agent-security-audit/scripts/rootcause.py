#!/usr/bin/env python3
"""跨单元根因的候选与裁决。The signals are mechanical; the merge is the model's.

A root cause spans units by construction: the partition cuts by directory and
responsibility, a defect distributes by mechanism. So no worker can see one (its unit is
frozen and parallel), `merge` refuses semantic judgements, and the report writer may
neither keep a second finding list nor touch a reviewed finding. This module gives the
segment reviewer the handle and the write path. It never declares a merge itself.

Both signals were measured on a 227-finding audit before being chosen, and those numbers
are why the output has the shape it has:

* 命题共享（`fm:`）—— 63 families hold ≥2 findings, 30 span ≥3 units. Families
  recur legitimately too: one holds 12 findings that are 12 separate authorization gaps.
  A lead, never a verdict.
* 位置重合（`set:`）—— 375 pairs of findings share an identical evidence location.
  Transitive closure over that relation is useless: it chains 137 of the 227 findings
  into a single component. So a candidate is the set of findings citing one identical
  location, and its weight is how many identical locations that same set shares (6 at
  the top of that audit).
* 修复建议文本相似度 was measured and dropped. Among the 72 findings with no framework
  proposition it produced 0 pairs at a 0.6 difflib ratio and 1 same-unit pair at 0.3.
  A signal that fires on nothing is worse than no signal, because it reads as coverage.
  Those 72 are reported as their own bucket instead — the proposition signal is blind to
  them by construction.

`strong` is a floor, not the job. Of eight root-cause families read out of that audit by
hand, seven have a strong candidate and one — the shared media loader, five findings
across four units — has none, because its members share locations only one at a time.
That is why the contracts route the merge-type report todos and the no-proposition
bucket alongside this list, and why `--apply` accepts a cluster no candidate proposed.
"""
import copy
import hashlib
import json
import re
from collections import defaultdict

from units import id_owner

STRONG_FM_UNITS = 3
STRONG_LOCATIONS = 3
VERDICTS = ('merge', 'distinct')
ROW_KEYS = {'id', 'verdict', 'statement', 'fix_point', 'finding_ids', 'member_paths',
            'candidates', 'by', 'reason'}
PATH_KEYS = {'finding_id', 'location', 'difference'}
ID_RE = re.compile(r'RC-[0-9A-Za-z-]{2,}$')


def _current(state):
    return [f for f in state.get('findings') or [] if f.get('status') == 'current']


def _modes(state):
    checks = {c['id']: c for c in state.get('checks') or []}
    return {f['id']: sorted({(checks.get(c) or {}).get('failure_mode_id')
                             for c in f.get('check_ids') or []
                             if (checks.get(c) or {}).get('failure_mode_id')})
            for f in _current(state)}


def _units_of(ids):
    return sorted({id_owner(i) for i in ids if id_owner(i)})


def _locator_text(locator):
    if isinstance(locator, dict):
        return '；'.join('%s %s' % (key, '-'.join(str(v) for v in locator[key]))
                        if isinstance(locator[key], list)
                        else '%s %s' % (key, locator[key])
                        for key in sorted(locator))
    return json.dumps(locator, ensure_ascii=False, sort_keys=True)


def candidates(state):
    """One row per mechanical lead, strong ones first. No verdict is implied."""
    findings = _current(state)
    evidence = {e['id']: e for e in state.get('evidence') or []}
    materials = state.get('materials') or {}
    modes = _modes(state)

    by_mode = defaultdict(set)
    for fid, owned in modes.items():
        for mode in owned:
            by_mode[mode].add(fid)
    rows = {}
    for mode in sorted(by_mode):
        members = sorted(by_mode[mode])
        if len(members) < 2:
            continue
        units = _units_of(members)
        rows['fm:' + mode] = {
            'key': 'fm:' + mode, 'finding_ids': members, 'units': units,
            'basis': ['命题 %s 被 %d 条发现引用，跨 %d 个单元' % (mode, len(members), len(units))],
            # Units, not findings: a member contributes at most one unit, so this
            # already implies three findings. Two thresholds would mean one of them
            # could be widened with nothing to show for it.
            'strong': len(units) >= STRONG_FM_UNITS}

    by_location = defaultdict(set)
    for finding in findings:
        for eid in finding.get('evidence_ids') or []:
            row = evidence.get(eid)
            if not row:
                continue
            by_location[(row.get('material_id'),
                         json.dumps(row.get('locator'), sort_keys=True,
                                    ensure_ascii=False))].add(finding['id'])
    places = defaultdict(list)
    for (mid, locator), owners in by_location.items():
        if len(owners) < 2:
            continue
        places[tuple(sorted(owners))].append(
            '%s（%s）' % ((materials.get(mid) or {}).get('path') or mid,
                         _locator_text(json.loads(locator))))
    for members, where in sorted(places.items()):
        units = _units_of(members)
        strong = len(where) >= STRONG_LOCATIONS and len(units) >= 2
        basis = '%d 处完全相同的证据位置：%s' % (len(where), '、'.join(sorted(where)[:3]))
        # Two signals on the same member set are one adjudication, not two: the
        # proposition key keeps the row and absorbs the location basis.
        same = next((r for r in rows.values() if tuple(r['finding_ids']) == members), None)
        if same is not None:
            same['basis'].append(basis)
            same['strong'] = same['strong'] or strong
            continue
        key = 'set:' + '+'.join(members)
        rows[key] = {'key': key, 'finding_ids': list(members), 'units': units,
                     'basis': [basis], 'strong': strong}
    out = list(rows.values())
    for row in out:
        row['cross_unit'] = len(row['units']) > 1
    return sorted(out, key=lambda r: (not r['strong'], not r['cross_unit'], r['key']))


def no_proposition(state, rows):
    """The findings the proposition signal cannot see, and which of them have no lead."""
    local = sorted(fid for fid, owned in _modes(state).items() if not owned)
    paired = {fid for row in rows for fid in row['finding_ids']}
    return {'count': len(local), 'finding_ids': local,
            'unpaired': sorted(set(local) - paired),
            'note': '全是目标本地检查，没有框架命题，命题信号对它们失效；'
                    'unpaired 的那些连位置信号也没有邻居，只能靠读。'}


def closure(state, rows=None):
    """Which strong candidates must be answered, and whether an answer named every member.

    Grandfathered per unit, not per workspace. `queue.legacy_freeze_contract` marks a
    record as migrated for good, so skipping the whole row on it would mean a workspace
    that was ever migrated is never held to this again — including a round done entirely
    under this contract, which is where the long-lived workspaces are. A strong candidate
    is exempt only when every member belongs to a unit that merged under an older
    contract: that is the entire strong slice on a migrated audit, and none of it for a
    unit merged since. `incomplete` is deliberately not limited to the strong ones —
    answering a candidate at all is a choice, and a half-answer is the shape the report
    todos actually took, some of the findings the requirement named rather than all.
    """
    rows = candidates(state) if rows is None else rows
    index = {row['key']: row for row in rows}
    legacy = {unit['id'] for unit in state.get('units') or []
              if unit.get('legacy_schema_version')}
    by_key = defaultdict(list)
    for cause in state.get('root_causes') or []:
        for key in cause.get('candidates') or []:
            by_key[str(key)].append(cause)
    strong = [row for row in rows if row['strong']]
    exempt = [row['key'] for row in strong
              if all(('U-' + (id_owner(fid) or '')) in legacy for fid in row['finding_ids'])]
    mandatory = [row['key'] for row in strong if row['key'] not in set(exempt)]
    incomplete = []
    for row in rows:
        answers = by_key.get(row['key']) or []
        if not answers:
            continue
        named = {fid for answer in answers for fid in answer.get('finding_ids') or []}
        unanswered = [fid for fid in row['finding_ids'] if fid not in named]
        if unanswered:
            incomplete.append({'candidate': row['key'], 'unanswered': unanswered,
                               'rows': [str(a.get('id')) for a in answers]})
    stale = [{'root_cause_id': str(cause.get('id')), 'candidate': str(key)}
             for cause in state.get('root_causes') or []
             for key in cause.get('candidates') or [] if str(key) not in index]
    return {'strong': [row['key'] for row in strong], 'mandatory': mandatory,
            'grandfathered': exempt,
            'open_mandatory': [key for key in mandatory if not by_key.get(key)],
            'incomplete': incomplete, 'stale_candidates': stale,
            'adjudicated': {key: [str(a.get('id')) for a in answers]
                            for key, answers in sorted(by_key.items())}}


def digest(state, rows=None):
    """What the model read before adjudicating: the candidate sets and the existing rows."""
    rows = candidates(state) if rows is None else rows
    payload = [[row['key'], row['finding_ids']] for row in rows]
    payload.append(sorted(str(c.get('id')) for c in state.get('root_causes') or []))
    return hashlib.sha256(json.dumps(payload, sort_keys=True,
                                     ensure_ascii=False).encode()).hexdigest()


def survey(state):
    rows = candidates(state)
    merged = [c for c in state.get('root_causes') or [] if c.get('verdict') == 'merge']
    grouped = {fid for cause in merged for fid in cause.get('finding_ids') or []}
    return {'base_sha256': digest(state, rows),
            'findings': len(_current(state)), 'candidates': len(rows),
            'root_causes': {'merge': len(merged),
                            'distinct': len([c for c in state.get('root_causes') or []
                                             if c.get('verdict') == 'distinct']),
                            'grouped_findings': len(grouped),
                            'ungrouped_findings': len(_current(state)) - len(grouped)},
            'closure': closure(state, rows), 'no_proposition': no_proposition(state, rows),
            'rows': rows,
            'note': '候选是线索，不是分母：两个信号都有误配（同名命题可以是同一处授权缺失重复'
                    '十二次，也可以是十二个模块各自缺一次），实测还漏掉了一整族（成员每次只'
                    '共享一处位置）。强候选是必须答的下限，不是可以归并的上限——没有候选的'
                    '簇照样可以 --apply，合并呈现类的报告待办与 no_proposition 要一起读。'}


def _row_problems(state, row, keys, claimed):
    """Everything about one submitted adjudication whose answer the record fixes."""
    findings = {f['id']: f for f in _current(state)}
    rid = str(row.get('id'))
    out = []
    if not ID_RE.match(rid):
        return [rid + '：根因 id 以 RC- 开头，不带单元 token（根因按构造跨单元）']
    stray = sorted(set(row) - ROW_KEYS)
    if stray:
        out.append(rid + '：未定义键 ' + '、'.join(stray))
    verdict = row.get('verdict')
    if verdict not in VERDICTS:
        out.append(rid + '：verdict 取 merge 或 distinct')
    members = row.get('finding_ids')
    if not isinstance(members, list):
        out.append(rid + '：finding_ids 是发现号的列表')
        members = []
    elif len(members) < 2:
        # Kept as submitted: resetting it here made the path count report 「成员 0，路径 2」
        # alongside the real message, and a reader fixes what the message says.
        out.append(rid + '：finding_ids 至少两条')
    unknown = [m for m in members if m not in findings]
    if unknown:
        out.append(rid + '：不是当前发现 ' + '、'.join(unknown[:4]))
    if len(set(members)) != len(members):
        out.append(rid + '：finding_ids 有重复')
    if not str(row.get('reason') or '').strip():
        out.append(rid + '：reason 写明依据——判同源靠什么，判不同源差在哪')
    if not str(row.get('by') or '').strip():
        out.append(rid + '：by 写明裁决者')
    named = row.get('candidates') or []
    if not isinstance(named, list) or any(not isinstance(k, str) for k in named):
        out.append(rid + '：candidates 是候选 key 的列表（可以为空）')
    else:
        missing = [k for k in named if k not in keys]
        if missing:
            out.append(rid + '：当前候选里没有 ' + '、'.join(missing[:4])
                       + '（先跑一次 rootcause 读现在的 key）')
    if verdict == 'merge':
        for key in ('statement', 'fix_point'):
            if not str(row.get(key) or '').strip():
                out.append(rid + '：merge 要 ' + key)
        paths = row.get('member_paths')
        if not isinstance(paths, list):
            out.append(rid + '：member_paths 是受影响路径的列表')
        else:
            owners = [p.get('finding_id') for p in paths if isinstance(p, dict)]
            if sorted(owners) != sorted(members):
                out.append(rid + '：每个成员恰好一条受影响路径（成员 %d，路径 %d）'
                           % (len(members), len(owners)))
            for path in paths:
                if not isinstance(path, dict):
                    out.append(rid + '：member_paths 的每项是对象')
                    continue
                # The row has a key whitelist; without one here the two layers disagree,
                # and an extra key written into an affected path lands in the record
                # while records.md enumerates exactly three.
                stray_path = sorted(set(path) - PATH_KEYS)
                if stray_path:
                    out.append('%s / %s：受影响路径里有未定义键 %s'
                               % (rid, path.get('finding_id'), '、'.join(stray_path)))
                for key in ('location', 'difference'):
                    if not str(path.get(key) or '').strip():
                        out.append('%s / %s：缺 %s——归并保留受影响路径，差异不写就是丢路径'
                                   % (rid, path.get('finding_id'), key))
        for member in members:
            if claimed.get(member, rid) != rid:
                out.append('%s：%s 已归入 %s，一条发现只有一个根因'
                           % (rid, member, claimed[member]))
    elif verdict == 'distinct':
        for key in ('statement', 'fix_point'):
            if str(row.get(key) or '').strip():
                out.append(rid + '：判不同源的那条不写 ' + key + '——理由写进 reason')
        if row.get('member_paths'):
            out.append(rid + '：判不同源的那条不写 member_paths')
    return out


def apply_adjudication(workspace, state, payload):
    """Record adjudications and the back-links, after checking all of them."""
    from audit import save
    if not isinstance(payload, dict) or not isinstance(payload.get('root_causes'), list) \
            or not payload['root_causes']:
        raise ValueError('rootcause --apply needs a nonempty root_causes list')
    rows = candidates(state)
    current = digest(state, rows)
    if payload.get('base_sha256') != current:
        # Both values, because the message has to separate 「my hash is old」 from
        # 「this comparison is wrong」. Without them the only available action is to copy
        # the hash again, which does nothing when the submission was not the stale side.
        raise ValueError('Stale base_sha256: the record now reads %s, the submission says '
                         '%s. Run rootcause and read the current candidates — a successful '
                         'apply changes it too, so a second batch needs a fresh one.'
                         % (current, payload.get('base_sha256')))
    keys = {row['key'] for row in rows}
    working = copy.deepcopy(state)
    existing = {str(c.get('id')): c for c in working.get('root_causes') or []}
    claimed = {fid: rid for rid, cause in existing.items()
               for fid in cause.get('finding_ids') or []
               if cause.get('verdict') == 'merge'}
    incoming, problems, seen = [], [], set()
    for item in payload['root_causes']:
        if not isinstance(item, dict):
            problems.append('每条裁决是一个对象')
            continue
        row = {k: v for k, v in item.items()}
        row.setdefault('by', payload.get('by'))
        rid = str(row.get('id'))
        if rid in seen:
            problems.append(rid + '：同一次提交里重复')
            continue
        seen.add(rid)
        # A replacement releases the members it no longer claims, so the check below
        # judges the state this apply would leave, not the one it started from.
        for fid, owner in list(claimed.items()):
            if owner == rid:
                claimed.pop(fid)
        problems += _row_problems(state, row, keys, claimed)
        if row.get('verdict') == 'merge':
            for fid in row.get('finding_ids') or []:
                claimed.setdefault(fid, rid)
        incoming.append(row)
    if problems:
        raise ValueError('；'.join(problems[:6]))
    replaced = sorted(str(r['id']) for r in incoming if str(r['id']) in existing)
    for row in incoming:
        existing[str(row['id'])] = row
    working['root_causes'] = [existing[k] for k in sorted(existing)]
    merged = {fid: str(c['id']) for c in working['root_causes']
              if c.get('verdict') == 'merge' for fid in c.get('finding_ids') or []}
    cleared = []
    for finding in working.get('findings') or []:
        want = merged.get(finding['id'])
        if finding.get('root_cause_id') and finding.get('root_cause_id') != want:
            cleared.append(finding['id'])
        finding['root_cause_id'] = want
    save(workspace, working)
    state.clear()
    state.update(working)
    return {'applied': len(incoming), 'replaced': replaced,
            'root_causes': len(working['root_causes']),
            'grouped_findings': len(merged), 'relinked': sorted(cleared),
            'closure': closure(working)}
