#!/usr/bin/env python3
"""Recall comparison candidates and apply explicit attribution decisions.

File groups, shared propositions, evidence locations, exact material copies and
record links are retrieval signals. Semantic comparisons belong to the attribution
reviewer; the writer binds decisions to their actual facts and preserves history.
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
            'candidates', 'by', 'reason', 'comparisons', 'evidence_ids',
            'source_digest', 'read_dependencies', 'status', 'legacy_review'}
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
    for row in file_candidates(state):
        rows[row['key']] = row
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
                    'unpaired 的那些还没有候选邻居，仍需人工核查。'}


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
    from attribution import fingerprint, finding_packet
    return fingerprint({'facts': finding_packet(state, [f['id'] for f in state.get('findings', [])]),
                        'root_causes': state.get('root_causes', []),
                        'dispositions': state.get('finding_dispositions', []),
                        'chains': state.get('chains', []), 'framework': state.get('framework'),
                        'targets': state.get('targets', []),
                        'todos': [{k: v for k, v in t.items() if k not in {'status', 'reason'}}
                                  for t in state.get('report_todos', [])]})


def survey(state):
    rows = candidates(state)
    merged = [c for c in state.get('root_causes') or [] if c.get('verdict') == 'merge']
    grouped = {fid for cause in merged for fid in cause.get('finding_ids') or []}
    from attribution import build_vulnerability_view
    view = build_vulnerability_view(state)
    return {'base_sha256': digest(state, rows), 'attribution': view,
            'findings': len(_current(state)), 'candidates': len(rows),
            'root_causes': {'merge': len(merged),
                            'distinct': len([c for c in state.get('root_causes') or []
                                             if c.get('verdict') == 'distinct']),
                            'grouped_findings': len(grouped),
                            'ungrouped_findings': len(_current(state)) - len(grouped)},
            'candidate_coverage': closure(state, rows), 'no_proposition': no_proposition(state, rows),
            'rows': rows,
            'note': '候选仅为文件、命题、位置、副本和关联检索线索，不自动判同源。'
                    'candidate_coverage 是候选应答统计；完整收口以 attribution.pending 与 statistics 为准。'}



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
    """Trial the whole batch, preserve history, then make one shared-record write."""
    from audit import save, now
    from attribution import (fingerprint, decision_digest, disposition_errors,
                             structural_errors, build_vulnerability_view, comparison_errors, indexes)
    import uuid
    if not isinstance(payload, dict):
        raise ValueError('裁决必须是对象')
    allowed = {'base_sha256', 'by', 'root_causes', 'finding_dispositions',
               'retire_root_cause_ids', 'run_id', 'run_digest', 'resolutions', 'chains'}
    if set(payload) - allowed:
        raise ValueError('未知裁决字段：' + ', '.join(sorted(set(payload) - allowed)))
    if not payload.get('root_causes') and not payload.get('finding_dispositions') and not payload.get('retire_root_cause_ids') and not payload.get('chains'):
        raise ValueError('rootcause --apply needs nonempty decisions')
    content_hash = fingerprint(payload)
    commits = state.get('attribution_commits', [])
    if commits and commits[-1].get('payload_sha256') == content_hash and commits[-1].get('after_sha256') == digest(state):
        return dict(commits[-1]['result'], replayed=True)
    if payload.get('base_sha256') != digest(state):
        raise ValueError('Stale base_sha256: read current facts and reconcile affected decisions')
    if payload.get('run_id'):
        from rootcause_run import validate_submission
        validate_submission(workspace, state, payload)
    working = copy.deepcopy(state)
    source_maps = indexes(state)
    existing = {r['id']: r for r in working.get('root_causes', [])}
    retired = payload.get('retire_root_cause_ids', [])
    if not isinstance(retired, list) or any(rid not in existing for rid in retired):
        raise ValueError('retire_root_cause_ids 引用无效')
    history = working.setdefault('attribution_history', [])
    for rid in retired:
        history.append({'at': now(), 'record': copy.deepcopy(existing[rid])})
        existing[rid] = dict(existing[rid], status='retired')
    incoming = payload.get('root_causes', [])
    if not isinstance(incoming, list) or any(not isinstance(row, dict) for row in incoming):
        raise ValueError('root_causes 必须为对象数组')
    changed_ids = {row.get('id') for row in incoming}
    claimed = {fid: rid for rid, row in existing.items()
               if row.get('verdict') == 'merge' and row.get('status') != 'retired' and rid not in changed_ids
               for fid in row['finding_ids']}
    keys = {row['key'] for row in candidates(state)}
    problems, seen = [], set()
    for item in incoming:
        row = copy.deepcopy(item)
        row.setdefault('by', payload.get('by'))
        rid = row.get('id')
        if rid in seen:
            problems.append('重复裁决 ID：' + str(rid))
        seen.add(rid)
        problems += _row_problems(state, row, keys, claimed)
        if row.get('verdict') == 'merge':
            for fid in row.get('finding_ids', []): claimed.setdefault(fid, rid)
        # Legacy submissions remain historical leads. A final attribution batch must
        # provide the new member-level comparison and evidence contract.
        if 'finding_dispositions' in payload:
            evidence_ids = row.get('evidence_ids', [])
            known_evidence = {e['id'] for e in state.get('evidence', [])}
            if not isinstance(evidence_ids, list) or not evidence_ids or any(eid not in known_evidence for eid in evidence_ids):
                problems.append(str(rid) + ': 缺少或引用无效裁决证据')
            if row.get('verdict') == 'distinct':
                comparisons = row.get('comparisons', [])
                covered = set()
                for cmp in comparisons:
                    problems += comparison_errors(state, cmp, str(rid), 'distinct', source_maps)
                    covered.update(cmp.get('finding_ids', []))
                if not comparisons or covered != set(row.get('finding_ids', [])):
                    problems.append(str(rid) + ': distinct 比较必须覆盖全部成员')
            expected = decision_digest(state, row, source_maps)
            if row.get('source_digest') not in (None, expected):
                problems.append(str(rid) + ': 归因证据已过期')
            row['source_digest'] = expected
        if rid in existing:
            history.append({'at': now(), 'record': copy.deepcopy(existing[rid])})
        existing[rid] = row
    incoming_chains = payload.get('chains', [])
    if not isinstance(incoming_chains, list):
        raise ValueError('chains 必须为数组')
    chain_ids = {c['id'] for c in working.get('chains', [])}
    for chain in incoming_chains:
        cid = chain.get('id')
        if not isinstance(chain, dict) or not cid or cid in chain_ids:
            problems.append('链 ID 缺失或已存在：' + str(cid)); continue
        chain_ids.add(cid)
        if not str(chain.get('title', '')).strip():
            problems.append(str(cid) + ': 链缺少标题')
        if chain.get('entry_exposure') not in {'EXT', 'ADJ', 'INT'}:
            problems.append(str(cid) + ': entry_exposure 必须是 EXT/ADJ/INT')
        steps = chain.get('steps') or []
        if not isinstance(steps, list) or not steps:
            problems.append(str(cid) + ': 链缺少步骤')
        for step in steps:
            if not str(step.get('description', '')).strip():
                problems.append(str(cid) + ': 每跳需要衔接论证（step.description：谁触发、必要配置、为何能从上一跳到达）')
            refs = [step.get(k) for k in ('check_id', 'finding_id') if step.get(k)]
            if not refs:
                problems.append(str(cid) + ': 每跳须引用 confirmed 检查或 current 发现'); continue
            for kind_key, pool, ok in (('check_id', source_maps['checks'], lambda r: r.get('verdict') == 'confirmed' and r.get('status') == 'complete'),
                                       ('finding_id', source_maps['findings'], lambda r: r.get('status') == 'current')):
                rid = step.get(kind_key)
                if rid and (rid not in pool or not ok(pool[rid])):
                    problems.append(str(cid) + ': 跳引用无效或非 confirmed/current：' + str(rid))
        working.setdefault('chains', []).append(dict(chain, by=payload.get('by')))
        source_maps = indexes(working)
    dispositions = payload.get('finding_dispositions', [])
    if not isinstance(dispositions, list):
        raise ValueError('finding_dispositions 必须为数组')
    fseen = set()
    for item in dispositions:
        row = copy.deepcopy(item)
        row.setdefault('by', payload.get('by'))
        problems += disposition_errors(state, row, source_maps)
        fid = row.get('finding_id')
        if fid in fseen:
            problems.append(str(fid) + ': 同批处置重复')
        fseen.add(fid)
        expected = decision_digest(state, row, source_maps)
        if row.get('source_digest') not in (None, expected):
            problems.append(str(fid) + ': 处置来源已过期')
        row.update(id='FD-' + uuid.uuid4().hex[:12], source_digest=expected,
                   created_at=now(), run_id=payload.get('run_id'))
        working.setdefault('finding_dispositions', []).append(row)
    if problems:
        raise ValueError('；'.join(problems))
    working['root_causes'] = [existing[k] for k in sorted(existing)]
    from attribution import sync_root_cause_links
    owners = sync_root_cause_links(working)
    problems = structural_errors(working)
    view = build_vulnerability_view(working)
    pending = {r['finding_id']: r['reasons'] for r in view['pending']}
    for row in dispositions:
        if row['kind'] not in {'pending', 'superseded'} and row['finding_id'] in pending:
            problems.append(row['finding_id'] + ': ' + '；'.join(pending[row['finding_id']]))
        if row['kind'] == 'superseded' and any(x['finding_id'] == row['finding_id'] for x in view['historical_issues']):
            problems.append(row['finding_id'] + ': 替代关系尚未闭合')
    if problems:
        raise ValueError('；'.join(problems))
    result = {'applied': len(incoming), 'dispositions': len(dispositions),
              'root_causes': len(existing), 'replaced': sorted(changed_ids & {r['id'] for r in state.get('root_causes', [])}),
              'grouped_findings': len(owners), 'candidate_coverage': closure(working),
              'relinked': sorted(f['id'] for f in state['findings'] if f.get('root_cause_id') and f.get('root_cause_id') != owners.get(f['id'])),
              'attribution': view['statistics'], 'run_id': payload.get('run_id')}
    working.setdefault('attribution_commits', []).append({
        'id': 'AC-' + uuid.uuid4().hex[:12], 'run_id': payload.get('run_id'),
        'payload_sha256': content_hash, 'after_sha256': digest(working),
        'at': now(), 'result': result})
    save(workspace, working)
    state.clear(); state.update(working)
    return result


def file_groups(state):
    """Index every evidence file; groups overlap and imply no semantic equality."""
    from attribution import finding_packet
    evidence = {e['id']: e for e in state.get('evidence', [])}
    by_file = defaultdict(set)
    for finding in _current(state):
        ids = set(finding.get('evidence_ids', []))
        for point in finding.get('failure_points', []): ids.update(point.get('evidence_ids', []))
        for eid in ids:
            mid = evidence.get(eid, {}).get('material_id')
            if mid in state.get('materials', {}): by_file[mid].add(finding['id'])
    grouped = defaultdict(list)
    for mid, ids in by_file.items(): grouped[tuple(sorted(ids))].append(mid)
    seen = {fid for ids in grouped for fid in ids}
    for finding in _current(state):
        if finding['id'] not in seen: grouped[(finding['id'],)] = []
    return [{'finding_ids': list(ids), 'material_ids': sorted(mids)}
            for ids, mids in sorted(grouped.items())]


def file_candidates(state):
    from attribution import fingerprint
    output = []
    for group in file_groups(state):
        ids = group['finding_ids']
        if len(ids) < 2: continue
        output.append(dict(group, key='file:' + fingerprint(group)[:20],
                           units=_units_of(ids), strong=False,
                           basis=['共享材料，需按具体失效比较；不自动合并']))
    current = {f['id']: f for f in _current(state)}
    links = set()
    for fid, f in current.items():
        for rel in f.get('related_findings', []):
            other = rel.get('finding_id')
            if other in current and other != fid: links.add(tuple(sorted((fid, other))))
        mentioned = set(re.findall(r'(?<![A-Za-z0-9_-])(F-[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])', f.get('mechanism', '')))
        for other in mentioned & set(current) - {fid}:
            links.add(tuple(sorted((fid, other))))
    for todo in state.get('report_todos', []):
        ids = sorted(set(re.findall(r'(?<![A-Za-z0-9_-])(F-[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])', todo.get('instruction', ''))) & set(current))
        if len(ids) > 1: links.add(tuple(ids))
    by_hash = defaultdict(set)
    ev = {e['id']: e for e in state.get('evidence', [])}
    for fid, finding in current.items():
        for eid in finding.get('evidence_ids', []):
            material = state.get('materials', {}).get(ev.get(eid, {}).get('material_id'), {})
            if material.get('sha256'):
                by_hash[material['sha256']].add(fid)
    for sha, ids in sorted(by_hash.items()):
        if len(ids) > 1:
            output.append({'key': 'copy:' + sha, 'finding_ids': sorted(ids), 'units': _units_of(ids),
                           'strong': False, 'basis': ['材料内容相同，仅提示核查同源副本']})
    for cause in state.get('root_causes', []):
        ids = sorted(set(cause.get('finding_ids', [])) & set(current))
        if len(ids) > 1 and cause.get('status') != 'retired': links.add(tuple(ids))
    for ids in sorted(links):
        output.append({'key': 'link:' + fingerprint(ids)[:20], 'finding_ids': list(ids),
                       'units': _units_of(ids), 'strong': False, 'basis': ['显式发现关联或完整 ID 回指']})
    return output
