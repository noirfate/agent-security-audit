"""Bind model-authored reading groups to the single effective attribution view.

This module never decides that findings share a defect and never writes prose.
Report membership, independent defect identity and evidence references have
different cardinalities; only the attribution view owns defect identity.
"""
from collections import Counter
from copy import deepcopy
import re

from attribution import (build_vulnerability_view, evidence_refs, finding_packet,
                         fingerprint, indexes, latest_dispositions)

IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\Z')
PLAN_KEYS = {'version', 'groups', 'scenarios', 'chain_placements', 'source_digest'}
GROUP_KEYS = {'id', 'title', 'framework_object_ids', 'vulnerability_ids',
              'grouping_reason', 'source_digest'}
SCENARIO_KEYS = {'id', 'title', 'chain_ids', 'vulnerability_ids',
                 'grouping_reason', 'source_digest'}
PLACEMENT_KEYS = {'chain_id', 'kind', 'target_id', 'reason', 'source_digest'}
# A group is one report, so this is how many separate defects a developer has to wade
# through on one page. Routes of a single control defect share an identity and count
# once, so the cap only bites when a group collects distinct defects. Measured: a
# 12-identity group produced a report nobody could navigate; the run whose groups topped
# out at 6 produced four that passed every rule.
MAX_GROUP_IDENTITIES = 6


def _ids(value, label):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise ValueError(label + ' 必须为非空字符串数组')
    if len(set(value)) != len(value):
        raise ValueError(label + ' 不得含重复成员')
    return value


def finding_objects(state, finding_ids):
    maps = indexes(state)
    result = set()
    for fid in finding_ids:
        f = maps['findings'].get(fid, {})
        for cid in f.get('check_ids', []):
            c = maps['checks'].get(cid, {})
            mode = c.get('failure_mode_id')
            if isinstance(mode, str) and mode.startswith('FM-'):
                result.add(mode[3:].rsplit('-', 1)[0])
            for iid in c.get('instance_ids', []):
                result.update(maps['instances'].get(iid, {}).get('framework_object_ids', []))
    return sorted(result)


def related_chains(state, finding_ids):
    fids = set(finding_ids)
    checks = {cid for f in state.get('findings', []) if f['id'] in fids
              for cid in f.get('check_ids', [])}
    return sorted((c for c in state.get('chains', [])
                   if any(s.get('finding_id') in fids or s.get('check_id') in checks
                          for s in c.get('steps', []))), key=lambda c: c['id'])


def chain_findings(state, chains):
    check_ids = {s['check_id'] for c in chains for s in c.get('steps', []) if s.get('check_id')}
    fids = {s['finding_id'] for c in chains for s in c.get('steps', []) if s.get('finding_id')}
    fids.update(f['id'] for f in state.get('findings', []) if check_ids & set(f.get('check_ids', [])))
    return sorted(fids)


def chain_dependencies(state, chains, maps=None):
    """A check-only hop still carries controls, evidence, material and scope."""
    maps = maps or indexes(state)
    cids = {s['check_id'] for c in chains for s in c.get('steps', []) if s.get('check_id')}
    checks = [maps['checks'].get(cid) for cid in sorted(cids)]
    controls = sorted((r for r in state.get('controls', []) if cids & set(r.get('check_ids', []))), key=lambda r: r['id'])
    eids = evidence_refs(checks + controls)
    evidence = [maps['evidence'].get(eid) for eid in sorted(eids)]
    mids = {e['material_id'] for e in evidence if e and e.get('material_id')}
    iids = {iid for c in checks if c for iid in c.get('instance_ids', [])}
    return {'checks': checks, 'controls': controls, 'evidence': evidence,
            'instances': {iid: maps['instances'].get(iid) for iid in sorted(iids)},
            'materials': {mid: maps['materials'].get(mid) for mid in sorted(mids)}}


def _topology(state, view):
    # No report_plan, its own digest, or presentation-completion bookkeeping.
    return fingerprint({'framework': state.get('framework'), 'targets': state.get('targets'),
                        'vulnerabilities': [{k: v[k] for k in ('id', 'finding_ids', 'severity')}
                                            for v in view['vulnerabilities']],
                        'finding_kinds': {fid: row['kind'] for fid, row in view['finding_map'].items()},
                        'chain_ids': sorted(c['id'] for c in state.get('chains', []))})


def _dependency_digest(state, fids, chains, maps):
    dispositions = latest_dispositions(state)
    direct = set(fids)
    all_fids = direct | set(chain_findings(state, chains))
    packet = finding_packet(state, all_fids, maps)
    packet.update(chains=chains, chain_sources=chain_dependencies(state, chains, maps),
                  dispositions={fid: dispositions.get(fid) for fid in sorted(all_fids)},
                  root_causes=[r for r in state.get('root_causes', [])
                               if all_fids & set(r.get('finding_ids', []))],
                  framework=state.get('framework'), targets=state.get('targets'))
    return fingerprint(packet)


def _normalize(state, plan, view, bind=False):
    if not isinstance(plan, dict) or set(plan) - PLAN_KEYS:
        raise ValueError('report_plan 必须是已定义字段组成的对象')
    if plan.get('version') != 1:
        raise ValueError('report_plan.version 必须为 1')
    out = deepcopy(plan)
    maps = indexes(state)
    vulns = {v['id']: v for v in view['vulnerabilities']}
    chains = {c['id']: c for c in state.get('chains', [])}
    for key in ('groups', 'scenarios', 'chain_placements'):
        if not isinstance(out.get(key), list):
            raise ValueError('report_plan.' + key + ' 必须为数组')
    used, gids, scene_ids, placed = [], set(), set(), set()
    def stamp(row, expected, label):
        if row.get('source_digest') not in (None, expected) or (not bind and row.get('source_digest') != expected):
            raise ValueError(label + ' 来源已变化，需要重新比较')
        row['source_digest'] = expected
    for g in out['groups']:
        if not isinstance(g, dict) or set(g) - GROUP_KEYS:
            raise ValueError('报告分组含未定义字段')
        gid = g.get('id')
        if not isinstance(gid, str) or not IDENTIFIER.fullmatch(gid) or gid in gids:
            raise ValueError('报告分组 ID 非法或重复')
        gids.add(gid)
        for k in ('title', 'grouping_reason'):
            if not isinstance(g.get(k), str) or not g[k].strip():
                raise ValueError(gid + ': 缺少 ' + k)
        vids = _ids(g.get('vulnerability_ids'), gid + '.vulnerability_ids')
        if not vids or set(vids) - set(vulns):
            raise ValueError(gid + ': 成员必须是当前有效独立缺陷')
        if len(vids) > MAX_GROUP_IDENTITIES:
            raise ValueError('%s: 一个报告组最多 %d 个独立身份，现有 %d 个；按失效实现拆成多个组'
                             % (gid, MAX_GROUP_IDENTITIES, len(vids)))
        used.extend(vids)
        fids = {fid for vid in vids for fid in vulns[vid]['finding_ids']}
        refs = _ids(g.get('framework_object_ids', []), gid + '.framework_object_ids')
        if set(refs) - set(finding_objects(state, fids)):
            raise ValueError(gid + ': 框架引用缺少成员依据')
        stamp(g, _dependency_digest(state, fids, related_chains(state, fids), maps), gid)
    if set(used) != set(vulns) or any(n != 1 for n in Counter(used).values()):
        raise ValueError('每个有效独立缺陷必须恰属一个主报告')
    for scene in out['scenarios']:
        if not isinstance(scene, dict) or set(scene) - SCENARIO_KEYS:
            raise ValueError('场景含未定义字段')
        sid = scene.get('id')
        if not isinstance(sid, str) or not IDENTIFIER.fullmatch(sid) or sid in scene_ids:
            raise ValueError('场景 ID 非法或重复')
        scene_ids.add(sid)
        for k in ('title', 'grouping_reason'):
            if not isinstance(scene.get(k), str) or not scene[k].strip():
                raise ValueError(sid + ': 缺少 ' + k)
        cids = _ids(scene.get('chain_ids'), sid + '.chain_ids')
        vids = _ids(scene.get('vulnerability_ids'), sid + '.vulnerability_ids')
        if not cids or set(cids) - set(chains) or set(cids) & placed:
            raise ValueError(sid + ': 链不存在或重复主归属')
        if set(vids) - set(vulns):
            raise ValueError(sid + ': 独立缺陷引用失效')
        placed.update(cids)
        fids = {fid for vid in vids for fid in vulns[vid]['finding_ids']}
        stamp(scene, _dependency_digest(state, fids, [chains[c] for c in cids], maps), sid)
    for row in out['chain_placements']:
        if not isinstance(row, dict) or set(row) - PLACEMENT_KEYS:
            raise ValueError('链去向含未定义字段')
        cid = row.get('chain_id')
        if cid not in chains or cid in placed:
            raise ValueError('链不存在或重复主归属：' + str(cid))
        placed.add(cid)
        if row.get('kind') not in {'report', 'boundary'} or not str(row.get('reason', '')).strip():
            raise ValueError(str(cid) + ': 链去向需要 report/boundary 及理由')
        if row['kind'] == 'report' and row.get('target_id') not in gids:
            raise ValueError(str(cid) + ': 链报告目标不存在')
        if row['kind'] == 'boundary' and row.get('target_id') is not None:
            raise ValueError(str(cid) + ': boundary 位置由记录索引派生')
        stamp(row, _dependency_digest(state, [], [chains[cid]], maps), cid)
    if placed != set(chains):
        raise ValueError('全部 chains 必须有且仅有一个主呈现去向')
    stamp(out, _topology(state, view), 'report_plan')
    return out


def bind_plan(state, plan, view=None):
    return _normalize(state, plan, view or build_vulnerability_view(state), bind=True)


def validate_proposal(state, proposal):
    """Check a partial task return; only a global apply may establish coverage."""
    if not isinstance(proposal, dict) or set(proposal) - PLAN_KEYS or proposal.get('version') != 1:
        raise ValueError('报告组织提案格式无效')
    view = build_vulnerability_view(state)
    valid = {v['id'] for v in view['vulnerabilities']}
    chains = {c['id'] for c in state.get('chains', [])}
    for name, keys in (('groups', GROUP_KEYS), ('scenarios', SCENARIO_KEYS)):
        rows = proposal.get(name, [])
        if not isinstance(rows, list):
            raise ValueError(name + ' 必须为数组')
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) - keys:
                raise ValueError(name + ' 提案字段无效')
            rid = row.get('id')
            if not isinstance(rid, str) or not IDENTIFIER.fullmatch(rid) or rid in seen:
                raise ValueError(name + ' 提案 ID 无效或重复')
            seen.add(rid)
            if not str(row.get('title', '')).strip() or not str(row.get('grouping_reason', '')).strip():
                raise ValueError(rid + ': 提案缺少标题或理由')
            vids = _ids(row.get('vulnerability_ids'), rid)
            if set(vids) - valid or (name == 'groups' and not vids):
                raise ValueError(rid + ': 引用失效独立缺陷')
            if name == 'groups' and len(vids) > MAX_GROUP_IDENTITIES:
                raise ValueError('%s: 一个报告组最多 %d 个独立身份，现有 %d 个；按失效实现拆成多个组'
                                 % (rid, MAX_GROUP_IDENTITIES, len(vids)))
            if name == 'scenarios':
                cids = _ids(row.get('chain_ids'), rid)
                if not cids or set(cids) - chains:
                    raise ValueError(rid + ': 引用未知链')
            else:
                _ids(row.get('framework_object_ids', []), rid)
    placements = proposal.get('chain_placements', [])
    if not isinstance(placements, list):
        raise ValueError('chain_placements 必须为数组')
    for row in placements:
        if (not isinstance(row, dict) or set(row) - PLACEMENT_KEYS or row.get('chain_id') not in chains
                or row.get('kind') not in {'report', 'boundary'} or not str(row.get('reason', '')).strip()):
            raise ValueError('链去向提案无效')


def plan_errors(state, view=None):
    view = view or build_vulnerability_view(state)
    if state.get('report_plan') is None:
        return ['缺少报告组织计划'] if view['vulnerabilities'] or state.get('chains') else []
    try:
        _normalize(state, state['report_plan'], view)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return [str(exc)]
    return []


def build_report_view(state, locations=None, attribution=None):
    view = attribution or build_vulnerability_view(state)
    errors = plan_errors(state, view)
    plan = state.get('report_plan') or {'groups': [], 'scenarios': [], 'chain_placements': []}
    if errors:
        return {'errors': errors, 'groups': [], 'finding_map': {}, 'scenarios': [],
                'chain_locations': {}, 'high_vulnerabilities': [], 'pending': view['pending'],
                'statistics': {**view['statistics'], 'report_tasks': 0}}
    vulns = {v['id']: v for v in view['vulnerabilities']}
    findings = {f['id']: f for f in state.get('findings', [])}
    dispositions = latest_dispositions(state)
    groups, mapping, owner = [], {}, {}
    for row in plan['groups']:
        vids = row['vulnerability_ids']
        fids = sorted({fid for vid in vids for fid in vulns[vid]['finding_ids']})
        causes = sorted({vulns[vid]['root_cause_id'] for vid in vids if vulns[vid]['root_cause_id']})
        group = dict(row, finding_ids=fids, root_cause_ids=causes,
                     root_cause_id=causes[0] if len(vids) == 1 and len(causes) == 1 else None,
                     path='vulnerabilities/' + row['id'] + '.md')
        groups.append(group)
        for vid in vids:
            owner[vid] = row['id']
            for fid in vulns[vid]['finding_ids']:
                mapping[fid] = dict(view['finding_map'][fid], report_id=row['id'], path=group['path'] + '#' + fid)
    for fid, row in view['finding_map'].items():
        if fid in mapping:
            continue
        category = 'finding_dispositions' if fid in dispositions else 'findings'
        rid = dispositions[fid]['id'] if fid in dispositions else fid
        path = (locations or {}).get(category, {}).get(rid)
        if findings[fid]['severity'] in {'critical', 'high'}:
            path = 'summary.md#' + fid
        mapping[fid] = dict(row, path=path, record_ref={'category': category, 'id': rid})
    placements = {}
    for scene in plan['scenarios']:
        for cid in scene['chain_ids']:
            placements[cid] = {'kind': 'scenario', 'target_id': scene['id'], 'path': 'summary.md#' + scene['id']}
    for row in plan['chain_placements']:
        cid = row['chain_id']
        placements[cid] = dict(row, path=('vulnerabilities/' + row['target_id'] + '.md#' + cid
                              if row['kind'] == 'report' else (locations or {}).get('chains', {}).get(cid)))
    high = [dict(v, report_id=owner[v['id']]) for v in view['vulnerabilities'] if v['severity'] in {'critical', 'high'}]
    return {'errors': [], 'groups': groups, 'finding_map': mapping, 'scenarios': plan['scenarios'],
            'chain_locations': placements, 'high_vulnerabilities': high, 'pending': view['pending'],
            'statistics': {**view['statistics'], 'report_tasks': len(groups)}}
