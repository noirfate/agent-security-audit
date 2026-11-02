"""Pure attribution validity, dependency bindings and the shared vulnerability view."""
import hashlib
import json
from collections import Counter

KINDS = {'defect', 'supplement', 'chain', 'summary', 'superseded', 'pending'}
SEVERITIES = ('critical', 'high', 'medium', 'low', 'informational')
RELATIONS = {'possible_same_defect', 'supplements', 'overlaps'}


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def indexes(state):
    result = {k: {r['id']: r for r in state.get(k, [])}
              for k in ('findings', 'checks', 'evidence', 'reviews', 'chains',
                        'report_todos', 'root_causes', 'controls', 'instances')}
    result['materials'] = state.get('materials', {})
    return result


def evidence_refs(value):
    out = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith('evidence_ids') and isinstance(item, list):
                out.update(x for x in item if isinstance(x, str))
            else:
                out.update(evidence_refs(item))
    elif isinstance(value, list):
        for item in value:
            out.update(evidence_refs(item))
    return out


def finding_packet(state, ids, maps=None):
    maps = maps or indexes(state)
    wanted = set(ids)
    findings = [{k: v for k, v in maps['findings'][fid].items()
                 if k not in {'root_cause_id', 'review_ids'}}
                for fid in sorted(wanted) if fid in maps['findings']]
    cids = {cid for f in findings for cid in f.get('check_ids', [])}
    checks = [maps['checks'][cid] for cid in sorted(cids) if cid in maps['checks']]
    reviews = [r for r in state.get('reviews', []) if r['finding_id'] in wanted]
    controls = sorted((r for r in state.get('controls', []) if cids & set(r.get('check_ids', []))), key=lambda r: r['id'])
    eids = evidence_refs(findings + checks + reviews + controls)
    evidence = [maps['evidence'][eid] for eid in sorted(eids) if eid in maps['evidence']]
    mids = {e.get('material_id') for e in evidence} - {None}
    return {'findings': findings, 'checks': checks, 'reviews': reviews,
            'controls': controls, 'evidence': evidence,
            'materials': {mid: maps['materials'].get(mid) for mid in sorted(mids)}}


def decision_finding_ids(row):
    ids = set(row.get('finding_ids', []))
    if row.get('finding_id'):
        ids.add(row['finding_id'])
    if row.get('target_finding_id'):
        ids.add(row['target_finding_id'])
    ids.update((row.get('comparison') or {}).get('finding_ids', []))
    for comparison in row.get('comparisons', []):
        ids.update(comparison.get('finding_ids', []))
    return ids


def decision_digest(state, row, maps=None):
    maps = maps or indexes(state)
    fids = decision_finding_ids(row)
    chain_checks = set()
    for cid in row.get('chain_ids', []):
        for step in maps['chains'].get(cid, {}).get('steps', []):
            if step.get('finding_id'): fids.add(step['finding_id'])
            if step.get('check_id'): chain_checks.add(step['check_id'])
    sources = maps.setdefault('_finding_sources', {})
    for fid in sorted(fids):
        if fid not in sources: sources[fid] = fingerprint(finding_packet(state, [fid], maps))
    packet = {'finding_sources': {fid: sources[fid] for fid in sorted(fids)}}
    packet['chain_checks'] = {cid: maps['checks'].get(cid) for cid in sorted(chain_checks)}
    packet['framework'] = state.get('framework')
    packet['targets'] = state.get('targets', [])
    packet['extra_evidence'] = {eid: maps['evidence'].get(eid)
                                for eid in sorted(evidence_refs(row))}
    comparisons = [row.get('comparison') or {}] + row.get('comparisons', [])
    mids = {mid for c in comparisons for mid in c.get('material_ids', [])}
    packet['extra_materials'] = {mid: maps['materials'].get(mid) for mid in sorted(mids)}
    for category, key in (('chains', 'chain_ids'), ('report_todos', 'todo_ids')):
        packet[category] = {}
        for rid in sorted(row.get(key, [])):
            value = maps[category].get(rid)
            # Completing presentation must not stale its semantic attribution.
            if category == 'report_todos' and isinstance(value, dict):
                value = {k: v for k, v in value.items() if k not in {'status', 'reason'}}
            packet[category][rid] = value
    packet['dependencies'] = [dependency_value(state, ref, maps)
                               for ref in row.get('read_dependencies', [])]
    return fingerprint(packet)


def dependency_value(state, ref, maps=None):
    maps = maps or indexes(state)
    category, rid = ref.get('category'), ref.get('id')
    if not isinstance(category, str) or category not in {'findings','checks','evidence','reviews','chains','report_todos','root_causes','controls','instances','materials'} or not isinstance(rid, str):
        return None
    if category == 'findings':
        return finding_packet(state, [rid], maps) if rid in maps['findings'] else None
    value = maps.get(category, {}).get(rid)
    if category == 'report_todos' and isinstance(value, dict):
        value = {k: v for k, v in value.items() if k not in {'status', 'reason'}}
    return value


def dependency_errors(state, refs, maps=None):
    if not isinstance(refs, list):
        return ['read_dependencies 必须为数组']
    errors = []
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append('read_dependencies 条目必须为对象'); continue
        value = dependency_value(state, ref, maps)
        if value is None or ref.get('sha256') != fingerprint(value):
            errors.append('依赖已变或不存在：%s/%s' % (ref.get('category'), ref.get('id')))
    return errors


def fact_errors(state, finding, maps=None):
    from review import latest_review, subject_digest, evidence_digest
    maps = maps or indexes(state)
    errors = []
    if finding.get('status') != 'current':
        return ['发现不是 current']
    review = latest_review(state, finding)
    if not review or review.get('decision') != 'retain':
        return ['没有有效 retain 复核']
    if review.get('subject_sha256') != subject_digest(state, finding):
        errors.append('事实复核已过期')
    ids = review.get('evidence_ids', []) + review.get('counterevidence_ids', [])
    if review.get('evidence_sha256') != evidence_digest(state, ids):
        errors.append('复核证据已改变')
    used = [maps['checks'].get(cid, {}) for cid in finding.get('check_ids', [])]
    for eid in set(ids) | evidence_refs(finding) | evidence_refs(used):
        ev = maps['evidence'].get(eid, {})
        if ev.get('status') != 'current':
            errors.append('证据失效：' + eid)
        mid = ev.get('material_id')
        if mid and (maps['materials'].get(mid, {}).get('status') != 'present'
                    or ev.get('sha256') != maps['materials'].get(mid, {}).get('sha256')):
            errors.append('材料已改变：' + str(mid))
    for cid in finding.get('check_ids', []):
        c = maps['checks'].get(cid, {})
        if c.get('status') != 'complete' or c.get('verdict') != 'confirmed':
            errors.append('检查不再成立：' + cid)
    return errors


def finding_extension_errors(state, rows=None):
    maps = indexes(state)
    errors = []
    for finding in state.get('findings', []) if rows is None else rows:
        fid = finding.get('id', '?')
        points = finding.get('failure_points', [])
        relations = finding.get('related_findings', [])
        if not isinstance(points, list) or not isinstance(relations, list):
            errors.append(fid + ': failure_points/related_findings 必须为数组'); continue
        for point in points:
            if not isinstance(point, dict) or set(point) - {'evidence_ids', 'symbol', 'expected_control', 'observed_failure'}:
                errors.append(fid + ': 非法 failure_points'); continue
            for key in ('expected_control', 'observed_failure'):
                if not isinstance(point.get(key), str) or not point[key].strip():
                    errors.append(fid + ': failure_points 缺少 ' + key)
            if not point.get('evidence_ids') or any(e not in maps['evidence'] for e in point['evidence_ids']):
                errors.append(fid + ': failure_points 必须引用实际证据')
        for rel in relations:
            if not isinstance(rel, dict) or set(rel) - {'finding_id', 'relation', 'reason', 'evidence_ids'}:
                errors.append(fid + ': 非法 related_findings'); continue
            if rel.get('finding_id') not in maps['findings'] or rel.get('finding_id') == fid:
                errors.append(fid + ': related_findings 目标不存在或指向自身')
            if rel.get('relation') not in RELATIONS or not str(rel.get('reason', '')).strip():
                errors.append(fid + ': related_findings 缺少关系或理由')
            if not rel.get('evidence_ids') or any(e not in maps['evidence'] for e in rel['evidence_ids']):
                errors.append(fid + ': related_findings 缺少证据')
    return errors


def comparison_errors(state, comparison, owner, conclusion=None, maps=None):
    maps = maps or indexes(state)
    if not isinstance(comparison, dict):
        return [owner + ': 缺少 comparison 比较记录']
    errors = []
    for key in ('by', 'scope', 'reason'):
        if not isinstance(comparison.get(key), str) or not comparison[key].strip():
            errors.append(owner + ': comparison 缺少 ' + key)
    if comparison.get('conclusion') not in ({conclusion} if conclusion else {'standalone', 'grouped', 'distinct'}):
        errors.append(owner + ': comparison 结论无效')
    if not any(comparison.get(key) for key in ('finding_ids', 'evidence_ids', 'material_ids')):
        errors.append(owner + ': comparison 没有实际比较对象')
    for key, category in (('finding_ids', 'findings'), ('evidence_ids', 'evidence'), ('material_ids', 'materials')):
        ids = comparison.get(key, [])
        if not isinstance(ids, list) or any(not isinstance(rid, str) or rid not in maps[category] for rid in ids):
            errors.append(owner + ': comparison 引用无效 ' + key)
    return errors


def disposition_errors(state, row, maps=None):
    if not isinstance(row, dict):
        return ['处置必须为对象']
    maps = maps or indexes(state)
    fid, kind = row.get('finding_id'), row.get('kind')
    errors = []
    if fid not in maps['findings']:
        errors.append(str(fid) + ': 处置指向未知发现')
    if kind not in KINDS:
        errors.append(str(fid) + ': 处置 kind 无效')
    for key in ('by', 'reason'):
        if not isinstance(row.get(key), str) or not row[key].strip():
            errors.append(str(fid) + ': 处置缺少 ' + key)
    for key, category in (('finding_ids', 'findings'), ('chain_ids', 'chains'), ('todo_ids', 'report_todos'), ('evidence_ids', 'evidence')):
        ids = row.get(key, [])
        if not isinstance(ids, list) or any(not isinstance(rid, str) or rid not in maps[category] for rid in ids):
            errors.append(str(fid) + ': 处置引用无效 ' + key)
    if kind == 'defect':
        errors += comparison_errors(state, row.get('comparison'), str(fid), maps=maps)
        if (row.get('comparison') or {}).get('conclusion') not in {'standalone', 'grouped'}:
            errors.append(str(fid) + ': defect 需要 standalone/grouped 比较')
    elif kind == 'supplement':
        if row.get('target_finding_id') not in maps['findings'] or row.get('target_finding_id') == fid:
            errors.append(str(fid) + ': supplement 必须直接指向另一条发现')
    elif kind in {'chain', 'summary', 'superseded'}:
        if kind == 'superseded' and maps['findings'].get(fid, {}).get('status') != 'withdrawn':
            errors.append(str(fid) + ': superseded 只用于 withdrawn 历史发现')
        if not row.get('finding_ids') or fid in row.get('finding_ids', []):
            errors.append(str(fid) + ': 缺少有效组成/替代发现')
        if kind == 'chain' and not row.get('chain_ids'):
            errors.append(str(fid) + ': chain 缺少 chains 引用')
        if kind == 'summary' and not row.get('todo_ids'):
            errors.append(str(fid) + ': summary 缺少呈现待办')
    return errors


def sync_root_cause_links(state):
    """Back-links are derived bookkeeping; unit products cannot assign ownership."""
    owners = {}
    for row in state.get('root_causes', []):
        if row.get('verdict') != 'merge' or row.get('status') == 'retired': continue
        for fid in row['finding_ids']:
            if fid in owners: raise ValueError(fid + ': 同一发现被多个根因领取')
            owners[fid] = row['id']
    for finding in state.get('findings', []):
        if finding['id'] in owners or 'root_cause_id' in finding:
            finding['root_cause_id'] = owners.get(finding['id'])
    return owners


def latest_dispositions(state):
    return {r['finding_id']: r for r in state.get('finding_dispositions', [])}


def relation_cycles(rows):
    graph = {}
    for fid, row in rows.items():
        graph[fid] = ([row['target_finding_id']] if row.get('kind') == 'supplement' and row.get('target_finding_id') else
                      list(row.get('finding_ids', [])) if row.get('kind') in {'chain', 'summary', 'superseded'} else [])
    done, cyclic = set(), set()
    for start in graph:
        if start in done: continue
        path, active = [start], {start: 0}
        stack = [(start, iter(graph[start]))]
        while stack:
            node, edges = stack[-1]
            target = next(edges, None)
            if target is None:
                done.add(node); stack.pop(); active.pop(node); path.pop()
            elif target in active:
                cyclic.update(path[active[target]:])
            elif target in graph and target not in done:
                active[target] = len(path); path.append(target); stack.append((target, iter(graph[target])))
    return cyclic


def structural_errors(state):
    errors = finding_extension_errors(state)
    maps = indexes(state)
    seen = set()
    for row in state.get('finding_dispositions', []):
        errors += disposition_errors(state, row, maps)
        if not row.get('id') or row['id'] in seen:
            errors.append('处置历史 ID 缺失或重复：' + str(row.get('id')))
        seen.add(row.get('id'))
        if not row.get('source_digest'):
            errors.append(str(row.get('id')) + ': 处置缺少来源指纹')
    for fid in relation_cycles(latest_dispositions(state)):
        errors.append(fid + ': 处置关联存在循环')
    return errors


def build_vulnerability_view(state):
    """Derive effective results only; stale decisions stay in the historical ledger."""
    maps = indexes(state)
    current = {fid: f for fid, f in maps['findings'].items() if f.get('status') == 'current'}
    latest = latest_dispositions(state)
    pending, active, historical = {}, {}, []
    def fail(fid, message):
        pending.setdefault(fid, []).append(message)
    for fid, finding in current.items():
        row = latest.get(fid)
        problems = fact_errors(state, finding, maps)
        if not row:
            problems.append('缺少归因处置')
        else:
            problems += disposition_errors(state, row, maps)
            if row.get('source_digest') != decision_digest(state, row, maps):
                problems.append('归因来源已过期，需要重新比较')
            problems += dependency_errors(state, row.get('read_dependencies', []), maps)
            if row.get('kind') in {'pending', 'superseded'}:
                problems.append('归因待定：' + row['reason'] if row.get('kind') == 'pending' else '当前发现尚未完成替代')
        if problems:
            pending[fid] = problems
        else:
            active[fid] = row
    for fid in relation_cycles(latest):
        if fid in current: fail(fid, '处置关联存在循环')
    groups, owners = [], {}
    for cause in state.get('root_causes', []):
        if cause.get('status') == 'retired' or cause.get('verdict') != 'merge':
            continue
        members = cause.get('finding_ids', [])
        live = set(members) & set(current)
        if not live:
            continue
        problems = []
        if cause.get('source_digest') != decision_digest(state, cause, maps):
            problems.append('同源裁决已过期或尚未按当前契约核对：' + cause['id'])
        if len(members) < 2 or any(fid not in active or active[fid]['kind'] != 'defect' for fid in members):
            problems.append('同源组的成员不是全部有效 defect：' + cause['id'])
        if problems:
            for fid in live:
                for problem in problems: fail(fid, problem)
            continue
        groups.append({'id': cause['id'], 'root_cause_id': cause['id'], 'finding_ids': sorted(members)})
        for fid in members:
            if fid in owners:
                fail(fid, '同一发现被多个同源组领取')
            owners.setdefault(fid, []).append(cause['id'])
    for fid, row in active.items():
        if row['kind'] == 'defect':
            grouped = fid in owners
            conclusion = row['comparison']['conclusion']
            if grouped != (conclusion == 'grouped'):
                fail(fid, '单例/归组比较与实际归属不一致')
        elif row['kind'] == 'supplement':
            target = row['target_finding_id']
            if target not in active or active[target]['kind'] != 'defect':
                fail(fid, '补充目标必须为有效 defect，不能沿补充指针传递')
        elif row['kind'] in {'chain', 'summary'}:
            if any(target == fid or (target in active and fid in active[target].get('finding_ids', [])) for target in row['finding_ids']):
                fail(fid, '组成关系存在循环，需要重新核对')
            if any(target not in current for target in row['finding_ids']):
                fail(fid, '组成发现已撤回或尚未事实复核')
    # A standalone label is insufficient while a known comparison is unanswered.
    # Compare component representatives, retaining every member's source binding.
    from rootcause import candidates
    distinct = [r for r in state.get('root_causes', []) if r.get('verdict') == 'distinct'
                and r.get('status') != 'retired' and r.get('source_digest') == decision_digest(state, r, maps)]
    for candidate in candidates(state):
        members = [fid for fid in candidate['finding_ids'] if fid in active and active[fid]['kind'] == 'defect']
        partitions = {}
        for fid in members:
            key = tuple(owners.get(fid, [fid]))
            partitions.setdefault(key, set()).add(fid)
        if len(partitions) < 2: continue
        for group, fids in partitions.items():
            compared = set()
            for fid in fids: compared.update(active[fid]['comparison'].get('finding_ids', []))
            for row in distinct:
                if fids & set(row['finding_ids']): compared.update(row['finding_ids'])
            missing = [sorted(peers) for other, peers in partitions.items()
                       if other != group and not peers & compared]
            if missing:
                for fid in fids: fail(fid, '已知候选尚无具体比较：' + candidate['key'])
    # A failing member/target invalidates its dependent presentation, never its facts.
    changed = True
    while changed:
        before = sum(len(v) for v in pending.values())
        for group in groups:
            if any(fid in pending for fid in group['finding_ids']):
                for fid in group['finding_ids']:
                    if fid not in pending: fail(fid, '同源组的其他成员尚未闭合')
        for fid, row in active.items():
            targets = ([row['target_finding_id']] if row['kind'] == 'supplement' else
                       row.get('finding_ids', []) if row['kind'] in {'chain', 'summary'} else [])
            if fid not in pending and any(target in pending for target in targets):
                fail(fid, '关联发现归因尚未闭合')
        changed = sum(len(v) for v in pending.values()) != before
    vulnerabilities = [g for g in groups if not any(fid in pending for fid in g['finding_ids'])]
    for fid, row in active.items():
        if row['kind'] == 'defect' and fid not in pending and fid not in owners:
            vulnerabilities.append({'id': fid, 'root_cause_id': None, 'finding_ids': [fid]})
    mapping = {}
    for vuln in vulnerabilities:
        for fid in vuln['finding_ids']:
            mapping[fid] = {'kind': 'defect', 'vulnerability_id': vuln['id'],
                            'path': 'vulnerabilities/' + vuln['id'] + '.md#' + fid}
    for fid, row in active.items():
        if fid in pending: continue
        if row['kind'] == 'supplement':
            target = mapping.get(row['target_finding_id'])
            if not target:
                fail(fid, '补充目标没有有效漏洞'); continue
            vuln = next(v for v in vulnerabilities if v['id'] == target['vulnerability_id'])
            vuln['finding_ids'].append(fid)
            mapping[fid] = {'kind': 'supplement', 'vulnerability_id': vuln['id'],
                            'path': 'vulnerabilities/' + vuln['id'] + '.md#' + fid}
        elif row['kind'] in {'chain', 'summary'}:
            mapping[fid] = {'kind': row['kind'], 'vulnerability_id': None,
                            'path': 'summary.md#' + fid, 'chain_ids': row.get('chain_ids', []),
                            'todo_ids': row.get('todo_ids', [])}
    for fid in pending:
        mapping[fid] = {'kind': 'pending', 'vulnerability_id': None, 'path': 'summary.md#' + fid}
    for fid, row in latest.items():
        if fid in current or row.get('kind') != 'superseded': continue
        if (maps['findings'].get(fid, {}).get('status') != 'withdrawn'
                or row.get('source_digest') != decision_digest(state, row, maps)
                or any(target not in mapping or target in pending for target in row.get('finding_ids', []))):
            historical.append({'finding_id': fid, 'reason': '历史替代关系失效，修复映射或按事实复核恢复；不自动复活'})
    for vuln in vulnerabilities:
        vuln['finding_ids'] = sorted(vuln['finding_ids'])
        best = min((current[fid] for fid in vuln['finding_ids']), key=lambda f: SEVERITIES.index(f['severity']))
        vuln['severity'] = best['severity']
        vuln['severity_finding_id'] = best['id']
        vuln['exposures'] = sorted({current[fid].get('exposure') or 'unknown' for fid in vuln['finding_ids']})
    kinds = Counter(row['kind'] for fid, row in active.items() if fid not in pending)
    return {'vulnerabilities': sorted(vulnerabilities, key=lambda v: (SEVERITIES.index(v['severity']), v['id'])),
            'finding_map': mapping, 'pending': [{'finding_id': fid, 'reasons': sorted(set(reasons))}
                                               for fid, reasons in sorted(pending.items())],
            'historical_issues': historical,
            'statistics': {'current_findings': len(current), 'independent_vulnerabilities': len(vulnerabilities),
                           'high_vulnerabilities': sum(v['severity'] in {'critical', 'high'} for v in vulnerabilities),
                           'supplements': kinds['supplement'], 'chains': kinds['chain'], 'summaries': kinds['summary'],
                           'pending_findings': len(pending), 'report_tasks': len(vulnerabilities),
                           'attribution_complete': not pending}}
