"""Isolated, resumable attribution jobs. Workers write proposals, never audit.json."""
import copy
import json
import re
import uuid
from pathlib import Path

from attribution import (fingerprint, finding_packet, indexes, dependency_errors,
                         decision_digest, KINDS, evidence_refs)

ACTIVE = {'dispatched', 'running'}


def safe_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', value):
        raise ValueError('不安全的运行或任务 ID')
    return value


def inside(root, relative):
    root = Path(root)
    path = root / relative
    if Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('运行路径必须在本运行目录内')
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('运行路径不允许符号链接')
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('运行路径越界')
    return path


def run_dir(workspace, run_id):
    return inside(workspace, 'units/_reviews/rootcause/' + safe_id(run_id))


def load(workspace, run_id):
    from knowledge import read
    root = run_dir(workspace, run_id)
    manifest = read(inside(root, 'manifest.json'))
    source = read(inside(root, 'source.json'))
    if manifest.get('run_id') != run_id or manifest.get('source_sha256') != fingerprint(source):
        raise ValueError('归因运行基线被修改')
    return root, manifest, source


def packet(state, ids, groups=None, candidate_rows=None, maps=None, kind='analysis', instructions=None):
    from rootcause import candidates
    from report_plan import related_chains, chain_dependencies
    from attribution import latest_dispositions, build_vulnerability_view
    maps = maps or indexes(state)
    facts = finding_packet(state, ids, maps)
    selected = set(ids)
    facts.update(finding_ids=sorted(selected), file_groups=groups or [],
                 target_id=state['target_id'], targets=state.get('targets', []),
                 candidates=[r for r in (candidate_rows if candidate_rows is not None else candidates(state)) if selected & set(r['finding_ids'])],
                 root_causes=[r for r in state.get('root_causes', []) if selected & set(r.get('finding_ids', []))],
                 chains=related_chains(state, selected),
                 report_todos=[t for t in state.get('report_todos', [])
                               if selected & set(re.findall(r'(?<![A-Za-z0-9_-])(F-[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])', t.get('instruction', '')))])
    dispositions = latest_dispositions(state)
    facts['finding_dispositions'] = [dispositions[fid] for fid in sorted(selected) if fid in dispositions]
    if kind == 'report-organization':
        if '_attribution_view' not in maps:
            maps['_attribution_view'] = build_vulnerability_view(state)
        view = maps['_attribution_view']
        facts['effective_vulnerabilities'] = [v for v in view['vulnerabilities'] if selected & set(v['finding_ids'])]
        facts['attribution_pending'] = [r for r in view['pending'] if r['finding_id'] in selected]
        # report_plan is validated against every chain in the workspace, so a packet
        # filtered by owner findings cannot satisfy the contract it is asked to meet:
        # measured, 66 of 69 arrived and the reviewer had to read the record for the
        # rest before its plan would apply at all.
        facts['chains'] = list(state.get('chains', []))
    facts['chain_sources'] = chain_dependencies(state, facts['chains'], maps)
    facts['framework'] = state.get('framework')
    instance_ids = {iid for c in facts['checks'] for iid in c.get('instance_ids', [])}
    facts['instance_sources'] = {iid: next((r for r in state.get('instances', []) if r['id'] == iid), None) for iid in sorted(instance_ids)}
    if kind != 'analysis' or instructions:
        facts.update(kind=kind, instructions=instructions or '')
    return facts


def framework_task_plan(workspace, state, request=None, packet_bytes=160000):
    """Build a topic index first; ambiguous ownership is a model decision."""
    from knowledge import baseline_dir, load_bundle, objects
    from audit import write_json
    from rootcause import digest
    bundle, _, _ = load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))
    catalog = objects(bundle)
    topics = {row['id']: row['name'] for key in ('layers', 'domains') for row in bundle.get(key, [])}
    maps = indexes(state)
    rows = []
    for f in sorted(state.get('findings', []), key=lambda row: row['id']):
        if f.get('status') != 'current':
            continue
        object_ids, instance_ids = set(), set()
        for cid in f.get('check_ids', []):
            check = maps['checks'].get(cid, {})
            mode = bundle.get('failure_modes', {}).get(check.get('failure_mode_id'), {})
            if mode.get('object_id'):
                object_ids.add(mode['object_id'])
            instance_ids.update(check.get('instance_ids', []))
        for iid in instance_ids:
            object_ids.update(maps['instances'].get(iid, {}).get('framework_object_ids', []))
        candidates = sorted({oid.split('.')[0] for oid in object_ids if oid in catalog and oid.split('.')[0] in topics})
        rows.append({'finding_id': f['id'], 'title': f['title'],
                     'object_ids': sorted(object_ids), 'topic_candidates': candidates,
                     'instance_ids': sorted(instance_ids),
                     'instances': [maps['instances'][iid].get('name', iid) for iid in sorted(instance_ids) if iid in maps['instances']],
                     'mapping_gap': not candidates})
    base = fingerprint({'facts': digest(state),
                        **{key: sorted(state.get(key, []), key=lambda r: r['id'])
                           for key in ('instances', 'connections', 'assets', 'attackers')}})
    route_dir = Path(workspace) / 'units/_reviews/rootcause/routing'
    index_path = route_dir / (base + '.json')
    index_data = {'version': 1, 'base_sha256': base, 'topics': topics, 'findings': rows,
                  'source_path': str((Path(workspace) / 'audit.json').resolve()),
                  'instructions': '为每个发现选择一个主主题；其余主题仅作上下文。依据实际失效控制说明理由，不按第一项或编号排序决定。无法映射时用local并说明缺口。'}
    assignments = (request or {}).get('topic_assignments')
    if assignments is None:
        ambiguous = [r for r in rows if len(r['topic_candidates']) > 1]
        assignments = [{'finding_id': r['finding_id'],
                        'topic_id': r['topic_candidates'][0] if len(r['topic_candidates']) == 1 else 'local' if not r['topic_candidates'] else None,
                        'reason': '唯一已有对象主题' if len(r['topic_candidates']) == 1 else '框架映射缺口，需本地比较' if not r['topic_candidates'] else ''}
                       for r in rows]
        if ambiguous:
            write_json(index_path, {**index_data, 'topic_assignments': assignments})
            return {'routing_required': True, 'base_sha256': base,
                    'topic_index_path': str(index_path), 'unassigned_findings': [r['finding_id'] for r in ambiguous],
                    'next': '模型读取主题索引和必要源记录，另存补全topic_assignments的JSON，再用rootcause --prepare --input提交；不需要用户逐条选择。'}
    if request is not None and request.get('base_sha256') != base:
        raise ValueError('主题路由来源已变化，重新比较后提交')
    if not isinstance(assignments, list) or any(not isinstance(r, dict) for r in assignments):
        raise ValueError('topic_assignments 必须为对象数组')
    expected = {r['finding_id'] for r in rows}
    if sorted(r.get('finding_id', '') for r in assignments) != sorted(expected):
        raise ValueError('主题主归属必须完整且唯一')
    by_topic = {}
    for r in assignments:
        topic = r.get('topic_id')
        if topic not in topics and topic != 'local':
            raise ValueError('无效主主题：' + str(topic))
        if not isinstance(r.get('reason'), str) or not r['reason'].strip():
            raise ValueError('主题主归属缺少判断理由')
        by_topic.setdefault(topic, []).append(r['finding_id'])
    write_json(index_path, {**index_data, 'topic_assignments': assignments})
    tasks = []
    def make(topic, owner_ids):
        context = {r.get('finding_id') for fid in owner_ids
                    for r in maps['findings'][fid].get('related_findings', [])} & expected
        context -= set(owner_ids)
        return {'finding_ids': sorted(set(owner_ids) | context), 'owner_finding_ids': sorted(owner_ids),
                'context_finding_ids': sorted(context), 'topic_id': topic,
                'topic_index_path': str(index_path), 'reason': '在固定框架主题内比较具体失效，索引提供完整跨文件邻居'}
    for topic, ids in sorted(by_topic.items()):
        batch = []
        for fid in sorted(ids):
            proposed = batch + [fid]
            candidate = make(topic, proposed)
            size = len(json.dumps(finding_packet(state, candidate['finding_ids'], maps), ensure_ascii=False).encode())
            if batch and size > packet_bytes:
                tasks.append(make(topic, batch)); batch = []
            batch.append(fid)
        if batch:
            tasks.append(make(topic, batch))
    return {'mode': 'framework', 'tasks': tasks, 'topic_index_path': str(index_path)}


def prepare(workspace, state, run_id=None, task_plan=None, packet_bytes=160000):
    from audit import write_json, now
    from rootcause import digest, file_groups
    if packet_bytes < 1:
        raise ValueError('packet-bytes 必须为正数')
    run_id = run_id or 'RUN-' + uuid.uuid4().hex[:12]
    root = run_dir(workspace, run_id)
    if root.exists():
        _, manifest, _ = load(workspace, run_id)
        if manifest['base_sha256'] != digest(state):
            raise ValueError('已有 run 来源不同；保留旧运行并创建新运行')
        return status(workspace, state, run_id)
    if task_plan is None or 'topic_assignments' in task_plan:
        task_plan = framework_task_plan(workspace, state, task_plan, packet_bytes)
        if task_plan.get('routing_required'):
            return task_plan
    groups = file_groups(state)
    from rootcause import candidates
    candidate_rows, maps = candidates(state), indexes(state)
    def make(ids, groups=None, kind='analysis', instructions=None):
        return packet(state, ids, groups, candidate_rows, maps, kind=kind, instructions=instructions)
    tasks = []
    if task_plan is not None:
        if not isinstance(task_plan, dict) or not isinstance(task_plan.get('tasks'), list):
            raise ValueError('任务计划需要 tasks 数组')
        for row in task_plan['tasks']:
            if not row.get('reason') or not row.get('finding_ids'):
                raise ValueError('自定义比较任务需要 finding_ids 和 reason')
            if row.get('kind') not in {None, 'analysis', 'reconciliation', 'synthesis-forward', 'synthesis-sink', 'synthesis-edges', 'report-organization'}:
                raise ValueError('未知归因任务类型')
            if row.get('kind') not in (None, 'analysis'):
                if not isinstance(row.get('instructions'), str) or not row['instructions'].strip():
                    raise ValueError('非 analysis 任务需要 instructions')
            data = make(row['finding_ids'], row.get('groups'), row.get('kind') or 'analysis', row.get('instructions'))
            # Normalise once, here: an explicit task plan names only finding_ids, so
            # owners is derived at plan-read time rather than re-derived on every read.
            owners = row.get('owner_finding_ids') or row['finding_ids']
            context = row.get('context_finding_ids', [])
            if (len(set(owners)) != len(owners) or len(set(context)) != len(context) or set(owners) & set(context)
                    or set(owners) | set(context) != set(row['finding_ids'])):
                raise ValueError('主处理成员与上下文必须为输入成员的互斥分区')
            data.update(owner_finding_ids=sorted(owners), context_finding_ids=sorted(context))
            for key in ('topic_id', 'topic_index_path'):
                if key in row: data[key] = row[key]
            tasks.append(data)
    else:
        current_groups, current_ids = [], set()
        for group in groups:
            ids = current_ids | set(group['finding_ids'])
            candidate = make(ids, current_groups + [group])
            if current_groups and len(json.dumps(candidate, ensure_ascii=False).encode()) > packet_bytes:
                tasks.append(make(current_ids, current_groups))
                current_groups, current_ids = [], set()
            current_groups.append(group); current_ids.update(group['finding_ids'])
        if current_groups:
            tasks.append(make(current_ids, current_groups))
    current = {f['id'] for f in state['findings'] if f['status'] == 'current'}
    covered = {fid for task in tasks for fid in task['finding_ids']}
    partial = bool(task_plan and task_plan.get('partial'))
    if not partial and covered != current:
        raise ValueError('任务必须覆盖全部 current finding 且无额外成员')
    if partial and not covered <= current:
        raise ValueError('partial 计划的成员也必须是 current finding')
    if task_plan and task_plan.get('mode') == 'framework':
        claimed = [fid for t in tasks for fid in t['owner_finding_ids']]
        if sorted(claimed) != sorted(current):
            raise ValueError('框架任务主成员必须完整且唯一')
    manifest = {'version': 2, 'run_id': run_id, 'created_at': now(), 'status': 'prepared',
                'source_sha256': fingerprint(state), 'base_sha256': digest(state),
                'finding_ids': sorted(current), 'tasks': {}, 'packet_bytes': packet_bytes,
                'global_report_todo_ids': [t['id'] for t in state.get('report_todos', [])
                                          if not current & set(re.findall(r'(?<![A-Za-z0-9_-])(F-[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])', t.get('instruction', '')))]}
    # Build in a sibling temporary directory, then publish the complete run.
    root.parent.mkdir(parents=True, exist_ok=True)
    staging = root.parent / ('.building-' + uuid.uuid4().hex)
    staging.mkdir()
    try:
        write_json(staging / 'source.json', state)
        for number, data in enumerate(tasks, 1):
            tid = 'T%04d' % number
            rel = 'tasks/' + tid + '/input.json'
            write_json(staging / rel, data)
            manifest['tasks'][tid] = {'id': tid, 'kind': data.get('kind', 'analysis'),
                                      'finding_ids': data['finding_ids'],
                                      'owner_finding_ids': data.get('owner_finding_ids') or data['finding_ids'],
                                      'protocol_version': 2,
                                      'input_path': rel, 'input_digest': fingerprint(data),
                                      'state': 'planned', 'attempts': [], 'selected_attempt': None}
            if partial:
                manifest['partial'] = True
        reuse_results(staging, root.parent, manifest, state)
        write_json(staging / 'manifest.json', manifest)
        staging.rename(root)
    except Exception:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return status(workspace, state, run_id)


def task_input(root, task):
    from knowledge import read
    data = read(inside(root, task['input_path']))
    if fingerprint(data) != task['input_digest']:
        raise ValueError(task['id'] + ': 输入包被修改')
    for ref in data.get('proposal_refs', []):
        from knowledge import read
        if fingerprint(read(inside(root, ref['path']))) != ref['sha256']:
            raise ValueError(task['id'] + ': 比较输入的临时建议已变化')
    return data


def stale_reasons(state, data, material_cache=None):
    expected = {k: data[k] for k in ('findings', 'checks', 'reviews', 'controls', 'evidence', 'materials')}
    actual = finding_packet(state, data['finding_ids'])
    reasons = []
    if fingerprint(actual) != fingerprint(expected): reasons.append('任务事实或复核已改变')
    # The input includes related groups and chain dependencies, not merely finding ids.
    selected = set(data['finding_ids'])
    causes = [r for r in state.get('root_causes', []) if selected & set(r.get('finding_ids', []))]
    if causes != data.get('root_causes', []): reasons.append('相关旧归因已改变')
    if 'finding_dispositions' in data:
        from attribution import latest_dispositions
        dispositions = latest_dispositions(state)
        if [dispositions[fid] for fid in sorted(selected) if fid in dispositions] != data['finding_dispositions']:
            reasons.append('相关归因处置已改变')
    if data.get('targets', []) != state.get('targets', []): reasons.append('目标位置或版本已改变')
    if 'framework' in data and data['framework'] != state.get('framework'): reasons.append('框架基线已改变')
    if 'instance_sources' in data:
        current_instances = {r['id']: r for r in state.get('instances', [])}
        if any(current_instances.get(iid) != row for iid, row in data['instance_sources'].items()): reasons.append('实例职责或对象映射已改变')
    from report_plan import related_chains
    actual_chains = (related_chains(state, selected) if 'framework' in data else
                     [c for c in state.get('chains', []) if any(s.get('finding_id') in selected for s in c.get('steps', []))])
    if actual_chains != data.get('chains', []): reasons.append('相关链及其条件已改变')
    if 'chain_sources' in data:
        from report_plan import chain_dependencies
        if chain_dependencies(state, actual_chains) != data['chain_sources']:
            reasons.append('链检查、反证或材料依赖已改变')
    from audit import material_path
    from knowledge import digest
    material_cache = {} if material_cache is None else material_cache
    source_materials = {**data.get('materials', {}), **data.get('chain_sources', {}).get('materials', {})}
    for mid, material in source_materials.items():
        if not material: continue
        key = (mid, material.get('sha256'))
        if key not in material_cache:
            try:
                material_cache[key] = digest(material_path(state, material)) == material.get('sha256')
            except (OSError, ValueError, KeyError): material_cache[key] = False
        if not material_cache[key]: reasons.append('源文件已变化或不可读：' + mid)
    return reasons


def status(workspace, state, run_id):
    root, manifest, source = load(workspace, run_id)
    rows, material_cache = [], {}
    for tid, task in sorted(manifest['tasks'].items()):
        data = task_input(root, task)
        stale = stale_reasons(state, data, material_cache)
        selected = next((a for a in task['attempts'] if a['n'] == task.get('selected_attempt')), None)
        if selected:
            try:
                from knowledge import read
                result = read(inside(root, selected['result_path']))
                if fingerprint(result) != selected.get('result_sha256'): stale.append('已接收结果被修改')
                stale += dependency_errors(state, result.get('read_dependencies', []))
            except (OSError, ValueError): stale.append('已接收结果不可读')
        rows.append({'task_id': tid, 'kind': task['kind'], 'state': task['state'],
                     'effective_state': 'stale' if stale else task['state'],
                     'finding_ids': task['finding_ids'], 'stale_reasons': stale,
                     'selected_attempt': task.get('selected_attempt')})
    current = {f['id'] for f in state['findings'] if f['status'] == 'current'}
    return {'run_id': run_id, 'path': str(root), 'status': manifest['status'],
            'base_sha256': manifest['base_sha256'], 'tasks': rows,
            'new_finding_ids': sorted(current - set(manifest['finding_ids'])),
            'removed_finding_ids': sorted(set(manifest['finding_ids']) - current),
            'in_flight': sum(t['state'] in ACTIVE for t in manifest['tasks'].values())}


def dispatch(workspace, state, run_id, task_id, capacity):
    from audit import write_json, now, dispatch_capacity
    from knowledge import SKILL
    root, manifest, source = load(workspace, run_id)
    task = manifest['tasks'].get(safe_id(task_id))
    if not task: raise ValueError('未知归因任务：' + task_id)
    if task['state'] in ACTIVE or task['state'] == 'returned':
        raise ValueError('任务已派出或已接收；不得重复启动')
    data = task_input(root, task)
    if stale_reasons(state, data): raise ValueError('输入已过期；先刷新比较输入')
    if not isinstance(capacity, dict) or not isinstance(capacity.get('active_agent_ids'), list):
        raise ValueError('派单需要宿主容量文件及 active_agent_ids，不能猜测占用')
    limit = capacity.get('limit', dispatch_capacity(state)['limit'])
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError('容量 limit 无效')
    ids = set(capacity['active_agent_ids'])
    reserved = 0
    # All attribution runs share the host limit. A returned task consumes no slot.
    for path in root.parent.glob('*/manifest.json'):
        from knowledge import read
        other = read(path)
        for item in other.get('tasks', {}).values():
            if item.get('state') not in ACTIVE: continue
            attempt = item['attempts'][-1]
            if attempt.get('agent_id'): ids.add(attempt['agent_id'])
            else: reserved += 1
    if len(ids) + reserved + 1 > limit:
        raise ValueError('宿主容量已满；等待在跑任务返回，不启动新代理')
    n = len(task['attempts']) + 1
    stem = 'synthesis' if task.get('kind') in {'synthesis-forward', 'synthesis-sink', 'synthesis-edges'} else 'result'
    rel = 'tasks/%s/%s-%d.json' % (task_id, stem, n)
    brief_rel = 'tasks/%s/brief-%d.md' % (task_id, n)
    role = SKILL / 'references/roles/rootcause_reviewer.md'
    prompt = ('# 归因任务\n\n读取角色契约：%s\n\n'
              '运行：%s；任务：%s；类型：%s；尝试：%d。\n\n'
              '输入：%s\n\n唯一结果文件：%s\n\n'
              'input_digest：%s\n\n审计工作区：%s\n\n'
              '只写本任务的临时 JSON；owner_finding_ids 逐条处置，context 仅供比较。'
              '事实订正交回主代理，不改共享记录，不运行 rootcause --apply。'
              '完成消息只回一行摘要及结果文件绝对路径。\n') % (
                  role.resolve(), run_id, task_id, task['kind'], n,
                  inside(root, task['input_path']).resolve(), inside(root, rel).resolve(),
                  task['input_digest'], Path(workspace).resolve())
    inside(root, brief_rel).write_text(prompt, encoding='utf-8')
    attempt = {'n': n, 'at': now(), 'state': 'dispatched', 'result_path': rel,
               'brief_path': brief_rel, 'agent_id': None}
    task['attempts'].append(attempt); task['state'] = 'dispatched'
    write_json(root / 'manifest.json', manifest)
    return {'run_id': run_id, 'task_id': task_id, 'attempt': n, 'state': 'dispatched',
            'prompt': prompt, 'prompt_path': str(root / brief_rel), 'result_path': str(root / rel)}


def validate_result(state, task, result, attempt, run_id):
    if not isinstance(result, dict): raise ValueError('结果必须为对象')
    kind = task.get('kind') or 'analysis'
    if kind not in {'analysis', 'reconciliation', 'synthesis-forward', 'synthesis-sink', 'synthesis-edges', 'report-organization'}:
        raise ValueError('未知归因任务类型：' + str(kind))
    if task.get('protocol_version', 1) >= 2:
        origin = attempt.get('origin', {})
        expected = {'run_id': origin.get('run_id', run_id), 'task_id': origin.get('task_id', task['id']),
                    'attempt': origin.get('attempt', attempt['n']), 'input_digest': task['input_digest']}
        if any(result.get(k) != v for k, v in expected.items()):
            raise ValueError('结果的任务、尝试或输入指纹不匹配')
    if kind == 'report-organization':
        from report_plan import validate_proposal
        allowed = {'run_id', 'task_id', 'attempt', 'input_digest', 'reviewer', 'report_plan', 'read_dependencies', 'fact_corrections', 'open_items'}
        if set(result) - allowed or not str(result.get('reviewer', '')).strip():
            raise ValueError('报告组织结果字段或reviewer无效')
        validate_proposal(state, result.get('report_plan'))
        problems = dependency_errors(state, result.get('read_dependencies', []))
        known = {f['id'] for f in state.get('findings', [])}
        for key in ('fact_corrections', 'open_items'):
            rows = result.get(key, [])
            if not isinstance(rows, list):
                problems.append(key + '必须为数组'); continue
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get('finding_ids'), list)
                        or not row['finding_ids'] or any(fid not in known for fid in row['finding_ids'])
                        or not str(row.get('reason', '')).strip()):
                    problems.append(key + '需要实际成员与理由')
        if problems: raise ValueError('；'.join(problems))
        return
    if kind in {'synthesis-forward', 'synthesis-sink', 'synthesis-edges'}:
        maps = indexes(state)
        problems = []
        proposals = result.get('proposals')
        if result.get('task_id') != task['id']:
            problems.append('synthesis 产物 task_id 不匹配')
        if not isinstance(proposals, list) or not proposals:
            problems.append('synthesis 产物需要非空 proposals')
        else:
            from rootcause import candidates as _unused  # noqa: F401（保持导入一致性）
            for pr in proposals:
                if not isinstance(pr, dict) or pr.get('outcome') not in ('chain', 'no_chain', 'edge', 'pending'):
                    problems.append('proposal 需要 outcome ∈ chain/no_chain/edge/pending'); continue
                if not str(pr.get('reason', pr.get('anchor', ''))).strip():
                    problems.append('proposal 需要 anchor 或 reason')
                chain = pr.get('chain') or {}
                steps = chain.get('steps') or []
                if pr.get('outcome') == 'chain' and not steps:
                    problems.append('chain 提案至少一跳（既有链亦存在合法单跳）')
                for st in steps:
                    if not str(st.get('description', '')).strip():
                        problems.append('每跳需要衔接论证 description')
                    ref = st.get('check_id') or st.get('finding_id')
                    if not ref:
                        problems.append('每跳须引用 confirmed 检查或 current 发现'); continue
                    if st.get('check_id') and not (st['check_id'] in maps['checks'] and maps['checks'][st['check_id']].get('verdict') == 'confirmed' and maps['checks'][st['check_id']].get('status') == 'complete'):
                        problems.append('跳引用非 confirmed 检查: ' + str(st.get('check_id')))
                    if st.get('finding_id') and maps['findings'].get(st.get('finding_id'), {}).get('status') != 'current':
                        problems.append('跳引用非 current 发现: ' + str(st.get('finding_id')))
        if problems: raise ValueError('；'.join(problems))
        return
    allowed = {'run_id','task_id','attempt','input_digest','reviewer','assessments',
               'group_proposals','comparisons','cross_file_leads','fact_corrections',
               'open_items','read_dependencies','resolutions'}
    if set(result) - allowed: raise ValueError('临时结果包含未定义字段')
    origin = attempt.get('origin', {})
    if any(result.get(k) != v for k, v in {'run_id': origin.get('run_id', run_id), 'task_id': origin.get('task_id', task['id']),
            'attempt': origin.get('attempt', attempt['n']), 'input_digest': task['input_digest']}.items()):
        raise ValueError('结果的任务、尝试或输入指纹不匹配')
    if not str(result.get('reviewer', '')).strip(): raise ValueError('缺少分析者')
    for key in allowed - {'run_id','task_id','attempt','input_digest','reviewer'}:
        if not isinstance(result.get(key, []), list): raise ValueError(key + ' 必须为数组')
    assessments = result.get('assessments', [])
    if (any(not isinstance(a, dict) for a in assessments)
            or sorted(a.get('finding_id', '') for a in assessments) != sorted(task['owner_finding_ids'])):
        raise ValueError('临时结果必须逐条覆盖任务 finding，不允许遗漏、重复或额外成员')
    maps = indexes(state)
    for kind in ('cross_file_leads', 'fact_corrections', 'open_items'):
        for item in result.get(kind, []):
            if not isinstance(item, dict) or not item.get('finding_ids') or not item.get('reason'):
                raise ValueError(kind + ': 必须指明 finding_ids 和 reason')
            if any(fid not in maps['findings'] for fid in item['finding_ids']):
                raise ValueError(kind + ': 未知 finding 引用')
    cited = re.compile(r'\b(?:E|CHK)-[A-Za-z0-9]+-\d+\b')
    for a in assessments:
        if a.get('proposed_kind') not in KINDS or not str(a.get('reason', '')).strip():
            raise ValueError('assessment 缺少性质或理由')
        # A pending reason is the only thing the next round inherits, and prose like
        # 「需核安全边界」 inherits nothing — measured once, 0 of 88 pending reasons named
        # a record and 53 of 78 issues came back as repeats. Every pending finding has
        # checks or evidence of its own to point at, so this is answerable by construction.
        if a['proposed_kind'] == 'pending' and not any(
                ref in maps['evidence'] or ref in maps['checks']
                for ref in cited.findall(str(a.get('reason', '')))):
            raise ValueError('待定理由须点名具体证据或检查：' + str(a.get('finding_id')))
    for group in result.get('group_proposals', []):
        members = group.get('finding_ids', [])
        if len(members) < 2 or len(set(members)) != len(members) or not set(members) <= set(task['finding_ids']):
            raise ValueError('group_proposals 成员无效')
        if not group.get('reason'): raise ValueError('同源建议缺少理由')
    if any(eid not in maps['evidence'] for eid in evidence_refs(result)):
        raise ValueError('临时结果引用未知证据')
    problems = dependency_errors(state, result.get('read_dependencies', []))
    if problems: raise ValueError('；'.join(problems))


def _issues(state, results):
    """Reconcile explicit judgments and relations, not all raw retrieval hits."""
    from rootcause import comparison_candidates
    issues, groups, by_finding = {}, [], {}
    def add(kind, ids, basis):
        ids = sorted(set(ids))
        key = 'I-' + fingerprint([kind, ids])[:20]
        row = issues.setdefault(key, {'id': key, 'kind': kind, 'finding_ids': ids, 'basis': []})
        if basis not in row['basis']:
            row['basis'].append(basis)
    comparisons = []
    for tid, result in sorted(results.items()):
        for row in result.get('assessments', []):
            by_finding.setdefault(row['finding_id'], []).append((tid, row))
        groups.extend((tid, set(g['finding_ids'])) for g in result.get('group_proposals', []))
        comparisons.extend(result.get('comparisons', []))
        for kind in ('cross_file_leads', 'fact_corrections', 'open_items'):
            for row in result.get(kind, []):
                add(kind, row.get('finding_ids', []), {'task_id': tid, 'item': row})
    for fid, rows in by_finding.items():
        if len({(r['proposed_kind'], r.get('target_finding_id')) for _, r in rows}) > 1:
            add('disposition_conflict', [fid], {'task_ids': sorted(t for t, _ in rows)})
    for i, (tid, group) in enumerate(groups):
        for other_tid, other in groups[i+1:]:
            if group & other and group != other:
                add('overlapping_groups', group | other,
                    {'task_ids': sorted({tid, other_tid}), 'groups': sorted([sorted(group), sorted(other)])})
    for candidate in comparison_candidates(state) if by_finding else []:
        ids = set(candidate['finding_ids'])
        if not any(ids <= set(c.get('finding_ids', [])) and c.get('conclusion') in {'same', 'distinct', 'grouped'} and c.get('reason') for c in comparisons):
            add('candidate_comparison', ids, {'candidate_key': candidate['key']})
    for comparison in comparisons:
        if comparison.get('conclusion') == 'distinct':
            for tid, group in groups:
                if len(group & set(comparison.get('finding_ids', []))) >= 2:
                    add('merge_distinct_conflict', group | set(comparison['finding_ids']),
                        {'task_id': tid, 'comparison': comparison})
    return [issues[key] for key in sorted(issues)]


def collect(workspace, state, run_id, events=None):
    from audit import write_json
    from knowledge import read
    root, manifest, source = load(workspace, run_id)
    working = copy.deepcopy(manifest)
    material_cache = {}
    if events is not None:
        rows = events.get('events') if isinstance(events, dict) else events
        if not isinstance(rows, list): raise ValueError('returns-file 需要 events 数组')
        for event in rows:
            task = working['tasks'].get(event.get('task_id'))
            if not task: raise ValueError('返回事件指向未知任务')
            attempt = next((a for a in task['attempts'] if a['n'] == event.get('attempt')), None)
            if not attempt or attempt is not task['attempts'][-1]: raise ValueError('事件不是当前尝试')
            kind = event.get('event')
            if kind == 'started':
                if task['state'] not in ACTIVE or not event.get('agent_id'): raise ValueError('启动事件需要有效派单和代理 ID')
                if attempt.get('agent_id') not in (None, event['agent_id']): raise ValueError('运行中代理 ID 不得替换')
                attempt.update(state='running', agent_id=event['agent_id']); task['state'] = 'running'
            elif kind in {'failed', 'rejected'}:
                if not event.get('reason') or (task['state'] == 'running' and not event.get('stopped')):
                    raise ValueError('失败需要原因；运行中任务必须确认已停止')
                attempt.update(state=kind, reason=event['reason']); task['state'] = 'planned'
            elif kind == 'completed':
                expected = inside(root, attempt['result_path'])
                if Path(event.get('result_path', str(expected))).resolve() != expected.resolve():
                    raise ValueError('结果路径不是该尝试的唯一输出')
                if task['state'] not in ACTIVE | {'returned'}: raise ValueError('没有可完成的活动尝试')
                result = read(expected)
                if task['state'] == 'returned' and fingerprint(result) != attempt.get('result_sha256'):
                    raise ValueError('已接收结果不可改写；使用新尝试')
                data = task_input(root, task)
                if stale_reasons(state, data, material_cache): raise ValueError('任务输入已经过期')
                validate_result(state, task, result, attempt, run_id)
                attempt.update(state='returned', result_sha256=fingerprint(result))
                task.update(state='returned', selected_attempt=attempt['n'])
            else: raise ValueError('事件类型必须为 started/completed/failed/rejected')
    results, all_results = {}, {}
    stale = []
    for tid, task in working['tasks'].items():
        if task['state'] != 'returned': continue
        data = task_input(root, task)
        attempt = next(a for a in task['attempts'] if a['n'] == task['selected_attempt'])
        result = read(inside(root, attempt['result_path']))
        if (fingerprint(result) != attempt['result_sha256']
                or stale_reasons(state, data, material_cache)
                or dependency_errors(state, result.get('read_dependencies', []))):
            stale.append(tid); continue
        validate_result(state, task, result, attempt, run_id)
        all_results[tid] = result
        if task['kind'] == 'analysis': results[tid] = result
    issues = _issues(source, results)
    # Cross-file jobs use the same isolated protocol; no graph closure becomes a verdict.
    from rootcause import candidates
    candidate_rows, maps = candidates(source), indexes(source)
    has_analysis = any(task['kind'] == 'analysis' for task in working['tasks'].values())
    analyses_ready = has_analysis and all(task['state'] == 'returned' for task in working['tasks'].values() if task['kind'] == 'analysis') and not stale
    for issue in issues if analyses_ready else []:
        tid = 'C-' + issue['id'][2:]
        if tid in working['tasks']: continue
        data = packet(source, issue['finding_ids'], candidate_rows=candidate_rows, maps=maps)
        data['issue'] = issue
        data['proposal_refs'] = [{'task_id': name, 'path': working['tasks'][name]['attempts'][-1]['result_path'],
                                 'sha256': fingerprint(result)} for name, result in sorted(results.items())
                                if set(issue['finding_ids']) & set(working['tasks'][name]['finding_ids'])]
        rel = 'tasks/' + tid + '/input.json'
        write_json(inside(root, rel), data)
        working['tasks'][tid] = {'id': tid, 'kind': 'reconciliation', 'finding_ids': data['finding_ids'],
                                 'owner_finding_ids': data['finding_ids'],
                                 'input_path': rel, 'input_digest': fingerprint(data), 'state': 'planned',
                                 'attempts': [], 'selected_attempt': None, 'issue_id': issue['id']}
    all_issues = {i['id']: i for i in issues}
    for issue in _issues(source, all_results):
        all_issues[issue['id']] = issue  # The combined pass includes every accepted basis.
    summary = {'run_id': run_id, 'issues': [all_issues[k] for k in sorted(all_issues)], 'stale_tasks': stale,
               'missing_analysis_tasks': sorted(tid for tid, task in working['tasks'].items()
                                                if task['kind'] == 'analysis' and tid not in results),
               'result_refs': {tid: {'path': working['tasks'][tid]['attempts'][-1]['result_path'],
                                     'sha256': fingerprint(result)} for tid, result in sorted(all_results.items())}}
    write_json(root / 'reconciliation/worklist.json', summary)
    write_json(root / 'manifest.json', working)
    return summary


def validate_submission(workspace, state, payload):
    from knowledge import read
    root, manifest, source = load(workspace, payload['run_id'])
    from rootcause import digest
    if digest(state) != manifest['base_sha256']:
        raise ValueError('run 基线已变化；创建增量运行并复用未变任务，不得只换 base_sha256')
    material_cache = {}
    current = {f['id'] for f in state['findings'] if f['status'] == 'current'}
    if current != set(manifest['finding_ids']):
        raise ValueError('current 集合变化；新增/移除发现需要增量比较')
    summary = read(root / 'reconciliation/worklist.json')
    if payload.get('run_digest') != fingerprint(summary):
        raise ValueError('run_digest 过期；重新读取汇总')
    for task in manifest['tasks'].values():
        if task['state'] != 'returned': raise ValueError('归因任务尚未完成：' + task['id'])
        data = task_input(root, task)
        if stale_reasons(state, data, material_cache): raise ValueError('任务输入已过期：' + task['id'])
        attempt = next(a for a in task['attempts'] if a['n'] == task['selected_attempt'])
        result = read(inside(root, attempt['result_path']))
        validate_result(state, task, result, attempt, manifest['run_id'])
        if fingerprint(result) != attempt['result_sha256']: raise ValueError('任务结果已变化')
    resolutions = {r.get('issue_id'): r for r in payload.get('resolutions', [])}
    if set(resolutions) != {i['id'] for i in summary['issues']}:
        raise ValueError('最终 resolutions 必须核对全部汇总问题')
    if manifest['tasks'] and all(t['kind'] == 'report-organization' for t in manifest['tasks'].values()):
        if 'report_plan' not in payload:
            raise ValueError('报告组织运行必须提交report_plan')
        # Only *unresolved* issues block. Rejecting a resolved fact_correction as well
        # deadlocks against the staged-report rule: attribution is designed to leave
        # fact_corrections behind, so report organisation could never run once one
        # existed. Measured — the one round that got through had only open_items,
        # which was luck rather than design.
        unresolved = [i['id'] for i in summary['issues']
                      if resolutions[i['id']].get('resolution') != 'resolved']
        if unresolved:
            raise ValueError('报告组织仍有未闭合事项，先回交复核：' + '、'.join(unresolved[:4]))
        return
    dispositions = {r['finding_id']: r for r in payload.get('finding_dispositions', [])}
    if set(dispositions) & current != current:
        raise ValueError('运行提交必须处置全部 current finding')
    for issue in summary['issues']:
        row = resolutions[issue['id']]
        if not row.get('reason') or row.get('resolution') not in {'resolved', 'pending'}:
            raise ValueError('核对结论需要理由及 resolved/pending')
        if (row['resolution'] == 'pending' or issue['kind'] in {'fact_corrections', 'open_items'}) and any(
                dispositions[fid]['kind'] != 'pending' for fid in issue['finding_ids'] if fid in current):
            raise ValueError('事实订正或未解决问题必须保持 pending，先回交复核')


def record_disputes(workspace, working, payload, timestamp):
    """Carry unresolved disputes out of the run directory and into the record.

    `validate_submission` already forces a finding named by a fact_corrections or
    open_items issue to stay pending, so the tie exists at submission time. What did
    not exist is memory: the worklist lives in the run directory, a new run builds a
    fresh one, and the same dispute comes back looking new. Measured on one real
    closure, 53 of 78 issues were repeats and only the model knew — it wrote the
    previous id into prose that no script reads.

    No new identity is minted. The issue id is already content-addressed over
    (kind, sorted finding_ids), so the same dispute keeps the same id across runs and
    `runs` is simply the list of rounds it has survived.
    """
    from knowledge import read
    root, _, _ = load(workspace, payload['run_id'])
    summary = read(root / 'reconciliation/worklist.json')
    rows = {row['id']: row for row in working.setdefault('fact_disputes', [])}
    verdicts = {r.get('issue_id'): r for r in payload.get('resolutions', [])}
    for issue in summary['issues']:
        if issue['kind'] not in {'fact_corrections', 'open_items'}:
            continue
        verdict = verdicts.get(issue['id']) or {}
        row = rows.get(issue['id'])
        if row is None:
            row = {'id': issue['id'], 'kind': issue['kind'], 'runs': [],
                   'finding_ids': [], 'status': 'open', 'reason': ''}
            rows[issue['id']] = row
            working['fact_disputes'].append(row)
        row['finding_ids'] = list(issue['finding_ids'])
        row['reason'] = verdict.get('reason') or row.get('reason') or ''
        if payload.get('run_id') and payload['run_id'] not in row['runs']:
            row['runs'].append(payload['run_id'])
        if verdict.get('resolution') == 'resolved':
            row['status'], row['resolved_at'] = 'resolved', timestamp
        else:
            row['status'] = 'open'
            row.pop('resolved_at', None)


def record_receipt(workspace, run_id, result):
    from audit import write_json
    root, manifest, source = load(workspace, run_id)
    manifest['status'] = 'applied'
    write_json(root / 'receipt.json', result)
    write_json(root / 'manifest.json', manifest)


def reuse_results(staging, parent, manifest, state):
    from audit import write_json
    from knowledge import read
    eligible = {}
    for path in sorted(parent.glob('*/manifest.json')):
        old = read(path)
        for task in old.get('tasks', {}).values():
            if task.get('kind') != 'analysis' or task.get('state') != 'returned': continue
            attempt = next((a for a in task['attempts'] if a['n'] == task.get('selected_attempt')), None)
            if not attempt: continue
            try:
                result = read(inside(path.parent, attempt['result_path']))
                if fingerprint(result) != attempt['result_sha256']: continue
                validate_result(state, task, result, attempt, old['run_id'])
                eligible.setdefault(task['input_digest'], (old, task, attempt, result))
            except (OSError, ValueError, KeyError, TypeError): continue
    for task in manifest['tasks'].values():
        previous = eligible.get(task['input_digest'])
        if not previous: continue
        old, oldtask, oldattempt, result = previous
        rel = 'tasks/' + task['id'] + '/result-1.json'
        write_json(staging / rel, result)
        origin = oldattempt.get('origin') or {'run_id': old['run_id'], 'task_id': oldtask['id'], 'attempt': oldattempt['n']}
        task.update(state='returned', selected_attempt=1,
                    attempts=[{'n': 1, 'state': 'returned', 'agent_id': None, 'result_path': rel,
                               'result_sha256': fingerprint(result), 'origin': origin,
                               'reused_from': str(parent / old['run_id'] / oldattempt['result_path'])}])
