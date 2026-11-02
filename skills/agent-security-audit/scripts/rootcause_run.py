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


def packet(state, ids, groups=None, candidate_rows=None, maps=None):
    from rootcause import candidates
    facts = finding_packet(state, ids, maps)
    selected = set(ids)
    facts.update(finding_ids=sorted(selected), file_groups=groups or [],
                 target_id=state['target_id'], targets=state.get('targets', []),
                 candidates=[r for r in (candidate_rows if candidate_rows is not None else candidates(state)) if selected & set(r['finding_ids'])],
                 root_causes=[r for r in state.get('root_causes', []) if selected & set(r.get('finding_ids', []))],
                 chains=[r for r in state.get('chains', []) if any(s.get('finding_id') in selected for s in r.get('steps', []))],
                 report_todos=[t for t in state.get('report_todos', [])
                               if selected & set(re.findall(r'(?<![A-Za-z0-9_-])(F-[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])', t.get('instruction', '')))])
    return facts


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
    groups = file_groups(state)
    from rootcause import candidates
    candidate_rows, maps = candidates(state), indexes(state)
    def make(ids, groups=None):
        return packet(state, ids, groups, candidate_rows, maps)
    tasks = []
    if task_plan is not None:
        if not isinstance(task_plan, dict) or not isinstance(task_plan.get('tasks'), list):
            raise ValueError('任务计划需要 tasks 数组')
        for row in task_plan['tasks']:
            if not row.get('reason') or not row.get('finding_ids'):
                raise ValueError('自定义比较任务需要 finding_ids 和 reason')
            tasks.append(make(row['finding_ids']))
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
    if covered != current:
        raise ValueError('任务必须覆盖全部 current finding 且无额外成员')
    manifest = {'version': 1, 'run_id': run_id, 'created_at': now(), 'status': 'prepared',
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
            manifest['tasks'][tid] = {'id': tid, 'kind': 'analysis', 'finding_ids': data['finding_ids'],
                                      'input_path': rel, 'input_digest': fingerprint(data),
                                      'state': 'planned', 'attempts': [], 'selected_attempt': None}
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
    if data.get('targets', []) != state.get('targets', []): reasons.append('目标位置或版本已改变')
    from audit import material_path
    from knowledge import digest
    material_cache = {} if material_cache is None else material_cache
    for mid, material in data.get('materials', {}).items():
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
    rel = 'tasks/%s/result-%d.json' % (task_id, n)
    brief_rel = 'tasks/%s/brief-%d.md' % (task_id, n)
    role = SKILL / 'references/roles/rootcause_reviewer.md'
    prompt = ('# 归因任务\n\n读取角色契约：%s\n\n'
              '运行：%s；任务：%s；类型：%s；尝试：%d。\n\n'
              '输入：%s\n\n唯一结果文件：%s\n\n'
              'input_digest：%s\n\n审计工作区：%s\n\n'
              '只写本任务的临时 JSON；全部 finding 都要有建议或明确 pending。'
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
            or sorted(a.get('finding_id', '') for a in assessments) != sorted(task['finding_ids'])):
        raise ValueError('临时结果必须逐条覆盖任务 finding，不允许遗漏、重复或额外成员')
    maps = indexes(state)
    for kind in ('cross_file_leads', 'fact_corrections', 'open_items'):
        for item in result.get(kind, []):
            if not isinstance(item, dict) or not item.get('finding_ids') or not item.get('reason'):
                raise ValueError(kind + ': 必须指明 finding_ids 和 reason')
            if any(fid not in maps['findings'] for fid in item['finding_ids']):
                raise ValueError(kind + ': 未知 finding 引用')
    for a in assessments:
        if a.get('proposed_kind') not in KINDS or not str(a.get('reason', '')).strip():
            raise ValueError('assessment 缺少性质或理由')
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
    from rootcause import candidates
    issues = {}
    def add(kind, ids, basis):
        ids = sorted(set(ids))
        key = 'I-' + fingerprint([kind, ids, basis])[:20]
        issues[key] = {'id': key, 'kind': kind, 'finding_ids': ids, 'basis': basis}
    by_finding, groups = {}, []
    for tid, result in sorted(results.items()):
        for row in result['assessments']:
            by_finding.setdefault(row['finding_id'], []).append((tid, row))
        for group in result.get('group_proposals', []):
            groups.append((tid, set(group['finding_ids'])))
        for kind in ('cross_file_leads', 'fact_corrections', 'open_items'):
            for item in result.get(kind, []):
                add(kind, item.get('finding_ids', [item['finding_id']] if item.get('finding_id') else []),
                    {'task_id': tid, 'item': item})
    for fid, rows in by_finding.items():
        meanings = {(r['proposed_kind'], r.get('target_finding_id')) for _, r in rows}
        if len(meanings) > 1: add('disposition_conflict', [fid], {'task_ids': sorted(t for t, _ in rows)})
    for i, (tid, group) in enumerate(groups):
        for other_tid, other in groups[i+1:]:
            if group & other and group != other:
                add('overlapping_groups', group | other, {'task_ids': sorted({tid, other_tid}),
                                                       'groups': sorted([sorted(group), sorted(other)])})
    comparisons = [c for result in results.values() for c in result.get('comparisons', [])]
    for row in candidates(state):
        ids = set(row['finding_ids'])
        answered = any(ids <= set(c.get('finding_ids', [])) and c.get('conclusion') in {'same', 'distinct', 'grouped'}
                       and c.get('reason') for c in comparisons)
        if not answered:
            add('candidate_comparison', ids, {'candidate_key': row['key'], 'basis': row['basis']})
    for c in comparisons:
        if c.get('conclusion') != 'distinct': continue
        for tid, group in groups:
            if len(group & set(c.get('finding_ids', []))) >= 2:
                add('merge_distinct_conflict', group | set(c['finding_ids']), {'task_id': tid, 'comparison': c})
    return [issues[k] for k in sorted(issues)]


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
        validate_result(state, task, result, attempt, run_id)
        if fingerprint(result) != attempt['result_sha256'] or stale_reasons(state, data, material_cache):
            stale.append(tid); continue
        all_results[tid] = result
        if task['kind'] == 'analysis': results[tid] = result
    issues = _issues(source, results)
    # Cross-file jobs use the same isolated protocol; no graph closure becomes a verdict.
    from rootcause import candidates
    candidate_rows, maps = candidates(source), indexes(source)
    analyses_ready = all(task['state'] == 'returned' for task in working['tasks'].values() if task['kind'] == 'analysis') and not stale
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
                                 'input_path': rel, 'input_digest': fingerprint(data), 'state': 'planned',
                                 'attempts': [], 'selected_attempt': None, 'issue_id': issue['id']}
    all_issues = {i['id']: i for i in issues}
    for issue in _issues(source, all_results): all_issues.setdefault(issue['id'], issue)
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
