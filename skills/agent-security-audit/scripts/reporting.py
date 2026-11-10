"""Export indexed audit records; validate, never compose, authored reports."""
from collections import Counter, defaultdict
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import unquote, urlsplit

VERSION = 3
SHARD_BYTES = 96 * 1024
SHARD_RECORDS = 32
SUMMARY_HEADINGS = ('1. 审计对象与关键结论', '2. 全部严重问题',
                    '3. 重要攻击场景', '4. 证据边界')
VULNERABILITY_HEADINGS = ('1. 问题概述', '2. 组件与安全边界', '3. 触发条件与输入',
                          '4. 漏洞机制与证据', '5. 受影响范围',
                          '6. 验证与复现材料', '7. 结论边界与来源')
META_PREFIX = '<!-- audit-report: '
SEVERITIES = ('critical', 'high', 'medium', 'low', 'informational')
EXPOSURES = ('EXT', 'ADJ', 'INT', 'unknown')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def source_digest(state):
    # Presentation bookkeeping is not new audit evidence. Closing a report todo must
    # not invalidate the prose just written to close it.
    source = {k: v for k, v in state.items() if k not in {'updated_at', 'report_todos'}}
    source['report_todos'] = [{k: v for k, v in row.items() if k not in {'status', 'reason'}}
                              for row in state.get('report_todos', [])]
    return fingerprint(source)


def finding_order(finding):
    return (SEVERITIES.index(finding['severity']),
            EXPOSURES.index(finding.get('exposure')) if finding.get('exposure') in EXPOSURES else 3,
            finding['id'])


def high_findings(state):
    return sorted((f for f in state.get('findings', [])
                   if f.get('status') == 'current' and f.get('severity') in {'critical', 'high'}),
                  key=finding_order)


def _safe_id(value):
    value = str(value)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value) or value in {'.', '..'}:
        raise ValueError('Unsafe record identifier: ' + value)
    return value


def _owner(row):
    if row.get('unit_id'):
        return _safe_id(row['unit_id'])
    found = re.match(r'^[^-]+-([A-Za-z]+\d+)(?:-|$)', str(row.get('id', '')))
    return 'U-' + found.group(1) if found else 'shared'


def _refs(value, suffix='evidence_ids'):
    result = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith(suffix) and isinstance(item, list):
                result.update(x for x in item if isinstance(x, str))
            else:
                result.update(_refs(item, suffix))
    elif isinstance(value, list):
        for item in value:
            result.update(_refs(item, suffix))
    return result


def _input_maps(state):
    maps = {key: {r['id']: r for r in state.get(key, [])}
            for key in ('findings', 'checks', 'evidence', 'instances', 'root_causes')}
    maps['reviews'] = defaultdict(list)
    for review in state.get('reviews', []):
        maps['reviews'][review['finding_id']].append(review)
    maps['controls'] = defaultdict(list)
    for control in state.get('controls', []):
        for cid in control.get('check_ids', []):
            maps['controls'][cid].append(control)
    return maps


def task_input(state, task, maps=None):
    """Read a bounded dependency packet, preserving original records and caveats."""
    maps = maps or _input_maps(state)
    from report_plan import related_chains, chain_findings
    chains = related_chains(state, task['finding_ids'])
    ids = set(task['finding_ids']) | set(chain_findings(state, chains))
    findings = [maps['findings'][fid] for fid in sorted(ids) if fid in maps['findings']]
    check_ids = {cid for f in findings for cid in f.get('check_ids', [])}
    check_ids.update(s['check_id'] for chain in chains for s in chain.get('steps', []) if s.get('check_id') in maps['checks'])
    controls = {c['id']: c for cid in check_ids for c in maps['controls'].get(cid, [])}
    check_ids.update(cid for c in controls.values() for cid in c.get('check_ids', []))
    checks = [maps['checks'][cid] for cid in sorted(check_ids) if cid in maps['checks']]
    reviews = [r for f in findings for r in maps['reviews'].get(f['id'], [])]
    evidence_ids = _refs(findings) | _refs(checks) | _refs(reviews) | _refs(list(controls.values()))
    evidence = [maps['evidence'][eid] for eid in sorted(evidence_ids) if eid in maps['evidence']]
    materials = {e['material_id']: state['materials'][e['material_id']] for e in evidence
                 if e.get('material_id') in state.get('materials', {})}
    instance_ids = {iid for c in checks for iid in c.get('instance_ids', [])}
    todo_ids = set(task.get('todo_ids', []))
    from attribution import latest_dispositions
    dispositions = latest_dispositions(state)
    return {'finding_dispositions': [dispositions[f['id']] for f in findings if f['id'] in dispositions],
            'target_id': state['target_id'], 'targets': state.get('targets', []),
            'findings': findings, 'checks': checks, 'evidence': evidence, 'materials': materials,
            'reviews': reviews, 'controls': [controls[cid] for cid in sorted(controls)],
            'instances': [maps['instances'][iid] for iid in sorted(instance_ids) if iid in maps['instances']],
            'root_cause': maps['root_causes'].get(task.get('root_cause_id')),
            'root_causes': [maps['root_causes'][rid] for rid in task.get('root_cause_ids', [])],
            'chains': chains,
            'report_group': {k: task.get(k) for k in ('id', 'title', 'vulnerability_ids', 'framework_object_ids', 'grouping_reason')},
            'report_todos': [{k: v for k, v in t.items() if k not in {'status', 'reason'}}
                             for t in state.get('report_todos', []) if t['id'] in todo_ids]}


def build_tasks(state):
    maps = _input_maps(state)
    current = {f['id']: f for f in state.get('findings', []) if f.get('status') == 'current'}
    current_ids = set(current)
    from attribution import latest_dispositions
    dispositions = latest_dispositions(state)
    named = {t['id']: set(re.findall(r'(?<![A-Za-z0-9_-])(F-[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])',
                                     t.get('instruction', '')))
             for t in state.get('report_todos', [])}
    from report_plan import build_report_view
    view = build_report_view(state)
    if view['errors']:
        raise ValueError('；'.join(view['errors']))
    groups = view['groups']
    tasks = []
    for group in groups:
        rid = _safe_id(group['id'])
        members, root_id = group['finding_ids'], group['root_cause_id']
        todos = [t['id'] for t in state.get('report_todos', [])
                 if any(re.search(r'(?<![A-Za-z0-9_-])' + re.escape(fid) +
                                  r'(?![A-Za-z0-9_-])', t.get('instruction', ''))
                        for fid in members)]
        task = {**group, 'id': rid, 'finding_ids': members, 'root_cause_id': root_id, 'todo_ids': todos,
                'handoff_path': 'handoffs/' + rid + '.md'}
        packet = task_input(state, task, maps)
        task['source_digest'] = fingerprint(packet)
        task['input_refs'] = {k: [r['id'] for r in packet[k]]
                              for k in ('findings', 'checks', 'evidence', 'reviews', 'controls', 'instances')}
        task['input_refs']['materials'] = sorted(packet['materials'])
        task['input_refs']['finding_dispositions'] = [r['id'] for r in packet['finding_dispositions']]
        task['input_refs']['root_causes'] = task['root_cause_ids']
        task['input_refs']['chains'] = [c['id'] for c in packet['chains']]
        task['input_refs']['report_todos'] = todos
        # The packet already knows these; handing over only the id lists makes the
        # author re-derive them. Measured on one page: it had to read the
        # dispositions to learn two members were pending and one withdrawn, and
        # search the finding index to learn two routed todos had no member in this
        # record set at all. `todo_scope` lists the members rather than counting
        # them: these instructions often carry a whole cross-unit cluster table —
        # one named 28 findings — so a single number silently mixes in another
        # unit's members and sends the author looking for a landing that is not here.
        task['member_dispositions'] = {fid: dispositions[fid]['kind']
                                       for fid in members if fid in dispositions}
        task['todo_scope'] = {tid: sorted(named[tid] & current_ids) for tid in todos}
        tasks.append(task)
    return sorted(tasks, key=lambda t: (min(finding_order(current[fid])[:2] for fid in t['finding_ids']), t['id']))


def _record_groups(state):
    """Every top-level value has a lossless material landing, including unknown keys."""
    owners = {mid: u['id'] for u in state.get('units', []) for mid in u.get('material_ids', [])}
    for category, value in state.items():
        if category == 'materials':
            rows = [(str(key), row, owners.get(key, 'shared')) for key, row in value.items()]
        elif isinstance(value, list):
            rows = [(str(row.get('id', '%s-%06d' % (category, i))) if isinstance(row, dict)
                     else '%s-%06d' % (category, i), row,
                     _owner(row) if isinstance(row, dict) else 'shared')
                    for i, row in enumerate(value, 1)]
        else:
            rows = [(category, value, 'shared')]
        # Historical logs can legitimately reuse an ID. Preserve each occurrence
        # under a distinct locator; the original JSON ID is never changed.
        counts = Counter(rid for rid, _, _ in rows)
        used = {rid for rid, _, _ in rows if counts[rid] == 1}
        occurrences, normalized = Counter(), []
        for rid, row, owner in rows:
            key = rid
            if counts[rid] > 1:
                occurrences[rid] += 1
                key = rid + '@' + str(occurrences[rid])
                while key in used:
                    key += '@'
            used.add(key)
            normalized.append((key, row, owner))
        yield category, normalized


def _anchor_id(rid):
    return rid if re.fullmatch(r'[A-Za-z0-9_.:-]+', rid) else 'record-' + fingerprint(rid)[:20]


def _record_block(rid, row):
    data = json.dumps(row, ensure_ascii=False, indent=2)
    fence = '`' * max(3, 1 + max((len(m.group()) for m in re.finditer(r'`+', data)), default=0))
    return '<a id="%s"></a>\n## %s\n\n%sjson\n%s\n%s\n\n' % (
        html.escape(_anchor_id(rid), quote=True), html.escape(rid), fence, data, fence)


def _inside(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Report path must stay inside report/: ' + str(relative))
    path = root / relative
    for part in [path] + list(path.parents):
        if part == root.parent:
            break
        if part.is_symlink():
            raise ValueError('Report path is a symlink: ' + str(path))
    return path


def _atomic_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix='.report-', delete=False) as out:
        temporary = Path(out.name)
        out.write(text)
    try:
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_meta(text):
    first = text.splitlines()[0] if text.splitlines() else ''
    if not first.startswith(META_PREFIX) or not first.endswith(' -->'):
        raise ValueError('Missing audit-report JSON metadata on first line')
    value = json.loads(first[len(META_PREFIX):-4])
    if not isinstance(value, dict):
        raise ValueError('Report metadata must be an object')
    return value


def _artifact_status(root, path, expected_digest):
    target = _inside(root, path)
    if not target.exists():
        return 'pending'
    try:
        meta = read_meta(target.read_text(encoding='utf-8'))
        return 'draft' if meta.get('source_digest') == expected_digest else 'stale'
    except (OSError, ValueError, TypeError):
        return 'invalid'


def _handoff_errors(root, task_id, expected_digest, state):
    path = _inside(root, 'handoffs/' + _safe_id(task_id) + '.md')
    if not path.exists():
        return []
    try:
        body = path.read_text(encoding='utf-8')
        meta = read_meta(body)
        if (meta.get('type') != 'report_handoff' or meta.get('task_id') != task_id
                or not isinstance(meta.get('source_digest'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', meta['source_digest'])):
            return ['报告回交元数据无效：' + task_id]
        if meta['source_digest'] != expected_digest:
            return ['报告回交来源已变化，须核对并归档原回交：' + task_id]
        fids = meta.get('finding_ids')
        known = {f['id'] for f in state.get('findings', [])}
        if (not isinstance(fids, list) or any(not isinstance(fid, str) or fid not in known for fid in fids)
                or len(set(fids)) != len(fids) or meta.get('return_to') not in {'reviewer', 'rootcause_reviewer'}
                or _headings(body) != ['1. 无法成文的主张', '2. 支撑与冲突证据', '3. 回交范围']):
            return ['报告回交内容契约无效：' + task_id]
    except (OSError, ValueError, TypeError) as exc:
        return ['报告回交无法读取：' + task_id + '：' + str(exc)]
    return ['报告事实或归属回交未闭合：' + task_id + '；见 handoffs/' + task_id + '.md']


EXCERPT_LINES = 200


def _task_excerpts(workspace, state, tasks):
    """Ship the cited source with the packet instead of making every author fetch it.

    Measured on one wave of four writers: two timed out, both after the same step —
    「资料都齐了，写的时候没预算了」— and neither left a file. The packet hands out
    `input_refs` pointers, so each author resolves target roots, reads the files,
    slices the locators and then byte-compares its own transcription. The two that
    finished had each verified a dozen-plus excerpts by hand; nobody asked them to.

    Handing over the text removes that whole leg and, with it, a class of error:
    an excerpt that was never transcribed cannot be mistranscribed. Authors still
    read source when they go beyond the record, which is what the citation checks
    in `_authored_code_errors` are for.

    Not part of `source_digest`: the packet already carries each material's sha256,
    so a changed file already stales the task. Hashing the extracted text too would
    only add churn from decoding details.
    """
    roots = {row['id']: row['path'] for row in state.get('targets', [])}
    materials = state.get('materials', {})
    evidence = {row['id']: row for row in state.get('evidence', [])}
    blobs, cache = {}, {}

    def lines_of(material):
        if material['id'] not in cache:
            path = Path(roots.get(material['target_id'], '')) / material['path']
            try:
                from materials import decode
                cache[material['id']] = decode(path.read_bytes(), material.get('encoding'))[0].splitlines()
            except (OSError, ValueError, UnicodeDecodeError, LookupError) as exc:
                cache[material['id']] = str(exc)
        return cache[material['id']]

    for task in tasks:
        rows = {}
        for eid in task['input_refs']['evidence']:
            row = evidence.get(eid)
            material = materials.get((row or {}).get('material_id'))
            locator = (row or {}).get('locator') or {}
            span = locator.get('lines')
            # Every cited evidence gets a row, including the ones that cannot be
            # extracted. Skipping them silently is how the first version of this
            # shipped: 346 excerpts looked like full coverage while 102 citations —
            # every section-form locator into an oversized bundle and every .pyc —
            # had no entry at all, and the only way to notice was to diff the file
            # against `input_refs.evidence` by hand. An author who cannot tell
            # "absent" from "nothing to say" re-fetches everything.
            if not material:
                rows[eid] = {'unavailable': 'evidence has no material in the record'}
                continue
            entry = {'material_id': material['id'], 'path': material['path'],
                     'target_id': material['target_id'], 'sha256': material['sha256'],
                     'locator': locator}
            if span:
                entry['lines'] = list(span)
            if not span:
                entry['unavailable'] = ('定位不是行号（%s），需回源按该定位取材'
                                        % ('、'.join(locator) or '无 locator'))
            elif material.get('visibility') != 'text':
                entry['unavailable'] = material.get('visibility_reason') or 'material is not text'
            else:
                body = lines_of(material)
                if isinstance(body, str):
                    entry['unavailable'] = body
                else:
                    first, last = span[0], min(span[1], span[0] + EXCERPT_LINES - 1)
                    entry['text'] = '\n'.join(body[first - 1:last])
                    if last < span[1]:
                        entry['truncated_after'] = last
            rows[eid] = entry
        relative = 'excerpts/' + _safe_id(task['id']) + '.json'
        task['excerpt_path'] = relative
        blobs[relative] = json.dumps(rows, ensure_ascii=False, indent=2) + '\n'
    return blobs


def _pack_index(index):
    """Keep the root index small; detailed record/task maps have their own indexes."""
    root = {k: v for k, v in index.items() if k not in {'catalog', 'locations', 'aliases', 'tasks',
                                                       'task_indexes', 'task_order', 'finding_map'}}
    root['catalog'], root['task_indexes'], blobs = {}, [], {}
    for category, catalog in index['catalog'].items():
        relative = 'record-index/' + _safe_id(category) + '.json'
        content = {'catalog': catalog, 'locations': index['locations'][category],
                   'aliases': index.get('aliases', {}).get(category, {})}
        body = json.dumps(content, ensure_ascii=False, indent=2) + '\n'
        blobs[relative] = body
        root['catalog'][category] = {'records': catalog['records'], 'index_path': relative,
                                    'sha256': hashlib.sha256(body.encode('utf-8')).hexdigest()}
    groups = defaultdict(list)
    for task in index['tasks']:
        owner = 'root-causes' if task['root_cause_id'] else _owner({'id': task['id']})
        groups[owner].append(task)
    root['task_order'] = [t['id'] for t in index['tasks']]
    for owner, tasks in sorted(groups.items()):
        relative = 'task-index/' + _safe_id(owner) + '.json'
        body = json.dumps(tasks, ensure_ascii=False, indent=2) + '\n'
        blobs[relative] = body
        root['task_indexes'].append({'path': relative, 'ids': [t['id'] for t in tasks],
                                     'sha256': hashlib.sha256(body.encode('utf-8')).hexdigest()})
    map_path = 'record-index/_finding-map.json'
    map_body = json.dumps(index.get('finding_map', {}), ensure_ascii=False, indent=2) + '\n'
    blobs[map_path] = map_body
    root['finding_map_index'] = {'path': map_path, 'sha256': hashlib.sha256(map_body.encode()).hexdigest()}
    return root, blobs


def load_index(workspace):
    """Resolve indexed metadata without putting the entire catalog into model context."""
    root = Path(workspace) / 'report'
    stored = json.loads(_inside(root, 'index.json').read_text(encoding='utf-8'))
    expanded = dict(stored)
    expanded['catalog'], expanded['locations'], expanded['aliases'] = {}, {}, {}
    def read_index(relative, sha):
        content = _inside(root, relative).read_bytes()
        if hashlib.sha256(content).hexdigest() != sha:
            raise ValueError('Metadata index is missing or changed: ' + relative)
        return json.loads(content)
    for category, descriptor in stored['catalog'].items():
        content = read_index(descriptor['index_path'], descriptor['sha256'])
        if descriptor['records'] != content['catalog']['records']:
            raise ValueError('Category count differs: ' + category)
        expanded['catalog'][category] = content['catalog']
        expanded['locations'][category] = content['locations']
        expanded['aliases'][category] = content['aliases']
    tasks = {}
    for descriptor in stored['task_indexes']:
        rows = read_index(descriptor['path'], descriptor['sha256'])
        if [t['id'] for t in rows] != descriptor['ids']:
            raise ValueError('Task index IDs differ: ' + descriptor['path'])
        for task in rows:
            if task['id'] in tasks:
                raise ValueError('Duplicate report task: ' + task['id'])
            tasks[task['id']] = task
    if len(stored['task_order']) != len(tasks) or set(stored['task_order']) != set(tasks):
        raise ValueError('Task order does not match task indexes')
    expanded['tasks'] = [tasks[rid] for rid in stored['task_order']]
    if stored.get('finding_map_index'):
        descriptor = stored['finding_map_index']
        expanded['finding_map'] = read_index(descriptor['path'], descriptor['sha256'])
    return expanded


def export_package(workspace, state):
    """Replace machine-owned records/index; preserve every authored Markdown byte."""
    workspace = Path(workspace)
    root = _inside(workspace, 'report')
    root.mkdir(exist_ok=True)
    records = _inside(root, 'records')
    index_path = _inside(root, 'index.json')
    catalog, locations, aliases, rendered = {}, {}, {}, {}
    for category, rows in _record_groups(state):
        category_path = _safe_id(category).replace('_', '-')
        grouped = defaultdict(list)
        aliases[category] = {}
        for rid, row, owner in rows:
            if isinstance(row, dict) and row.get('id') and str(row['id']) != rid:
                aliases[category].setdefault(str(row['id']), []).append(rid)
            # Record IDs may include enum coordinates such as object_mapping:U-AA01.
            # They are anchors, not filesystem paths.
            if category in {'root_causes', 'chains'}:
                owner = rid
            grouped[_safe_id(owner)].append((rid, row))
        cat = {'records': len(rows), 'files': []}
        locations[category] = {}
        for owner, items in sorted(grouped.items()):
            chunks, chunk, size = [], [], 0
            for rid, row in items:
                block = _record_block(rid, row)
                block_size = len(block.encode('utf-8'))
                if chunk and (len(chunk) >= SHARD_RECORDS or size + block_size > SHARD_BYTES):
                    chunks.append(chunk); chunk, size = [], 0
                chunk.append((rid, block)); size += block_size
            if chunk:
                chunks.append(chunk)
            for number, chunk in enumerate(chunks, 1):
                relative = 'records/%s/%s-%03d.md' % (category_path, owner, number)
                body = '# %s / %s\n\n由审计记录机械导出；记录存在不等于结论已成立。\n\n' % (category, owner)
                body += ''.join(block for _, block in chunk)
                rendered[relative] = body
                cat['files'].append({'path': relative, 'ids': [rid for rid, _ in chunk],
                                     'bytes': len(body.encode('utf-8')),
                                     'sha256': hashlib.sha256(body.encode('utf-8')).hexdigest()})
                for rid, _ in chunk:
                    if rid in locations[category]:
                        raise ValueError('Duplicate record ID in ' + category + ': ' + rid)
                    locations[category][rid] = relative + '#' + _anchor_id(rid)
        catalog[category] = cat
    tasks = build_tasks(state)
    rendered.update(_task_excerpts(workspace, state, tasks))
    from report_plan import build_report_view
    view = build_report_view(state, locations)
    # The plan already decided where each chain is presented; without this the task
    # carries only `related_chains(finding_ids)`, which on a real page handed the
    # author nine chains for four assignments and no way to tell them apart —
    # while `report --check` demands an anchor for exactly the assigned four.
    for task in tasks:
        owned = [cid for cid, place in view['chain_locations'].items()
                 if place['kind'] == 'report' and place['target_id'] == task['id']]
        task['chain_ids'] = sorted(owned)
        task['context_chain_ids'] = sorted(set(task['input_refs']['chains']) - set(owned))
    digest = source_digest(state)
    current = [f for f in state.get('findings', []) if f.get('status') == 'current']
    all_todos = {t['id'] for t in state.get('report_todos', []) if t.get('status') != 'dropped'}
    routed_todos = {tid for task in tasks for tid in task['todo_ids']}
    index = {'version': VERSION, 'source': '../audit.json', 'source_digest': digest,
             'target_id': state['target_id'], 'catalog': catalog, 'locations': locations, 'aliases': aliases,
             'finding_map': view['finding_map'], 'attribution_pending': view['pending'],
             'high_vulnerabilities': view['high_vulnerabilities'], 'scenarios': view['scenarios'],
             'chain_locations': view['chain_locations'],
             'statistics': {'finding_status': dict(Counter(f.get('status') for f in state.get('findings', []))),
                            'current_severity': dict(Counter(f['severity'] for f in current)),
                            'current_exposure': dict(Counter(f.get('exposure') or 'unknown' for f in current)),
                            'checks': len(state.get('checks', [])), 'reviews': len(state.get('reviews', [])),
                            'materials': len(state.get('materials', {})), 'report_tasks': len(tasks),
                            'attribution': view['statistics']},
             'high_findings': [{'id': f['id'], 'severity': f['severity'], 'exposure': f.get('exposure')}
                               for f in high_findings(state)],
             'ext_chains': [{'id': c['id'], 'title': c['title'], 'status': c.get('status')}
                            for c in state.get('chains', []) if c.get('entry_exposure') == 'EXT'],
             'summary_todo_ids': sorted(all_todos - routed_todos), 'tasks': tasks,
             'summary_handoff_path': 'handoffs/summary.md',
             'summary_status': 'needs_review' if _handoff_errors(root, 'summary', digest, state) else _artifact_status(root, 'summary.md', digest)}
    for task in index['tasks']:
        task['writing_status'] = ('needs_review' if _handoff_errors(root, task['id'], task['source_digest'], state)
                                  else _artifact_status(root, task['path'], task['source_digest']))
    stored_index, metadata = _pack_index(index)
    rendered.update(metadata)
    # Stage all machine-owned trees. A failed publication restores the previous set.
    with tempfile.TemporaryDirectory(prefix='.report-build-', dir=workspace) as tmp:
        staging = Path(tmp)
        names = ('records', 'record-index', 'task-index', 'excerpts')
        for name in names:
            (staging / name).mkdir()
        for relative, body in rendered.items():
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding='utf-8')
        saved, published = [], []
        try:
            for name in names:
                destination = _inside(root, name)
                if destination.exists():
                    destination.rename(staging / ('old-' + name))
                    saved.append(name)
                (staging / name).rename(destination)
                published.append(name)
            _atomic_text(index_path, json.dumps(stored_index, ensure_ascii=False, indent=2) + '\n')
        except Exception:
            for name in reversed(published):
                shutil.rmtree(root / name)
            for name in reversed(saved):
                (staging / ('old-' + name)).rename(root / name)
            raise
    # Root report.md is a compatibility navigation file, not an authored artifact.
    pointer = workspace / 'report.md'
    if pointer.is_symlink():
        raise ValueError('Report navigation is a symlink')
    if pointer.exists() and not pointer.read_text(encoding='utf-8').startswith('# 审计报告导航\n'):
        legacy = _inside(root, 'legacy/report.md')
        if not legacy.exists():
            legacy.parent.mkdir(exist_ok=True)
            shutil.copy2(pointer, legacy)
    _atomic_text(pointer, '# 审计报告导航\n\n[阅读审计摘要](report/summary.md) · '
                 '[材料与报告索引](report/index.json)\n\n正文由 report_writer 撰写；'
                 '机械导出完成不代表人工报告已交付。\n')
    expected_paths = {task['path'] for task in tasks}
    folder = _inside(root, 'vulnerabilities')
    if folder.exists():
        for old in folder.glob('*.md'):
            relative = str(old.relative_to(root))
            if relative not in expected_paths:
                legacy = _inside(root, 'legacy/vulnerabilities/' + old.stem + '-' + hashlib.sha256(old.read_bytes()).hexdigest() + '.md')
                legacy.parent.mkdir(parents=True, exist_ok=True)
                if legacy.exists():
                    if legacy.read_bytes() != old.read_bytes():
                        raise ValueError('Historical author file collision')
                    old.unlink()
                else:
                    old.rename(legacy)
    return index


def _material_suffix_index(materials):
    """Every path suffix of every material, so a citation can be resolved by any tail."""
    index = {}
    for material in materials.values():
        parts = material['path'].split('/')
        for start in range(len(parts)):
            index.setdefault(tuple(parts[start:]), []).append(material)
    return index


def _resolve_citation(path, index):
    """Shortest unambiguous tail wins; an ambiguous or unknown path resolves to nothing.

    Neither end of the path works alone. Authors prefix with the target alias
    (`agentcore/agents/...`) while material paths are target-relative, so the full
    string misses; and a target shipping 267 packages has many files called
    `SKILL.md` or `config.yaml`, so the basename picks the wrong one. Guessing is
    worse than skipping: a wrong material yields a confident, false line count.
    """
    parts = path.split('/')
    for start in range(len(parts)):
        hits = index.get(tuple(parts[start:]))
        if hits:
            return hits[0] if len(hits) == 1 else None
    return None


def _authored_code_errors(relative, body, task, state):
    """A report a developer cannot act on passes every other check in this file.

    Three structural floors: an excerpt exists, every cited line range really is in
    that file, and every member is anchored to at least one of its own evidence
    locators. The middle one is what "不编造源码行号" means mechanically; the last
    one keeps the page tied to the audited record.

    What it deliberately does NOT require is that every citation sit inside a
    locator. Measured on two independently written pages: 20 of 44 citations fell
    outside the record because the author had read adjacent code to explain the
    mechanism, and all 20 were accurate. Rejecting those would block the better
    report to catch a rarer error, and would make the template's own demand for
    code locations nearly unsatisfiable.
    """
    problems = []
    if '```' not in body:
        problems.append(relative + ': no code excerpt; quote the offending lines')
    evidence = {row['id']: row for row in state.get('evidence', [])}
    materials = state.get('materials', {})
    findings = {row['id']: row for row in state.get('findings', [])}
    index = _material_suffix_index(materials)
    roots = {row['id']: row['path'] for row in state.get('targets', [])}
    counted = {}

    def physical_lines(material):
        if material['id'] not in counted:
            try:
                from materials import physical_line_count
                counted[material['id']] = physical_line_count(
                    Path(roots.get(material['target_id'], '')) / material['path'],
                    material.get('encoding'))
            except (ImportError, OSError, ValueError, UnicodeDecodeError):
                counted[material['id']] = None
        return counted[material['id']]

    cited = []
    for path, first, last in re.findall(
            r'([A-Za-z0-9_./*-]+\.[A-Za-z][A-Za-z0-9]{0,15}):(\d+)(?:-(\d+))?', body):
        first, last = int(first), int(last or first)
        material = _resolve_citation(path, index)
        if material is None:
            continue
        total = physical_lines(material)
        if total is not None and last > total:
            problems.append('%s: cited %s:%d-%d runs past the file (%d lines)'
                            % (relative, path, first, last, total))
        else:
            cited.append((material['path'], first, last))
    for fid in task['finding_ids']:
        spans, names = [], set()
        for eid in findings.get(fid, {}).get('evidence_ids', []):
            row = evidence.get(eid)
            material = materials.get((row or {}).get('material_id'))
            lines = (row.get('locator') or {}).get('lines') if row else None
            if material:
                names.add(material['path'].rsplit('/', 1)[-1])
            if material and lines:
                spans.append((material['path'], lines[0], lines[1]))
        if spans:
            if not any(path == known and start <= first and last <= end
                       for known, start, end in spans for path, first, last in cited):
                problems.append(relative + ': member ' + fid
                                + ' has no citation inside its own evidence')
        elif names and not any(name in body for name in names):
            # No line span to anchor to: the evidence is section-form (oversized
            # bundles, .pyc), which is the record's shape and not the author's doing.
            # Skipping quietly would read exactly like a member that passed —
            # measured, 5 of 42 members on a real export were never checked at all —
            # so the weaker but reachable requirement applies instead: name the file.
            problems.append(relative + ': member ' + fid
                            + ' names none of its own materials')
    return problems


def _prose(text):
    lines, fence = [], None
    for line in text.splitlines():
        match = re.match(r'^\s*(`{3,}|~{3,})', line)
        if match:
            token = match.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return '\n'.join(lines)


def _headings(text):
    return re.findall(r'^## (.+)$', _prose(text), re.M)


def _check_links(root, path, text):
    errors = []
    for target in re.findall(r'\[[^\]\n]*\]\(([^\s)]+)\)', _prose(text)):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc:
            continue
        relative = (Path(path).parent / unquote(parsed.path)) if parsed.path else Path(path)
        # ../ is necessary from vulnerabilities/ to records/, but the resolved path
        # must still be in report/, and each traversed component must be a real file.
        resolved = (root / relative).resolve()
        try:
            inside = resolved.relative_to(root.resolve())
            destination = _inside(root, inside)
        except ValueError:
            errors.append('%s: link leaves report/: %s' % (path, target)); continue
        if not destination.is_file():
            errors.append('%s: missing link target %s' % (path, target)); continue
        if parsed.fragment:
            body = destination.read_text(encoding='utf-8')
            anchor = unquote(parsed.fragment)
            if ('id="' + anchor + '"') not in body:
                errors.append('%s: missing explicit anchor %s' % (path, target))
    return errors


def _summary_errors(state, meta, body, view):
    """Check real summary landings, not a copied list of raw findings."""
    errors = []
    entries = meta.get('summary_entries', [])
    if not isinstance(entries, list):
        return ['summary_entries 必须为数组']
    high = {v['id']: v for v in view['high_vulnerabilities']}
    groups = {g['id']: g for g in view['groups']}
    by_id, covered = {}, []
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'id', 'report_id', 'vulnerability_ids'}:
            errors.append('summary_entries 字段必须为 id/report_id/vulnerability_ids'); continue
        eid = item['id']
        try:
            _safe_id(eid)
        except ValueError:
            errors.append('summary entry ID 非法'); continue
        if eid in by_id:
            errors.append('summary entry ID 重复')
        by_id[eid] = item
        vids = item['vulnerability_ids']
        if not isinstance(vids, list) or not vids or any(not isinstance(v, str) or v not in high for v in vids):
            errors.append('summary entry 必须引用有效严重缺陷'); continue
        covered.extend(vids)
        group = groups.get(item['report_id'])
        if not group or not set(vids) <= set(group['vulnerability_ids']):
            errors.append('summary entry 与主报告归属不一致')
    if set(covered) != set(high) or any(n != 1 for n in Counter(covered).values()):
        errors.append('summary 严重问题覆盖缺失或重复')
    prose = _prose(body)
    middle = prose.split('## ' + SUMMARY_HEADINGS[1], 1)[-1].split('## ' + SUMMARY_HEADINGS[2], 1)[0]
    rows = []
    for line in middle.splitlines():
        if not line.startswith('|'):
            continue
        cells = re.split(r'(?<!\\)\|', line)[1:-1]
        if len(cells) != 4:
            errors.append('summary 严重问题表必须有四列'); continue
        first = cells[0].strip()
        if first in {'问题', '---', ':---', '---:'}:
            continue
        match = re.fullmatch(r'<a id="([A-Za-z0-9_.-]+)"></a>\s*\[[^\]]+\]\(([^)]+)\)', first)
        if not match:
            errors.append('summary 严重问题行需要实际 entry 锚点与报告链接'); continue
        eid, target = match.groups()
        rows.append(eid)
        entry = by_id.get(eid)
        if not entry:
            errors.append('summary 正文含未登记问题行'); continue
        vids = entry['vulnerability_ids']
        if not isinstance(vids, list) or any(v not in high for v in vids):
            continue
        grades = sorted({high[v]['severity'] for v in vids}, key=SEVERITIES.index)
        if cells[1].strip().lower().replace(' ', '') != '/'.join(grades):
            errors.append('summary 等级集合与路径来源不符：' + eid)
        if not cells[2].strip() or not cells[3].strip():
            errors.append('summary 原理或影响缺失：' + eid)
        group = groups.get(entry['report_id'])
        if group and target.split('#', 1)[0] != group['path']:
            errors.append('summary 链接不是该问题的主报告：' + eid)
    if set(rows) != set(by_id) or any(n != 1 for n in Counter(rows).values()):
        errors.append('summary 实际严重问题行缺失或重复')
    for fid, row in view['finding_map'].items():
        if row.get('path') == 'summary.md#' + fid and ('<a id="' + fid + '"></a>') not in prose:
            errors.append('summary 严重非独立项缺少说明落点：' + fid)
    for scene in view['scenarios']:
        if prose.count('<a id="' + scene['id'] + '"></a>') != 1:
            errors.append('summary 场景落点缺失或重复：' + scene['id'])
    chains = {c['id']: c for c in state.get('chains', [])}
    dispositions = meta.get('chain_dispositions', {})
    if not isinstance(dispositions, dict) or set(dispositions) != set(chains):
        errors.append('summary 链证据状态必须覆盖全部登记链')
        dispositions = dispositions if isinstance(dispositions, dict) else {}
    for cid, chain in chains.items():
        value = dispositions.get(cid)
        if value not in {'static_trace', 'partial', 'needs_evidence'}:
            errors.append('summary 链证据状态无效：' + cid)
        if chain.get('status') == 'candidate' and value not in {'partial', 'needs_evidence'}:
            errors.append('summary 候选链被升级：' + cid)
    return errors


def validate_package(workspace, state):
    """Read-only structural closure; cannot certify prose quality or exploitability."""
    try:
        return _validate_package(Path(workspace), state)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        return ['Report validation could not read the package: %s: %s' % (type(exc).__name__, exc)]


def _validate_package(workspace, state):
    root = _inside(workspace, 'report')
    index_path = _inside(root, 'index.json')
    if not index_path.is_file():
        return ['Missing report/index.json; export report materials first']
    index = load_index(workspace)
    errors = []
    if index.get('version') != VERSION or index.get('source_digest') != source_digest(state):
        errors.append('Report material index is stale or has an unsupported version')
    wanted_high = [{'id': f['id'], 'severity': f['severity'], 'exposure': f.get('exposure')}
                   for f in high_findings(state)]
    if index.get('high_findings') != wanted_high:
        errors.append('Indexed high findings differ from the audit record')
    wanted_ext = [{'id': c['id'], 'title': c['title'], 'status': c.get('status')}
                  for c in state.get('chains', []) if c.get('entry_exposure') == 'EXT']
    if index.get('ext_chains') != wanted_ext:
        errors.append('Indexed EXT chains differ from the audit record')
    tasks = build_tasks(state)
    from report_plan import build_report_view
    view = build_report_view(state, index.get('locations'))
    errors.extend(view['errors'])
    for key in ('high_vulnerabilities', 'scenarios', 'chain_locations'):
        if index.get(key) != view[key]:
            errors.append('Report organization differs: ' + key)
    if index.get('finding_map') != view['finding_map'] or index.get('attribution_pending') != view['pending']:
        errors.append('Finding presentation mapping differs from attribution')
    current = [f for f in state.get('findings', []) if f.get('status') == 'current']
    wanted_statistics = {
        'finding_status': dict(Counter(f.get('status') for f in state.get('findings', []))),
        'current_severity': dict(Counter(f['severity'] for f in current)),
        'current_exposure': dict(Counter(f.get('exposure') or 'unknown' for f in current)),
        'checks': len(state.get('checks', [])), 'reviews': len(state.get('reviews', [])),
        'materials': len(state.get('materials', {})), 'report_tasks': len(tasks),
        'attribution': view['statistics']}
    if index.get('statistics') != wanted_statistics:
        errors.append('Indexed statistics differ from the audit record')
    expected = {t['id']: t for t in tasks}
    observed = {t['id']: t for t in index.get('tasks', [])}
    if set(expected) != set(observed) or len(observed) != len(index.get('tasks', [])):
        errors.append('Report task IDs do not match current findings/root causes')
    for rid, task in expected.items():
        if any(observed.get(rid, {}).get(k) != task[k]
               for k in ('path', 'finding_ids', 'root_cause_id', 'vulnerability_ids', 'source_digest')):
            errors.append('Report task mapping is stale: ' + rid)
    for category, catalog in index.get('catalog', {}).items():
        for chunk in catalog['files']:
            p = _inside(root, chunk['path'])
            if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != chunk['sha256']:
                errors.append('Material shard is missing or changed: ' + chunk['path'])
    # Reconcile the inventory against the state, not just against its own hashes.
    for category, rows in _record_groups(state):
        wanted = {rid for rid, _, _ in rows}
        expected_aliases = {}
        for rid, row, _ in rows:
            if isinstance(row, dict) and row.get('id') and str(row['id']) != rid:
                expected_aliases.setdefault(str(row['id']), []).append(rid)
        if index.get('aliases', {}).get(category, {}) != expected_aliases:
            errors.append('Historical record aliases differ: ' + category)
        if set(index.get('locations', {}).get(category, {})) != wanted:
            errors.append('Material record IDs missing or extra: ' + category)
        declared = [rid for chunk in index.get('catalog', {}).get(category, {}).get('files', [])
                    for rid in chunk.get('ids', [])]
        if set(declared) != wanted or len(declared) != len(wanted):
            errors.append('Material shard inventory differs: ' + category)
        for chunk in index.get('catalog', {}).get(category, {}).get('files', []):
            for rid in chunk.get('ids', []):
                if index.get('locations', {}).get(category, {}).get(rid) != chunk['path'] + '#' + _anchor_id(rid):
                    errors.append('Material locator differs: ' + category + '/' + rid)
    covered_todos = set()
    authored = [('summary.md', None)] + [(t['path'], t) for t in tasks]
    for relative, task in authored:
        errors.extend(_handoff_errors(root, task['id'] if task else 'summary',
                                      task['source_digest'] if task else source_digest(state), state))
        p = _inside(root, relative)
        if not p.is_file():
            errors.append('Missing authored report: ' + relative); continue
        body = p.read_text(encoding='utf-8')
        try:
            meta = read_meta(body)
        except (ValueError, TypeError) as exc:
            errors.append(relative + ': ' + str(exc)); continue
        kind = 'vulnerability' if task else 'summary'
        if meta.get('type') != kind:
            errors.append(relative + ': incorrect report type')
        digest = task['source_digest'] if task else source_digest(state)
        if meta.get('source_digest') != digest:
            errors.append(relative + ': authored report is stale')
        headings = VULNERABILITY_HEADINGS if task else SUMMARY_HEADINGS
        if _headings(body) != list(headings):
            errors.append(relative + ': template sections differ or are out of order')
        if re.search(r'\{\{[^{}\n]+\}\}', _prose(body)):
            errors.append(relative + ': unfilled template placeholder')
        covered_todos.update(meta.get('todo_ids', []))
        errors.extend(_check_links(root, relative, body))
        if task:
            if (sorted(meta.get('finding_ids', [])) != task['finding_ids']
                    or meta.get('root_cause_id') != task['root_cause_id']
                    or meta.get('report_id') != task['id']
                    or sorted(meta.get('vulnerability_ids', [])) != sorted(task['vulnerability_ids'])):
                errors.append(relative + ': source finding/root-cause mapping differs')
            for fid in task['finding_ids']:
                if ('<a id="' + fid + '"></a>') not in body:
                    errors.append(relative + ': member anchor missing: ' + fid)
            for cid, place in view['chain_locations'].items():
                if place['kind'] == 'report' and place['target_id'] == task['id'] and ('<a id="' + cid + '"></a>') not in body:
                    errors.append(relative + ': chain anchor missing: ' + cid)
            errors.extend(_authored_code_errors(relative, body, task, state))
            continue
        errors.extend(_summary_errors(state, meta, body, view))
    expected_paths = {t['path'] for t in tasks}
    if (root / 'vulnerabilities').exists():
        actual_paths = {str(p.relative_to(root)) for p in (root / 'vulnerabilities').rglob('*.md')}
        if actual_paths - expected_paths:
            errors.append('Unexpected vulnerability reports; archive obsolete drafts outside vulnerabilities/')
    required_todos = {t['id'] for t in state.get('report_todos', []) if t.get('status') == 'applied'}
    if required_todos - covered_todos:
        errors.append('Report todo presentation mappings missing: ' + ', '.join(sorted(required_todos - covered_todos)))
    return errors


def finalize_package(workspace, state):
    errors = validate_package(workspace, state)
    if errors:
        return {'valid': False, 'errors': errors}
    root = Path(workspace) / 'report'
    index = load_index(workspace)
    index['summary_status'] = 'checked'
    index['summary_sha256'] = hashlib.sha256((root / 'summary.md').read_bytes()).hexdigest()
    for task in index['tasks']:
        task['writing_status'] = 'checked'
        task['sha256'] = hashlib.sha256((root / task['path']).read_bytes()).hexdigest()
    stored_index, metadata = _pack_index(index)
    for relative, body in metadata.items():
        _atomic_text(_inside(root, relative), body)
    _atomic_text(root / 'index.json', json.dumps(stored_index, ensure_ascii=False, indent=2) + '\n')
    notes = root / 'notes'
    return {'valid': True, 'errors': [], 'reports': len(index['tasks']),
            'high_findings': len(index['high_findings']), 'ext_chains': len(index['ext_chains']),
            'notes': sorted(str(p.relative_to(root)) for p in notes.glob('*.md'))
                     if notes.is_dir() else []}
