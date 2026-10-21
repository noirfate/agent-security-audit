#!/usr/bin/env python3
"""Partition the declared materials into audit units. Mechanical recall only.

Every number here is produced from the recorded material index, so two independent
counts can be compared. Nothing in this module decides whether a directory is out of
scope, which member represents a cluster, how deep a unit should be audited, or what
an instance maps to: those answers are not determined by the files alone, so they are
left as pending decisions for the auditor to resolve before the queue can be frozen.
"""
import copy
import hashlib
import json
import os
import re
from pathlib import Path

KINDS = ('repo_shard', 'artifact', 'cross', 'residual')
EXPOSURES = ('EXT', 'ADJ', 'INT', 'unknown')
DEPTHS = ('triage', 'standard', 'deep')
# `redo` is gone with the verdict of that name: a correction is made in place by the
# reviewer and logged, so a unit never goes back to "needs redoing" as a state.
STATUSES = ('planned', 'dispatched', 'returned', 'merged', 'reviewed')
CROSS_TYPES = ('joint', 'chain', 'goal', 'xartifact')
DIMENSIONS = ('bidirectional', 'control_efficacy', 'trust_model',
              'lateral', 'capability_combo', 'asset_goal')
DIMENSION_STATES = ('pending', 'done', 'na')
PRIMITIVES = ('INJECT', 'PERSIST', 'EXFIL', 'EXEC', 'READ',
              'IMPERSONATE', 'APPROVE_BYPASS', 'ESCAPE', 'DOWNGRADE')
DECISION_KINDS = ('out_of_scope_candidate', 'cluster_representative', 'depth',
                  'cross_cutting_objects', 'partition', 'cross_scope',
                  'exposure', 'object_mapping', 'unassigned_material', 'oversized_unit',
                  'object_scope')

# Collection -> record id prefix. A unit's products must use these prefixes plus the
# unit token, so two workers running at once cannot allocate the same id.
PREFIXES = {'instances': 'INST', 'connections': 'CONN', 'assets': 'AST',
            'attackers': 'ATK', 'controls': 'CTL', 'hypotheses': 'HYP',
            'evidence': 'E', 'checks': 'CHK', 'findings': 'F', 'dismissed_candidates': 'F', 'coverage': 'COV',
            'primitives': 'PRIM'}

LIMITS = {'hits': 120, 'bytes_low': 60 * 1024, 'bytes_high': 120 * 1024, 'units': 24}

# Directory names that are usually dependencies or build output. They are candidates
# for exclusion, never excluded here: the skill's own rule is that artefacts which get
# loaded at runtime do live in such directories, so only the auditor may rule them out.
DEPENDENCY_DIR_NAMES = ('node_modules', 'vendor', 'site-packages', 'dist', 'build',
                        'target', '.venv', 'venv', '__pycache__', '.tox', 'bower_components')

# Two kinds of marker, and the difference decides the unit kind. A capability marker
# declares what the thing may do, so its directory is an artefact: one MCP server, one
# skill package, one plugin, and its declaration can be checked against its code. A build
# manifest only declares how to compile, so on its own it marks a natural shard boundary.
#
# A build manifest makes an artefact only when the manifests are independent packages
# rather than members of one workspace, and the structural signal for that is the target
# root: a workspace carries a manifest at its root, a pile of packages does not. Without
# this split a 38-crate Rust workspace comes out as 38 "artefacts" each wanting a triage
# depth, while a directory of a hundred MCP packages comes out as one.
CAPABILITY_MARKERS = ('SKILL.md', 'AGENTS.md', 'mcp.json', '.mcp.json', 'server.json')
BUILD_MARKERS = ('package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod')
ARTIFACT_MARKERS = CAPABILITY_MARKERS + BUILD_MARKERS

SHINGLE_BYTES = 262144
SKETCH_K = 64
# Below this many shingles the estimator is noise, so similarity is not used at all and
# only an identical fingerprint clusters two artefacts. A script that guesses here would
# merge packages that only look alike, and a merged cluster is audited once.
SKETCH_MIN = 20


def unit_token(unit_id):
    """`U-SH01` -> `SH01`. The token is what record ids carry."""
    token = unit_id[2:] if unit_id.startswith('U-') else unit_id
    if not re.fullmatch(r'[A-Z]{2}[0-9]{2,4}', token):
        raise ValueError('Unit id must look like U-SH01: ' + unit_id)
    return token


def allocate(prefix, token, existing, width=3):
    """Next free `<prefix>-<token>-<n>` id. Ids are unique per unit by construction."""
    taken = set(existing)
    number = 1
    while True:
        candidate = '%s-%s-%0*d' % (prefix, token, width, number)
        if candidate not in taken:
            return candidate
        number += 1


def id_owner(record_id):
    """Unit token embedded in a record id, or None for workspace-level ids."""
    match = re.fullmatch(r'[A-Z]+-([A-Z]{2}[0-9]{2,4})-[0-9]+', record_id or '')
    return match.group(1) if match else None


def new_unit(uid, kind, title, **extra):
    if kind not in KINDS:
        raise ValueError('Unknown unit kind: ' + str(kind))
    unit = {
        'id': uid, 'kind': kind, 'title': title,
        'target_ids': [], 'material_ids': [], 'object_ids': [], 'mapping_note': '',
        'exposure': 'unknown', 'exposure_reason': '',
        'depth': None, 'depth_reason': '',
        'cluster_id': None,
        'phase': 2, 'cross_type': None, 'seed': {}, 'round': None, 'status': 'planned',
        'file_count': 0, 'byte_count': 0, 'text_count': 0, 'opaque_count': 0,
        'surface_hits': None, 'surface_matches': None, 'blind_languages': {},
        'split_from': None, 'merged_from': [],
        'progress': {'files_done': 0, 'hits_disposed': 0},
        'dimensions': {d: {'state': 'pending', 'reason': ''} for d in DIMENSIONS},
        'partial_sha256': None, 'merged_at': None,
    }
    unit.update(extra)
    return unit


def present(state):
    return {mid: row for mid, row in state['materials'].items() if row['status'] == 'present'}


def census(state):
    """Recount from the material index. The stored copy lives in state['queue']['census']."""
    rows = present(state)
    assigned = [mid for unit in state.get('units', []) for mid in unit['material_ids']]
    return {'enumerated': len(rows), 'out_of_scope': len(state['inventory_exclusions']),
            'in_units': len(set(assigned)), 'assignments': len(assigned),
            'unit_file_count_sum': sum(u['file_count'] for u in state.get('units', []))}


def partition_errors(state):
    """The three assertions. Both sides of each are counted independently."""
    errors = []
    units = [u for u in state.get('units', []) if u['kind'] != 'cross']
    rows = present(state)
    seen, twice = set(), set()
    for unit in units:
        for mid in unit['material_ids']:
            if mid in seen:
                twice.add(mid)
            seen.add(mid)
            if mid not in rows:
                errors.append('%s: material not present in the index: %s' % (unit['id'], mid))
    orphans = sorted(set(rows) - seen)
    if orphans:
        errors.append('%d present materials belong to no unit, first: %s'
                      % (len(orphans), ', '.join(orphans[:5])))
    if twice:
        errors.append('%d materials belong to more than one unit, first: %s'
                      % (len(twice), ', '.join(sorted(twice)[:5])))
    stored = sum(u['file_count'] for u in units)
    if units and stored != len(rows):
        errors.append('unit file_count sum %d != present materials %d' % (stored, len(rows)))
    for unit in state.get('units', []):
        if unit['kind'] == 'cross':
            if unit['material_ids']:
                errors.append(unit['id'] + ': a cross unit owns no materials')
            if unit.get('cross_type') not in CROSS_TYPES:
                errors.append(unit['id'] + ': cross unit needs a cross_type')
        elif not unit['material_ids']:
            errors.append(unit['id'] + ': empty unit')
    return errors


# ── candidate grouping ───────────────────────────────────────────────────────────
def _segments(path):
    return path.split('/')


def _artifact_roots(rows, max_depth):
    """Shallowest directories carrying a marker file, dependency dirs not considered."""
    roots, workspace_roots = set(), set()
    for row in rows.values():
        parts = _segments(row['path'])
        if any(p in DEPENDENCY_DIR_NAMES for p in parts[:-1]):
            continue
        if parts[-1] in BUILD_MARKERS and len(parts) == 1:
            workspace_roots.add(row['target_id'])
        if parts[-1] in ARTIFACT_MARKERS and len(parts) - 1 <= max_depth:
            if parts[-1] in BUILD_MARKERS and row['target_id'] in workspace_roots and len(parts) > 1:
                continue                  # a workspace member, not a package of its own
            roots.add((row['target_id'], '/'.join(parts[:-1])))
    # The target may be enumerated in any order, so re-apply the workspace rule once the
    # root manifest is known rather than relying on having seen it first.
    roots = {(t, d) for t, d in roots
             if not (t in workspace_roots and d != ''
                     and _segments(d + '/x')[-2] and not _has_capability(rows, t, d))}
    # A marker at the target root with markers below it is a workspace manifest, not a
    # package: treating it as one artefact would swallow the whole repo into a single
    # unit. Drop it and keep the packages below, which is what a pile of artefacts is.
    kept = {(t, d) for t, d in roots
            if d != '' or not any(o == t and e != '' for o, e in roots)}
    out = set()
    for target, directory in sorted(kept):
        inside_another = any(target == t and directory != d
                             and (d == '' or directory.startswith(d + '/'))
                             for t, d in kept)
        if not inside_another:
            out.add((target, directory))
    return out


def _has_capability(rows, target, directory):
    prefix = (directory + '/') if directory else ''
    return any(row['target_id'] == target and row['path'].startswith(prefix)
               and _segments(row['path'])[-1] in CAPABILITY_MARKERS
               and '/'.join(_segments(row['path'])[:-1]) == directory
               for row in rows.values())


def _group_key(row, roots, depth):
    target, path = row['target_id'], row['path']
    parts = _segments(path)
    for i in range(len(parts) - 1, -1, -1):
        candidate = '/'.join(parts[:i])
        if (target, candidate) in roots:
            return ('artifact', target, candidate)
    head = '/'.join(parts[:depth]) if len(parts) > depth else '(root)'
    return ('shard', target, head)


def plan_census(workspace, state, depth=1, artifact_depth=2, rebuild=False):
    """Write candidate units and the decisions that only the auditor can make."""
    from audit import save
    if state.get('queue', {}).get('phase1_frozen') is not None:
        raise ValueError('Stage 1 queue is frozen; units may not be re-planned in this audit')
    # Re-planning rebuilds every unit from the directory shape, so it silently discards
    # `--split` results — and the protocol used to tell the auditor to re-run `plan` to
    # make a decision "disappear", which would have thrown the splitting away. Splits are
    # a deliberate decision; losing them has to be asked for.
    if any(u.get('status') != 'planned' or u.get('partial_sha256')
           or (Path(workspace) / 'units' / u['id'] / 'partial.json').exists()
           for u in state.get('units', [])):
        raise ValueError('Existing work cannot be discarded by plan; use a new workspace')
    if state.get('queue', {}).get('partition_confirmed') and not rebuild:
        raise ValueError('Confirmed partition exists; use plan --apply or explicit --rebuild')
    split = sorted(u['id'] for u in state.get('units', []) if u.get('split_from'))
    if split and not rebuild:
        raise ValueError('%d 个单元是 --split 拆出来的（%s…）；重跑 plan 会按目录形状重建'
                         '全部单元、把拆分结果丢掉。确实要从头划分就加 --rebuild，'
                         '否则继续用 --split 细化'
                         % (len(split), '、'.join(split[:3])))
    rows = present(state)
    if not rows:
        raise ValueError('No present materials; run refresh before planning')
    roots = _artifact_roots(rows, artifact_depth)
    groups = {}
    for mid, row in sorted(rows.items(), key=lambda kv: (kv[1]['target_id'], kv[1]['path'])):
        groups.setdefault(_group_key(row, roots, depth), []).append(mid)
    old_units = {u['id']: u for u in state.get('units', [])}
    retired = set(state.get('retired_unit_ids') or [])
    taken = set(old_units) | retired
    units, counters = [], {'SH': 0, 'AR': 0, 'RS': 0}
    for key in sorted(groups):
        kind, target, head = key
        members = groups[key]
        if kind == 'artifact':
            prefix, unit_kind = 'AR', 'artifact'
        elif head == '(root)' and len(groups) > 1:
            prefix, unit_kind = 'RS', 'residual'
        else:
            prefix, unit_kind = 'SH', 'repo_shard'
        previous = next((u for u in old_units.values()
                         if u['kind'] == unit_kind and set(u['material_ids']) == set(members)), None)
        counters[prefix] += 1
        uid = 'U-%s%02d' % (prefix, counters[prefix])
        while uid in taken and (previous is None or uid != previous['id']):
            counters[prefix] += 1
            uid = 'U-%s%02d' % (prefix, counters[prefix])
        uid = previous['id'] if previous else uid
        taken.add(uid)
        unit = new_unit(uid, unit_kind, '%s:%s' % (target, head or '(target root)'),
                        target_ids=[target], material_ids=members)
        if previous:
            unit = copy.deepcopy(previous)
        unit['file_count'] = len(members)
        unit['byte_count'] = sum(rows[m]['size'] or 0 for m in members)
        unit['text_count'] = sum(rows[m].get('visibility') == 'text' for m in members)
        unit['opaque_count'] = unit['file_count'] - unit['text_count']
        units.append(unit)
    state['retired_unit_ids'] = sorted(retired | (set(old_units) - {u['id'] for u in units}))
    state['units'] = units
    valid_subjects = {u['id'] for u in units}
    state['pending_decisions'] = [d for d in state.get('pending_decisions', [])
        if d.get('kind') not in ('object_mapping','exposure','depth') or d.get('subject') in valid_subjects]
    # Keep slices only for stable unit IDs; removed boundaries cannot retain locations.
    stale = Path(workspace) / 'surface'
    if stale.is_dir():
        for path in sorted(stale.glob('*.json')) + sorted(stale.glob('_summary.md')):
            if path.name == '_summary.md' or path.stem not in {u['id'] for u in units}:
                path.unlink()
    state.setdefault('queue', {})
    state['queue'].update({
        'phase1_frozen': None, 'phase2_rows_frozen': None, 'phase3_rows_frozen': None,
        'phase3_critic': None, 'partition_confirmed': False,
        'partition_reason': '', 'cross_scope': {},
        'census': census(state),
    })
    state['pending_decisions'] = pending_decisions(workspace, state, rows)
    save(workspace, state)
    return {'units': len(units), 'census': state['queue']['census'],
            'base_plan_sha256': plan_digest(state), 'draft': plan_template(state),
            'pending_decisions': len(state['pending_decisions']),
            'oversized': [u['id'] for u in units if u['byte_count'] > LIMITS['bytes_high']],
            'note': '这是候选划分，不是结论：先逐条处置 pending_decisions，再 plan --freeze'}


def plan_digest(state):
    """Optimistic concurrency token for the entire partition and its source materials."""
    payload = {key: state.get(key) for key in
               ('materials', 'units', 'inventory_exclusions', 'retired_unit_ids', 'clusters')}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def plan_template(state):
    return {'base_plan_sha256': plan_digest(state), 'reason': '', 'units': [
        {key: copy.deepcopy(u[key]) for key in ('id', 'kind', 'title', 'material_ids')}
        for u in state.get('units', []) if u['kind'] != 'cross']}


def apply_plan(workspace, state, payload):
    """Apply explicit model boundaries; validate completely before a single save."""
    from audit import save
    if (not isinstance(payload, dict) or not isinstance(payload.get('reason'), str)
            or not payload['reason'].strip()):
        raise ValueError('plan --apply needs a reason and explicit units')
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    last = (state.get('queue') or {}).get('last_plan_apply') or {}
    if (last.get('input_sha256') == digest and last.get('result_sha256') == plan_digest(state)
            and state.get('queue', {}).get('partition_confirmed')):
        return {'applied': False, 'unchanged': True, 'base_plan_sha256': plan_digest(state)}
    if state.get('queue', {}).get('phase1_frozen') is not None:
        raise ValueError('Phase 1 is frozen; cannot change partition')
    if payload.get('base_plan_sha256') != plan_digest(state):
        raise ValueError('Stale base_plan_sha256; read the current plan before applying')
    if not isinstance(payload.get('units'), list) or not payload['units']:
        raise ValueError('plan.units must be a nonempty list')
    working = copy.deepcopy(state)
    old = {u['id']: u for u in working.get('units', [])}
    retired = set(working.get('retired_unit_ids', []))
    rows = present(working)
    made, seen = [], set()
    allowed = {'id', 'kind', 'title', 'material_ids', 'object_ids', 'mapping_note',
               'mapping_reason', 'exposure', 'exposure_reason', 'depth', 'depth_reason'}
    for item in payload['units']:
        if not isinstance(item, dict) or set(item) - allowed:
            raise ValueError('Unknown or malformed plan unit fields')
        uid = item.get('id')
        if not isinstance(uid, str):
            raise ValueError('Each unit needs an id')
        unit_token(uid)
        if uid in seen or uid in retired:
            raise ValueError('Duplicate or retired unit id: ' + uid)
        seen.add(uid)
        members = item.get('material_ids')
        if not isinstance(members, list) or not members or any(not isinstance(m, str) or m not in rows for m in members):
            raise ValueError(uid + ': material_ids must reference present materials')
        if len(members) != len(set(members)):
            raise ValueError(uid + ': duplicate material assignment')
        if (item.get('kind') not in KINDS or item['kind'] == 'cross'
                or not isinstance(item.get('title'), str) or not item['title'].strip()):
            raise ValueError(uid + ': explicit non-cross kind and title required')
        previous = old.get(uid)
        if previous and (set(previous['material_ids']) != set(members) or previous['kind'] != item['kind']):
            raise ValueError(uid + ': changed boundary requires a fresh unit id')
        if previous:
            unit = copy.deepcopy(previous)
            has_work = unit.get('status') != 'planned' or (Path(workspace) / 'units' / uid / 'partial.json').exists()
            if has_work and any(unit.get(k) != v for k, v in item.items() if k != 'material_ids'):
                raise ValueError(uid + ': cannot rewrite a unit with existing work')
            unit.update(copy.deepcopy(item))
        else:
            unit = new_unit(uid, item['kind'], item['title'])
            unit.update(copy.deepcopy(item))
        unit.update(target_ids=sorted({rows[m]['target_id'] for m in members}),
                    file_count=len(members), byte_count=sum(rows[m]['size'] or 0 for m in members),
                    text_count=sum(rows[m].get('visibility') == 'text' for m in members))
        unit['opaque_count'] = unit['file_count'] - unit['text_count']
        made.append(unit)
    removed = set(old) - seen
    for uid in removed:
        if (old[uid].get('status') != 'planned' or old[uid].get('partial_sha256') or old[uid].get('cluster_id')
                or (Path(workspace) / 'units' / uid / 'partial.json').exists()):
            raise ValueError(uid + ': existing work/cluster cannot be silently discarded')
    working['units'] = made
    working['retired_unit_ids'] = sorted(retired | removed)
    errors = partition_errors(working)
    if errors:
        raise ValueError('; '.join(errors))
    # Validate explicit semantic fields structurally; the model owns their meaning.
    known = set(_framework_object_ids(workspace, working))
    for u in made:
        if not isinstance(u['object_ids'], list) or any(oid not in known for oid in u['object_ids']):
            raise ValueError(u['id'] + ': unknown object_ids')
        if u['exposure'] not in EXPOSURES or (u['exposure'] != 'unknown' and not u.get('exposure_reason')):
            raise ValueError(u['id'] + ': invalid exposure or missing reason')
        if u['depth'] is not None and (u['depth'] not in DEPTHS or not u.get('depth_reason')):
            raise ValueError(u['id'] + ': invalid depth or missing reason')
    queue = working.setdefault('queue', {})
    queue.update(partition_confirmed=True, partition_reason=payload['reason'], census=census(working))
    working['pending_decisions'] = pending_decisions(workspace, working)
    queue['last_plan_apply'] = {'input_sha256': digest, 'result_sha256': plan_digest(working)}
    save(workspace, working)
    state.clear()
    state.update(working)
    return {'applied': True, 'units': len(made), 'retired': sorted(removed),
            'base_plan_sha256': plan_digest(state)}


def split_unit(workspace, state, unit_id, by='directory'):
    """Cut one oversized unit along directory boundaries, or by file when it is flat.

    A flat directory of dozens of files is the normal case, not an accident: the
    business entry points and the hits both concentrate there, and no sub-directory
    boundary exists to cut on. So `by=file` is a first-class option rather than a
    fallback to apologise for. The partition is preserved either way: every material
    of the old unit lands in exactly one new unit.
    """
    from audit import save
    if state.get('queue', {}).get('phase1_frozen') is not None:
        raise ValueError('Stage 1 queue is frozen; a unit may not be split in this audit')
    units = {u['id']: u for u in state['units']}
    unit = units.get(unit_id)
    if unit is None:
        raise ValueError('Unknown unit: ' + unit_id)
    if unit['kind'] == 'cross':
        raise ValueError('A cross unit owns no materials to split')
    if (unit.get('status') != 'planned' or unit.get('partial_sha256')
            or (Path(workspace) / 'units' / unit_id / 'partial.json').exists()):
        raise ValueError('Cannot split a unit with existing work')
    rows = present(state)
    members = sorted(unit['material_ids'], key=lambda m: rows[m]['path'])
    if len(members) < 2:
        raise ValueError(unit_id + ': nothing to split')
    prefix = os.path.commonprefix([rows[m]['path'] for m in members]).rsplit('/', 1)[0]
    groups = {}
    if by == 'directory':
        for mid in members:
            rest = rows[mid]['path'][len(prefix):].lstrip('/')
            groups.setdefault(rest.split('/')[0] if '/' in rest else '(files)', []).append(mid)
    if by == 'file':
        groups = {rows[mid]['path']: [mid] for mid in members}
    elif by != 'directory':
        raise ValueError('Unknown split rule: ' + str(by))
    if len(groups) < 2:
        raise ValueError(unit_id + ': no directory boundary; provide plan --apply or --by file')
    letters = unit_id[2:4]
    # Never reuse a released number. The parent leaves the list as it is split, so a
    # naive "first free" hands its number to an unrelated child later — and decision
    # answers are keyed by (kind, unit id), so the answer silently reattaches to a
    # different directory while `freeze` only checks that *an* answer exists. Observed on
    # a real run: splitting `crates` then `e2e` produced a child named U-SH07, which was
    # `crates`'s number.
    retired = set(state.setdefault('retired_unit_ids', []))
    taken = {u['id'] for u in state['units']} | retired
    made = []
    for name in sorted(groups):
        number = 1
        while 'U-%s%02d' % (letters, number) in taken:
            number += 1
        uid = 'U-%s%02d' % (letters, number)
        taken.add(uid)
        child = new_unit(uid, unit['kind'], '%s / %s' % (unit['title'], name),
                         target_ids=list(unit['target_ids']), material_ids=groups[name],
                         # Changed boundaries need fresh model decisions.
                         split_from=unit_id)
        child['file_count'] = len(groups[name])
        child['byte_count'] = sum(rows[m]['size'] or 0 for m in groups[name])
        child['text_count'] = sum(rows[m].get('visibility') == 'text' for m in groups[name])
        child['opaque_count'] = child['file_count'] - child['text_count']
        state['units'].append(child)
        made.append(uid)
    state['retired_unit_ids'] = sorted(retired | {unit_id})
    state['units'] = [u for u in state['units'] if u['id'] != unit_id]
    stale = Path(workspace) / 'surface' / (unit_id + '.json')
    if stale.is_file():
        stale.unlink()
    state['queue']['census'] = census(state)
    state['queue']['partition_confirmed'] = False
    state['pending_decisions'] = pending_decisions(workspace, state, rows)
    save(workspace, state)
    return {'split': unit_id, 'into': made, 'by': by if len(groups) else 'file',
            'note': '拆分按显式规则完成；请重新确认新单元的语义边界。检索索引可按需重建'}


def _framework_object_names(workspace, state):
    """`{id: 'A1.1 API与消息接口'}` for the pinned baseline, ids alone when unreadable."""
    try:
        from knowledge import baseline_dir, load_bundle, objects
        data, _, _ = load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))
        return {oid: '%s %s' % (oid, row.get('name', ''))
                for oid, row in objects(data).items()}
    except (OSError, ValueError, KeyError):
        return {}


def _framework_object_ids(workspace, state):
    """Every object the pinned baseline defines.

    Read failures propagate on purpose. Returning an empty set instead would make the
    scope decision vacuous — no object would ever be asked about — and that is exactly
    the failure this decision exists to prevent.
    """
    from knowledge import baseline_dir, load_bundle, objects
    data, _, _ = load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))
    return sorted(objects(data))


def pending_decisions(workspace, state, rows=None):
    """Recompute explicit decision questions and preserve answers by kind and subject.

    Optional search counts create no questions. Semantic answers live in durable fields
    as well as this worklist, so recomputing cannot silently erase a model decision.
    """
    rows = rows if rows is not None else present(state)
    answered = {(row.get('kind'), str(row.get('subject'))): row
                for row in state.get('pending_decisions') or []
                if row.get('resolution')}
    out, number = [], 0

    def add(kind, subject, question):
        nonlocal number
        number += 1
        previous = answered.get((kind, str(subject))) or {}
        out.append({'id': 'DEC-%03d' % number, 'kind': kind, 'subject': subject,
                    'question': question,
                    'resolution': previous.get('resolution'),
                    'reason': previous.get('reason', '')})

    queue = state.get('queue') or {}
    if state.get('units') and not queue.get('partition_confirmed') and queue.get('phase1_frozen') is None:
        add('partition', 'queue', '候选目录分组是否符合审计职责边界？模型确认后答 accept 并给理由，或 plan --apply 提交明确划分。')
    if queue.get('phase2_rows_frozen') is not None:
        for cross_type in CROSS_TYPES:
            decision = (queue.get('cross_scope') or {}).get(cross_type) or {}
            if decision.get('decision') not in ('needed', 'not_needed') or not decision.get('reason'):
                add('cross_scope', cross_type, '此类跨单元工作是否需要？答 needed 或 not_needed，并依据当前证据说明理由。')

    directories = {}
    for row in rows.values():
        for i, part in enumerate(_segments(row['path'])[:-1]):
            if part in DEPENDENCY_DIR_NAMES:
                key = (row['target_id'], '/'.join(_segments(row['path'])[:i + 1]))
                directories[key] = directories.get(key, 0) + 1
    for (target, directory), count in sorted(directories.items()):
        add('out_of_scope_candidate', '%s:%s' % (target, directory),
            '%d 个材料在这个依赖或构建目录下。它参与运行时加载吗？范围内就留着并说明，'
            '范围外用 exclusions 写绝对路径并给理由——不按目录名自动排除。' % count)
    for unit in state.get('units', []):
        if unit['kind'] == 'cross':
            continue
        if not unit['object_ids'] and not unit.get('mapping_note'):
            add('object_mapping', unit['id'], '这个单元承担哪些框架对象职责？没有对应对象时写 mapping_note。')
        if unit['exposure'] == 'unknown':
            add('exposure', unit['id'], '这个单元的暴露层级是 EXT / ADJ / INT？按绑定地址、认证默认值与真实入口判，并写理由。')
        if unit['kind'] == 'artifact' and not unit['depth']:
            add('depth', unit['id'], '这个制品按 triage / standard / deep 哪一档审？写 depth_reason。')
    # Target level, not unit level. Every unit records why it *takes* an object, and
    # nothing records why the target does not involve the rest — so an object nobody
    # thought about is indistinguishable from one deliberately ruled out, and the
    # coverage claim quietly shrinks its own denominator. Measured on the first real
    # run: 17 of 36 objects were declared and the other 19 were simply never mentioned.
    declared = {oid for unit in state.get('units', []) for oid in unit['object_ids'] or []}
    scoped = {str(row.get('subject')) for row in state.get('object_scope', [])
              if str(row.get('decision') or '')}
    names = _framework_object_names(workspace, state)
    for oid in sorted(set(_framework_object_ids(workspace, state)) - declared - scoped):
        # The name belongs in the question: 52 bare ids meant importing the bundle just
        # to know what each one is before judging it.
        add('object_scope', oid,
            '%s：' % names.get(oid, oid) +
            '本目标涉及这个框架对象吗？涉及就让某个单元声明它；不涉及要写明依据'
            '（这类组件不存在 / 由平台承担 / 本次范围外），依据进 object_scope。'
            '「没人提」与「判过不涉及」在记录里必须可区分。')
    scatter = (_object_scatter(state) if (state.get('queue') or {}).get('phase2_rows_frozen') is not None else [])
    if scatter and not str((state.get('queue') or {}).get('joint_objects') or '').strip():
        add('cross_cutting_objects', 'queue',
            '以下对象被多个单元声明：%s。这是分布统计，不能据此判断职责或证据是否完整。'
            '答：哪几个改由三阶段的 joint 段整体判（写对象编号，逗号分隔），'
            '或答 none 并说明为什么每片各判一次仍然够。'
            % '、'.join('%s×%d片' % (row['object'], len(row['units']))
                        for row in scatter[:8]))
    for cluster in state.get('clusters', []):
        if len(cluster['member_unit_ids']) > 1 and not cluster.get('representative_unit_id') and cluster.get('decision') != 'declined':
            add('cluster_representative', cluster['id'],
                '簇内 %d 个成员，代表选哪个？代表够不够代表要看 diff，不看指纹相同。'
                % len(cluster['member_unit_ids']))
    assigned = {mid for unit in state.get('units', []) for mid in unit['material_ids']}
    for mid in sorted(set(rows) - assigned):
        add('unassigned_material', mid, '这个材料不属于任何单元，归入某单元或写入 exclusions。')
    return out


def freeze(workspace, state, phase=1):
    """Close one phase. Refuses while any decision is unresolved.

    Three phases, and the first one owns no units: it closes **what the audit found out
    about itself** — the partition, which framework objects the target involves, and the
    model's scope decisions. Freezing it therefore records counts rather than a row
    count. Unit membership stays fixed; object adjudications can be corrected through
    decide with a reason. Their frozen count remains a historical observation, not a
    constraint on later evidence-based corrections.
    """
    from audit import save
    queue = state.setdefault('queue', {})
    unresolved = [d['id'] for d in state.get('pending_decisions', []) if not d.get('resolution')]
    if unresolved:
        raise ValueError('%d pending decisions are unresolved, first: %s'
                         % (len(unresolved), ', '.join(unresolved[:5])))
    errors = partition_errors(state)
    if errors:
        raise ValueError('Partition is not a partition: ' + '; '.join(errors[:3]))
    if phase == 1:
        if queue.get('phase1_frozen') is not None:
            raise ValueError('Phase 1 is already frozen: %s' % queue['phase1_frozen'])
        if not queue.get('partition_confirmed'):
            raise ValueError('Model must confirm partition or submit plan --apply before freeze')
        working = [u for u in state['units'] if u['kind'] != 'cross']
        unmapped = [u['id'] for u in working
                    if not (u['object_ids'] or u.get('mapping_note'))]
        if unmapped:
            raise ValueError('These units carry neither an object nor a mapping note: '
                             + '、'.join(unmapped[:5]))
        # The byte proxy is recorded as a count, not adjudicated: a reader who wants to
        # know how much code sits in one unit can see it, and nobody has to write 46
        # reasons for a limit the protocol calls the weakest of the three.
        frozen = {'units': len(working),
                  'object_scope': len(state.get('object_scope') or []),
                  'spots': sum(u.get('surface_hits') or 0 for u in working),
                  'over_byte_proxy': sum(1 for u in working
                                         if u['byte_count'] > LIMITS['bytes_high']),
                  'over_unit_limit': max(0, len(working) - LIMITS['units'])}
        queue['phase1_frozen'] = frozen
        queue['census'] = census(state)
        save(workspace, state)
        return {'phase': 1, 'phase1_frozen': frozen, 'census': queue['census'],
                'note': '此后单元集合不变；对象映射与裁决可经 decide 留理由订正，冻结统计保留原值'}
    key = 'phase%d_rows_frozen' % phase
    if queue.get(key) is not None:
        raise ValueError('Phase %d queue is already frozen at %d rows' % (phase, queue[key]))
    if queue.get('phase1_frozen') is None:
        raise ValueError('Freeze phase 1 before phase %d' % phase)
    if phase == 3 and queue.get('phase2_rows_frozen') is None:
        raise ValueError('Freeze phase 2 before phase 3')
    if phase == 3:
        present_types = {u.get('cross_type') for u in state['units'] if u['kind'] == 'cross'}
        decisions = queue.get('cross_scope') or {}
        for kind in CROSS_TYPES:
            decision = decisions.get(kind) or {}
            if decision.get('decision') not in ('needed', 'not_needed') or not str(decision.get('reason') or '').strip():
                raise ValueError('Phase 3 needs an explicit cross_scope decision for ' + kind)
            if decision['decision'] == 'needed' and kind not in present_types:
                raise ValueError('cross_scope marks needed but no unit exists: ' + kind)
            if decision['decision'] == 'not_needed' and kind in present_types:
                raise ValueError('cross_scope marks not_needed but a unit exists: ' + kind)
        confirmed = {c['id'] for c in state.get('checks', [])
                     if c.get('verdict') == 'confirmed'}
        for unit in state['units']:
            if unit.get('cross_type') != 'chain':
                continue
            seeds = (unit.get('seed') or {}).get('check_ids') or []
            if not seeds:
                raise ValueError(unit['id'] + ': a chain seed must name the confirmed '
                                 'checks it starts from (seed.check_ids)')
            stray = [cid for cid in seeds if cid not in confirmed]
            if stray:
                raise ValueError('%s: seeds a chain on checks that are not confirmed: %s'
                                 % (unit['id'], '、'.join(stray[:4])))
    if phase == 3:
        # The scatter answer has to be load-bearing. Naming an object and then not
        # building the joint unit for it would leave the object judged by nobody, which
        # is the very thing the question was asked to prevent.
        named = [oid for oid in str(queue.get('joint_objects') or '').split(',')
                 if oid.strip() and oid.strip() != 'none']
        seeded = {oid for unit in state['units'] if unit.get('cross_type') == 'joint'
                  for oid in ((unit.get('seed') or {}).get('object_ids') or [])}
        missing = [oid for oid in (o.strip() for o in named) if oid not in seeded]
        if missing:
            raise ValueError('这些对象答了「交 joint 段整体判」，但没有任何 joint 单元的 '
                             'seed.object_ids 带上它们：%s（用 cross --type joint 建，'
                             '或改答这条裁决）' % '、'.join(missing))
    if phase == 3 and not queue.get('phase3_critic'):
        raise ValueError('queue.phase3_critic must record the critique before freezing '
                         'phase 3; write "第 N 轮，补入 M 项" even when nothing was added')
    rowcount = len([u for u in state['units'] if u['phase'] == phase])
    if not rowcount and phase == 2:
        raise ValueError('Phase %d has no units' % phase)
    if phase == 2:
        # Which objects no single unit holds. A worker's unit boundary is also its
        # evidence boundary — anything outside becomes a crosslead, "written down, not
        # audited" — so an object spread thin is judged by nobody, however many units
        # declare it. Measured on a real target: a median of 5 units per object and a
        # worst case of 26 before packing, 4 and 13 after. Recorded ranked, and the call
        # of which ones move to a joint unit is asked once, not thresholded: the obvious
        # mechanical measure (the share of an object's hits in its largest unit) comes
        # from pattern-family footprints and puts 27 of 37 objects under 40%, which
        # separates nothing.
        queue['object_scatter'] = _object_scatter(state)
        # Recomputed here, because `freeze` does not otherwise touch the decision list:
        # the scatter question is raised by the freeze that measures it, and without this
        # it could never appear at all.
        queue[key] = rowcount
        state['pending_decisions'] = pending_decisions(workspace, state)
    queue[key] = rowcount
    queue['census'] = census(state)
    save(workspace, state)
    return {'phase': phase, key: rowcount, 'census': queue['census'],
            'note': '此后只减不增：本阶段不再新增单元，范围外的观察进残余前沿清单'}


# ── clustering a pile of artefacts ───────────────────────────────────────────────
def _sketch(texts):
    """Bottom-k sketch of 5-word shingles: one hash per shingle, keep the k smallest.

    One hash per shingle instead of k independent hashes keeps a pile of a hundred
    packages affordable; the bottom-k estimator below is the matching one.
    """
    values = set()
    for text in texts:
        words = re.findall(r'\w+', text)
        for i in range(max(len(words) - 4, 1)):
            shingle = ' '.join(words[i:i + 5]).encode('utf-8', 'replace')
            values.add(int.from_bytes(hashlib.blake2b(shingle, digest_size=8).digest(), 'big'))
    return sorted(values)[:SKETCH_K], len(values)


def _similarity(left, right):
    """Jaccard estimate over the k smallest hashes of the union."""
    if not left or not right:
        return 0.0
    union = sorted(set(left) | set(right))[:SKETCH_K]
    if not union:
        return 0.0
    a, b = set(left), set(right)
    return sum(1 for value in union if value in a and value in b) / len(union)


def cluster(workspace, state, threshold=0.8):
    """Group artefact units by content. Which member represents the cluster is not decided here."""
    from audit import material_path, save
    if state.get('queue', {}).get('phase1_frozen') is not None or any(
            c.get('representative_unit_id') or c.get('decision') for c in state.get('clusters', [])):
        raise ValueError('Cannot overwrite frozen partition or model cluster decisions')
    rows = present(state)
    targets = [u for u in state.get('units', []) if u['kind'] == 'artifact']
    if not targets:
        raise ValueError('No artifact units to cluster; run plan first')
    profiles = []
    for unit in targets:
        members = sorted(unit['material_ids'], key=lambda m: rows[m]['path'])
        exact = hashlib.sha256()
        texts, budget = [], SHINGLE_BYTES
        for mid in members:
            row = rows[mid]
            exact.update((row['path'] + '\0' + (row['sha256'] or '') + '\n').encode())
            if row.get('visibility') == 'text' and budget > 0:
                try:
                    chunk = material_path(state, row).read_bytes()[:budget]
                except (OSError, ValueError):
                    continue
                budget -= len(chunk)
                texts.append(chunk.decode('utf-8', 'replace'))
        sketch, shingles = _sketch(texts)
        profiles.append({'unit': unit, 'exact': exact.hexdigest(), 'near': sketch,
                         'shingles': shingles,
                         'files': {rows[m]['path']: rows[m]['sha256'] for m in members}})
    clusters, used = [], set()
    for i, left in enumerate(profiles):
        if left['unit']['id'] in used:
            continue
        members, similarity = [left], {}
        for right in profiles[i + 1:]:
            if right['unit']['id'] in used:
                continue
            same = right['exact'] == left['exact']
            comparable = min(left['shingles'], right['shingles']) >= SKETCH_MIN
            score = 1.0 if same else (_similarity(left['near'], right['near']) if comparable else 0.0)
            if same or score >= threshold:
                members.append(right)
                similarity[right['unit']['id']] = round(score, 3)
        if len(members) == 1:
            continue
        cid = 'CL-%02d' % (len(clusters) + 1)
        for member in members:
            used.add(member['unit']['id'])
            member['unit']['cluster_id'] = cid
        diffs = []
        for member in members[1:]:
            for path, sha in sorted(member['files'].items()):
                if left['files'].get(path) != sha:
                    diffs.append({'unit_id': member['unit']['id'], 'path': path,
                                  'status': 'open', 'reason': ''})
        clusters.append({'id': cid, 'exact_fingerprint': left['exact'],
                         'member_unit_ids': [m['unit']['id'] for m in members],
                         'similarity': similarity, 'shingles': left['shingles'],
                         'representative_unit_id': None, 'diff_files': diffs})
    state['clusters'] = clusters
    state['pending_decisions'] = pending_decisions(workspace, state, rows)
    save(workspace, state)
    return {'clusters': len(clusters), 'clustered_units': len(used),
            'diff_files': sum(len(c['diff_files']) for c in clusters),
            'note': '仅相似性建议；模型决定是否采用、选谁作代表及审哪些材料，不自动缩减覆盖'}


def pack_units(workspace, state):
    """Retired heuristic entry point: applying a model-authored plan is explicit."""
    raise ValueError('自动合并已移除；请用 plan --apply <划分文件> 应用明确的材料归属')


def completion_errors(unit, product=None, *, require_merged=False):
    """Check recorded completion only; reasons and actual analysis are model judgments."""
    source = unit if product is None else product
    uid = unit['id']
    errors = []
    if require_merged and unit.get('status') not in {'merged', 'reviewed'}:
        errors.append('%s: unit has not been merged (%s)' % (uid, unit.get('status')))
    progress = source.get('progress')
    done = progress.get('files_done') if isinstance(progress, dict) else None
    if type(done) is not int or done != unit['file_count']:
        errors.append('%s: progress.files_done must equal file_count (%r/%s)'
                      % (uid, done, unit['file_count']))
    dimensions = source.get('dimensions')
    if not isinstance(dimensions, dict):
        dimensions = {}
    for name in DIMENSIONS:
        row = dimensions.get(name)
        if not isinstance(row, dict):
            errors.append('%s/dimensions.%s: missing dimension' % (uid, name))
            continue
        if row.get('state') not in {'done', 'na'}:
            errors.append('%s/dimensions.%s: expected done or na' % (uid, name))
        reason = row.get('reason')
        if not isinstance(reason, str) or not reason.strip():
            errors.append('%s/dimensions.%s: completion needs a reason' % (uid, name))
    for name in sorted(set(dimensions) - set(DIMENSIONS)):
        errors.append('%s/dimensions.%s: unknown dimension' % (uid, name))
    return errors


def _object_scatter(state):
    """`[{object, units: [...]}, ...]` for objects more than one phase-2 unit declares,
    worst first. The denominator for "can this object be judged inside a unit"."""
    spread = {}
    for unit in state['units']:
        if unit.get('phase') != 2:
            continue
        for oid in unit.get('object_ids') or []:
            spread.setdefault(oid, []).append(unit['id'])
    return [{'object': oid, 'units': sorted(ids)}
            for oid, ids in sorted(spread.items(), key=lambda kv: (-len(kv[1]), kv[0]))
            if len(ids) > 1]


def add_cross(workspace, state, cross_type, title, seed):
    """Register one phase-three unit. Only allowed before the phase-three queue is frozen."""
    from audit import save
    if cross_type not in CROSS_TYPES:
        raise ValueError('cross_type must be one of ' + ', '.join(CROSS_TYPES))
    if state.get('queue', {}).get('phase2_rows_frozen') is None:
        raise ValueError('Phase 2 must be frozen before phase 3 units exist')
    if state.get('queue', {}).get('phase3_rows_frozen') is not None:
        raise ValueError('Stage 2 queue is frozen; new chains go to the residual frontier list')
    number = len([u for u in state['units'] if u['kind'] == 'cross']) + 1
    unit = new_unit('U-CX%02d' % number, 'cross', title, phase=3,
                    cross_type=cross_type, seed=seed or {})
    state['units'].append(unit)
    save(workspace, state)
    return {'unit': unit['id'], 'cross_type': cross_type}


def write_brief(workspace, state, unit, knowledge_brief, surface_path):
    """Compose the one file a worker reads about its own unit."""
    unit_dir = Path(workspace) / 'units' / unit['id']
    unit_dir.mkdir(parents=True, exist_ok=True)
    rows = present(state)
    roots = {t['id']: t['path'] for t in state['targets']}
    lines = ['# 单元 %s · %s' % (unit['id'], unit['title']), '',
             '本文件由 dispatch 生成。它是你这一单元的全部依据：框架知识已按本单元预切，不要再去全量查询对象。', '',
             '## 目标根（材料路径相对于它；读文件时拼绝对路径）', '']
    for alias in unit['target_ids'] or sorted(roots):
        lines.append('- `%s` → `%s`' % (alias, roots.get(alias, '未登记')))
    lines += ['',
             '## 单元事实', '',
             '- 类型：%s；阶段：%s；暴露层级：%s' % (unit['kind'], unit['phase'], unit['exposure']),
             '- 深度：%s（%s）' % (unit['depth'] or '未定', unit['depth_reason'] or '无'),
             '- 文件数：%d（文本 %d / 非文本 %d）；代码量：%.0f KB'
             % (unit['file_count'], unit['text_count'], unit['opaque_count'], unit['byte_count'] / 1024),
             '- 界面命中：%s 处' % ('未建索引' if unit['surface_hits'] is None else unit['surface_hits']),
             '- 语言零匹配（仅检索统计）：%s' % ('、'.join('%s %d 个文件' % (k, v) for k, v in
                                  sorted((unit.get('blind_languages') or {}).items()))
                              or '无记录；不代表覆盖'),
             '- 承担的框架对象：%s' % (', '.join(unit['object_ids']) or '（未映射：%s）' % (unit['mapping_note'] or '待裁决')),
             '']
    inbound = [row for row in state.get('crossleads') or []
               if isinstance(row, dict) and row.get('to_unit') == unit['id']]
    if inbound:
        # The most specific task a unit has is often one of these, and nothing used to
        # deliver them: they sat in the record addressed to this unit while the brief
        # said nothing, so finding them meant reading the whole shared record by hand.
        lines += ['## 定向到本单元的交接（%d 条，逐条要有结论）' % len(inbound), '',
                  '别的单元或侦察阶段看到了属于本单元的东西。**这些是本单元最具体的任务**，'
                  '逐条在检查或发现里作答；判为不属于本单元的，写回一条交接说明去向。', '']
        for row in inbound:
            lines.append('- 来自 %s：%s'
                         % (row.get('from_unit') or row.get('source') or '未记',
                            row.get('observation') or row.get('note') or ''))
            for key in ('judgement', 'reachable_from', 'missing_control_at'):
                if row.get(key):
                    lines.append('  %s：%s' % (key, row[key]))
        lines.append('')
    if unit.get('blind_languages'):
        lines += ['语言零匹配不能判断不存在危险构造；已有匹配也不能证明覆盖。无需逐语言交处置结论。', '']
    if unit['kind'] != 'cross':
        lines += ['## 材料清单（你的覆盖边界，逐个要有结论或跳过理由）', '']
        for mid in sorted(unit['material_ids'], key=lambda m: rows[m]['path'])[:2000]:
            row = rows[mid]
            lines.append('- `%s` | %s | %s | %s 字节' % (mid, row['target_id'], row['path'], row['size']))
        if unit['file_count'] > 2000:
            lines.append('- …… 其余 %d 条见 audit.json 的 units[].material_ids' % (unit['file_count'] - 2000))
        lines.append('')
    if unit['kind'] == 'cross':
        lines += ['## 本单元的种子', '', '```json',
                  json.dumps(unit['seed'], ensure_ascii=False, indent=2), '```', '']
    # Scope and framework knowledge precede optional search locations. A missing
    # match never removes a question from the model's investigation.
    lines += ['## 本单元适用的框架知识（预切，勿再全量查询）', '', knowledge_brief, '']
    if surface_path:
        lines += ['## 可选检索候选', '',
                  '定位信息在 `%s`。原始命中不要求逐条处置，也不代表同一问题或覆盖。'
                  '模型依据职责和证据建立的正式检查仍须完成。'
                  % surface_path, '']
    text = '\n'.join(lines)
    (unit_dir / 'brief.md').write_text(text, encoding='utf-8')
    return {'brief': str(unit_dir / 'brief.md'), 'bytes': len(text.encode('utf-8'))}
