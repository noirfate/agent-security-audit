#!/usr/bin/env python3
"""Maintain only a target audit workspace. Never execute or modify target files."""
# Importable under `python3 -I`, which clears the script directory from sys.path:
# the session rule is to read untrusted data with -I, and these scripts import
# their siblings, so without this they fail before doing anything.
import sys as _sys
from pathlib import Path as _Path
if str(_Path(__file__).resolve().parent) not in _sys.path:
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

sys.dont_write_bytecode = True
from knowledge import SKILL, baseline_dir, digest, load_bundle, objects, read
SCHEMA_VERSION = '1.6'
# Collections added by 1.2. They carry the scheduling layer: how the target was cut
# into units, which round did what, and what the files alone cannot decide.
SCHEDULING_COLLECTIONS = ('units', 'clusters', 'artifacts', 'rounds', 'chains', 'primitives',
                         'pending_decisions', 'scope_notes', 'crossleads', 'stale_notes',
                         'route_excluded', 'corrections', 'report_todos',
                         'withdrawn_reviews', 'reconciliations', 'object_scope',
                         'target_patterns', 'form_gaps', 'retired_unit_ids', 'dismissed_candidates')
EMPTY_QUEUE = {'phase1_frozen': None, 'phase2_rows_frozen': None,
               'phase3_rows_frozen': None, 'phase3_critic': None,
               'census': None, 'partition_confirmed': False,
               'partition_reason': '', 'cross_scope': {}}
# Older target records this release still knows how to migrate. Anything outside this
# set plus SCHEMA_VERSION is refused rather than guessed at.
# Every version this tool will still open. Bumping SCHEMA_VERSION without adding the
# previous one here turns every existing record into an unrecognized one, refused even
# by refresh — the migration path cannot run because the guard rejects the record first.
MIGRATABLE = ('1.0', '1.1', '1.2', '1.3', '1.4', '1.5')


def now():
    return datetime.now(timezone.utc).isoformat()


def inside(path, root):
    return path == root or root in path.parents


def workspace_path(path):
    path = Path(path).expanduser().resolve()
    if inside(path, SKILL):
        raise ValueError('Audit workspace must be outside the installed skill')
    return path


def write_json(path, value):
    path = Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('Refusing to write through a symlink: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def save(workspace, state):
    if (state.get('queue') or {}).get('phase2_rows_frozen') is not None:
        from units import _object_scatter
        state['queue']['object_scatter'] = _object_scatter(state)
    state['updated_at'] = now()
    write_json(workspace / 'audit.json', state)


def pin_bundle(workspace):
    data, manifest, fingerprint = load_bundle()
    target = baseline_dir(workspace, fingerprint)
    if target.exists():
        _, _, actual = load_bundle(target)
        if actual != fingerprint:
            raise ValueError('Pinned baseline changed')
    else:
        if any(p.is_symlink() for p in target.parents):
            raise ValueError('Baseline directory is a symlink')
        target.mkdir(parents=True)
        for name in ('framework.json', 'manifest.json'):
            shutil.copyfile(SKILL / 'knowledge' / name, target / name)
    return {'baseline_id': fingerprint, 'version': manifest['framework_version'],
            'contract_schema': manifest['contract_schema']}


def skill_fingerprint():
    h = hashlib.sha256()
    for p in sorted(SKILL.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix not in {'.pyc', '.pyo'}:
            h.update(p.relative_to(SKILL).as_posix().encode())
            h.update(bytes.fromhex(digest(p)))
    return h.hexdigest()


def inventory(workspace, targets, exclusions):
    materials, skipped = {}, []
    excluded = [Path(p).resolve() for p in exclusions] + [workspace]
    for target in targets:
        root = Path(target['path'])
        if not root.exists():
            raise ValueError('Target missing; cannot treat it as an empty tree: ' + str(root))
        def skip(path):
            reason = None
            if path.is_symlink():
                reason = 'symlink_not_followed; declare its resolved target explicitly if in scope'
            elif any(inside(path, p) for p in excluded):
                reason = 'audit_workspace_or_explicit_exclusion'
            elif path.name == '.git' and path.is_dir():
                reason = 'version_control_metadata'
            elif inside(path, SKILL) and not inside(root, SKILL):
                reason = 'installed_audit_skill'
            if reason:
                skipped.append({'target_id': target['id'], 'path': str(path.relative_to(root)), 'reason': reason})
            return bool(reason)
        files = []
        root_is_file = root.is_file()
        if root_is_file:
            files = [root]
        else:
            def walk_error(exc):
                skipped.append({'target_id': target['id'], 'path': str(Path(exc.filename).relative_to(root)),
                                'reason': 'enumeration_failed: ' + type(exc).__name__})
            for current, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
                directory = Path(current)
                dirs[:] = sorted(name for name in dirs if not skip(directory / name))
                files.extend(directory / name for name in sorted(names) if not skip(directory / name))
        for path in files:
            if not path.is_file():
                skipped.append({'target_id': target['id'], 'path': str(path.relative_to(root)), 'reason': 'not_regular_file'})
                continue
            rel = path.name if root_is_file else path.relative_to(root).as_posix()
            mid = 'MAT-' + hashlib.sha256((target['id'] + '/' + rel).encode()).hexdigest()[:16]
            from materials import MAX_BYTES, inspect
            # One read serves both the fingerprint and the visibility verdict. They used
            # to open the file separately, and `root.is_file()` was asked once per
            # material for an answer fixed before the walk — 1891 materials paid six
            # stats and two reads each, which is forty of the preflight's seconds.
            try:
                with path.open('rb') as handle:
                    head = handle.read(MAX_BYTES + 1)
                    sha = hashlib.sha256(head)
                    for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                        sha.update(chunk)
                    sha, size = sha.hexdigest(), path.stat().st_size
                access_error = None
            except OSError as exc:
                head, sha, size, access_error = None, None, None, type(exc).__name__
            visibility = inspect(path, head)
            materials[mid] = {'id': mid, 'target_id': target['id'], 'path': rel,
                              'sha256': sha, 'size': size, 'status': 'present',
                              'access_error': access_error, **visibility}
    return materials, skipped


def material_path(state, material):
    targets = {t['id']: t for t in state['targets']}
    root = Path(targets[material['target_id']]['path'])
    path = root if root.is_file() else root / material['path']
    if path.is_symlink() or (root.is_dir() and not inside(path.resolve(), root.resolve())):
        raise ValueError('Material escaped declared target: ' + material['path'])
    return path


def snapshot_entries(root, exclude_history=False):
    """Enumerate regular workspace files and directories without following links."""
    import stat
    root = Path(root)
    if root.is_symlink():
        raise ValueError('Snapshot source is a symlink: ' + str(root))
    files, directories = {}, []

    def visit(directory):
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root).as_posix()
            if exclude_history and relative == 'snapshots':
                continue
            if path.is_symlink():
                raise ValueError('Snapshot refuses a symlink: ' + relative)
            mode = path.stat().st_mode
            if stat.S_ISDIR(mode):
                directories.append(relative)
                visit(path)
            elif stat.S_ISREG(mode):
                files[relative] = path
            else:
                raise ValueError('Snapshot refuses a non-regular file: ' + relative)

    visit(root)
    return files, directories


def snapshot_manifest(directory):
    """Verify a complete archive; accept the original three-file format as history."""
    from pathlib import PurePosixPath
    directory = Path(directory)
    actual, directories = snapshot_entries(directory)
    if 'manifest.json' not in actual:
        raise ValueError('Snapshot incomplete: ' + directory.name)
    manifest = read(actual['manifest.json'])
    if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), dict):
        raise ValueError('Invalid snapshot manifest: ' + directory.name)
    files = manifest['files']
    version = manifest.get('format_version', 1)
    if version not in (1, 2):
        raise ValueError('Unknown snapshot format: ' + str(version))
    required = 'workspace/audit.json' if version == 2 else 'audit.json'
    if required not in files:
        raise ValueError('Invalid snapshot file list: missing ' + required)
    for name, sha in files.items():
        relative = PurePosixPath(name)
        if (relative.is_absolute() or '..' in relative.parts or '\\' in name
                or relative.as_posix() != name or name in ('', '.', 'manifest.json')):
            raise ValueError('Invalid snapshot path: ' + name)
        if version == 2 and (not relative.parts or relative.parts[0] != 'workspace'):
            raise ValueError('Invalid snapshot payload path: ' + name)
        if version == 1 and name not in {'audit.json', 'report.md', 'report.sarif.json'}:
            raise ValueError('Invalid legacy snapshot file list: ' + name)
        if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha):
            raise ValueError('Invalid snapshot digest: ' + name)
    if set(actual) != set(files) | {'manifest.json'}:
        missing = sorted(set(files) - set(actual))
        extra = sorted(set(actual) - set(files) - {'manifest.json'})
        raise ValueError('Snapshot changed: %s; missing=%s unlisted=%s'
                         % (directory.name, missing, extra))
    if version == 2 and manifest.get('directories') != sorted(directories):
        raise ValueError('Snapshot directory list changed: ' + directory.name)
    for name, sha in files.items():
        if digest(actual[name]) != sha:
            raise ValueError('Snapshot changed: ' + directory.name + '/' + name)
    baselines = manifest.get('baseline_ids')
    if not isinstance(baselines, list) or any(
            not isinstance(bid, str) or not re.fullmatch(r'[0-9a-f]{64}', bid)
            for bid in baselines):
        raise ValueError('Invalid snapshot baseline list: ' + directory.name)
    return manifest


def archive(workspace, state, label, report=None):
    """Publish a self-contained workspace checkpoint after all writers have paused."""
    import tempfile
    workspace = Path(workspace)
    if workspace.is_symlink() or any(p.is_symlink() for p in workspace.parents):
        raise ValueError('Snapshot workspace is a symlink')
    history = workspace / 'snapshots'
    if history.is_symlink():
        raise ValueError('Snapshot directory is a symlink')
    history.mkdir(parents=True, exist_ok=True)
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-' + label + '-' + uuid.uuid4().hex[:6]
    if Path(name).name != name:
        raise ValueError('Invalid snapshot label')
    directory = history / name
    source, source_dirs = snapshot_entries(workspace, exclude_history=True)
    hashes = {name: digest(path) for name, path in source.items()}
    with tempfile.TemporaryDirectory(prefix='.pending-', dir=history) as temporary:
        staging = Path(temporary)
        payload = staging / 'workspace'
        payload.mkdir()
        for relative in source_dirs:
            (payload / relative).mkdir(parents=True, exist_ok=True)
        for relative, path in source.items():
            shutil.copy2(path, payload / relative)
            if digest(payload / relative) != hashes[relative]:
                raise ValueError('Workspace changed during snapshot: ' + relative)
        current, current_dirs = snapshot_entries(workspace, exclude_history=True)
        if set(current) != set(source) or current_dirs != source_dirs:
            raise ValueError('Workspace file list changed during snapshot')
        if any(digest(current[name]) != sha for name, sha in hashes.items()):
            raise ValueError('Workspace changed during snapshot; pause writers before retrying')
        write_json(payload / 'audit.json', state)
        if report is not None:
            (payload / 'report.md').write_text(report, encoding='utf-8')
            from records import render_coverage
            (payload / 'coverage-details.md').write_text(render_coverage(state, workspace), encoding='utf-8')
            from sarif import export_sarif
            write_json(payload / 'report.sarif.json', export_sarif(state, workspace))
        archived, directories = snapshot_entries(staging)
        write_json(staging / 'manifest.json', {
            'format_version': 2, 'created_at': now(), 'purpose': label,
            'files': {name: digest(path) for name, path in archived.items()},
            'directories': sorted(directories),
            'baseline_ids': sorted({state['framework']['baseline_id']} | {
                c['baseline_id'] for c in state['checks']})})
        snapshot_manifest(staging)
        staging.rename(directory)
    return directory


def initialize(workspace, name, target_specs, excludes):
    if (workspace / 'audit.json').exists():
        raise ValueError('Audit already exists; use refresh to resume')
    targets = []
    for spec in target_specs or ['target=' + str(Path.cwd())]:
        tid, separator, value = spec.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z0-9_-]+', tid):
            raise ValueError('--target must be a unique name=/absolute/or/relative/path')
        path = Path(value).expanduser().resolve(strict=True)
        if inside(path, workspace):
            raise ValueError('Target cannot be inside the audit workspace')
        if inside(workspace, path):
            # Not only because the records would sit among the material. The workspace
            # writes on every command, so a work tree holding it is permanently dirty —
            # and a dirty tree means the recorded commit does not describe what was read,
            # which turns every kept target pattern into "cannot be compared".
            raise ValueError('Audit workspace cannot be inside a declared target (%s): '
                             'it would keep that work tree permanently dirty' % tid)
        from vcs import dirty, revision
        # The revision is what makes a recalled pattern reusable later: it says which
        # code the audit actually read. A dirty tree means the commit id does not
        # describe what was read, so it is recorded as such rather than silently
        # stamping a knowledge base with a revision that is not the truth.
        targets.append({'id': tid, 'path': str(path),
                        'revision': revision(path), 'dirty': dirty(path)})
    if len({t['id'] for t in targets}) != len(targets):
        raise ValueError('Duplicate target id')
    exclusions = [str(Path(p).expanduser().resolve()) for p in excludes]
    if any(inside(Path(t['path']), Path(e)) for t in targets for e in exclusions):
        raise ValueError('An exclusion covers a whole declared target')
    # Pin the baseline first: that creates the workspace, so a single enumeration
    # already records its exclusion. Enumerating twice costs minutes on a multi-repo
    # target and produces the same index.
    framework = pin_bundle(workspace)
    mats, skipped = inventory(workspace, targets, exclusions)
    data, _, _ = load_bundle()
    state = {
        'schema_version': SCHEMA_VERSION, 'target_id': name, 'created_at': now(), 'updated_at': now(),
        'targets': targets, 'framework': framework, 'skill_fingerprint': skill_fingerprint(),
        'profile': {d['id']: {'value': None, 'evidence_ids': [], 'unknown_reason': '尚未调查'} for d in data['audit_profile']['dimensions']},
        'exclusions': exclusions, 'inventory_exclusions': skipped, 'materials': mats,
        'instances': [], 'connections': [], 'assets': [], 'controls': [], 'attackers': [],
        'hypotheses': [], 'coverage': [], 'evidence': [], 'checks': [], 'findings': [],
        'method_notes': [], 'pending_framework': None,
        'reviews': [], 'observations': [], 'dynamic_sessions': [],
        **{key: [] for key in SCHEDULING_COLLECTIONS}, 'queue': {**EMPTY_QUEUE, 'cross_scope': {}},
    }
    save(workspace, state)
    # Legal, sometimes deliberate, and worth saying out loud: a workspace inside an
    # unrelated repository means every command dirties that repository's status, and the
    # records get committed into it by accident. Reported, not refused — the auditor may
    # want their audits versioned.
    from vcs import work_tree_root
    host = work_tree_root(workspace)
    declared = {str(Path(t['path']).resolve()) for t in targets}
    note = None
    if host and host not in declared:
        note = ('工作区位于 git 仓 %s 之内，而那不是被审目标：每条命令都会污染它的 '
                'git status，记录也容易被误提交。确实要把审计记录纳入版本管理就忽略这条，'
                '否则换到一个专用的审计根目录。' % host)
    return {'workspace': str(workspace), 'materials': len(mats), 'framework': framework,
            'workspace_in_git_repo': host if note else None, 'note': note}


def check_evidence_ids(check):
    ids = set(check.get('evidence_ids', []) + check.get('counterevidence_ids', []))
    for row in check.get('prerequisites', []) + check.get('criteria', []):
        ids.update(row.get('evidence_ids', []))
    return ids


def check_counterevidence_ids(check):
    """Explicit counterevidence, including condition annotations in older records."""
    ids = set(check.get('counterevidence_ids', []))
    for row in check.get('criteria', []):
        if row.get('state') == 'not_met':
            ids.update(row.get('evidence_ids', []))
    return ids


def refresh(workspace, state, adopt=False):
    from units import id_owner
    # An instance's owning unit is mechanically determined — the id carries the unit's
    # token — so a row that reached the record without it gets it back here rather than
    # through `merge --replace`, which would demand withdrawing sound reviews to repair a
    # field nobody judged. Measured: one unit's 19 judged propositions were reported as
    # "never instantiated" because two of its instances had `unit_id: null`.
    units_by_token = {u['id'][2:]: u['id'] for u in state.get('units') or []}
    for row in state.get('instances') or []:
        if not row.get('unit_id'):
            owner = units_by_token.get(id_owner(row['id']))
            if owner:
                row['unit_id'] = owner
    previous = state['schema_version']
    migrated = previous != SCHEMA_VERSION
    if migrated:
        archive(workspace, state, 'before-schema-migration')
        state['schema_version'] = SCHEMA_VERSION
        for key in ('reviews', 'observations', 'dynamic_sessions') + SCHEDULING_COLLECTIONS:
            state.setdefault(key, [])
        state.setdefault('queue', dict(EMPTY_QUEUE))
        # Keep old facts and freeze states without pretending they passed 1.6.
        state.setdefault('contract_history', []).append({
            'from': previous, 'to': SCHEMA_VERSION, 'at': now(),
            'note': 'Legacy conclusions/fp counts retained; no candidate associations or semantic decisions inferred'})
        queue = state['queue']
        queue['legacy_freeze_contract'] = previous
        queue.setdefault('partition_confirmed', False)
        queue.setdefault('cross_scope', {})
        for unit in state.get('units', []):
            unit.setdefault('legacy_schema_version', previous)
        # Obsolete hit-count obligations do not survive as work. Other answers remain.
        state['pending_decisions'] = [d for d in state.get('pending_decisions', [])
                                      if d.get('kind') != 'oversized_unit']
        # 1.5 removed the bounded-read path, so read receipts have no validator, no
        # renderer and no writer. Dropping them is the migration: leaving them would keep
        # rows nothing checks in a record whose own version says they do not exist.
        # Their one load-bearing use — "state what you actually read" — moved to the
        # unconditional `analysis_method`/`limitations` on a reviewed coverage row.
        dropped_reads = len(state.pop('reads', []) or [])
        if previous in {'1.0', '1.1', '1.2', '1.3'}:
            # Two stages became three phases: the reconnaissance and locating work that
            # used to sit inside `plan` is now a phase with its own products and gate.
            # Unit stages shift up by one because phase 1 owns no units, and the old
            # stage-1 row count becomes phase 2's — it counted the same set of units.
            for unit in state.get('units', []):
                if 'phase' not in unit:
                    unit['phase'] = {1: 2, 2: 3}.get(unit.pop('stage', 1), 2)
            queue = state.setdefault('queue', {})
            was_stage1 = queue.pop('stage1_rows_frozen', None)
            was_stage2 = queue.pop('stage2_rows_frozen', None)
            was_critic = queue.pop('stage2_critic', None)
            working = [u for u in state.get('units', []) if u['kind'] != 'cross']
            queue.setdefault('phase1_frozen',
                             {'units': len(working),
                              'object_scope': len(state.get('object_scope') or []),
                              'spots': sum(u.get('surface_hits') or 0 for u in working)}
                             if was_stage1 is not None else None)
            queue.setdefault('phase2_rows_frozen', was_stage1)
            queue.setdefault('phase3_rows_frozen', was_stage2)
            queue.setdefault('phase3_critic', was_critic)
        if previous == '1.0':
            # 1.0 predates the read receipts and the review ledger, so its conclusions
            # were never held to them. 1.1 records keep their findings: 1.2 and 1.3 only
            # add scheduling collections, and the skill fingerprint below already flags
            # the checks for re-review. Adding a collection is what a version bump is
            # for — the keys are created here and nowhere else, so a new collection that
            # does not move the version never reaches an existing record, and the rules
            # reading it stay silent instead of failing.
            for f in state['findings']:
                f['status'] = 'needs_review'
    from vcs import dirty as _dirty, revision as _revision
    for target in state['targets']:
        target['revision'] = _revision(target['path'])
        target['dirty'] = _dirty(target['path'])
    mats, skipped = inventory(workspace, state['targets'], state['exclusions'])
    old = state['materials']
    previous = {mid: row for mid, row in old.items() if row['status'] == 'present'}
    changed = {mid for mid in set(mats) | set(previous)
               if mid not in mats or mid not in previous or
               (mats[mid].get('sha256'), mats[mid].get('access_error')) !=
               (previous[mid].get('sha256'), previous[mid].get('access_error'))}
    available = pin_bundle(workspace)
    framework_changed = available['baseline_id'] != state['framework']['baseline_id']
    new_framework_notice = framework_changed and (adopt or available['baseline_id'] != (state.get('pending_framework') or {}).get('baseline_id'))
    # Recorded, not acted on: see the note in records.validate. The baseline carries
    # the guarantee; this only says which skill version produced the record.
    current_skill = skill_fingerprint()
    if changed or new_framework_notice:
        archive(workspace, state, 'before-refresh')
    for mid, row in old.items():
        if mid not in mats:
            mats[mid] = {**row, 'status': 'removed'}
    stale_evidence = set()
    for evidence in state['evidence']:
        if evidence.get('material_id') in changed:
            evidence['status'] = 'needs_review'
            stale_evidence.add(evidence['id'])
    affected = {i['id'] for i in state['instances'] if changed.intersection(i.get('material_ids', []))}
    assigned = {m for i in state['instances'] for m in i.get('material_ids', [])}
    # A changed shared provider can invalidate its consumers; include the entire
    # connected boundary until the auditor has established a narrower impact.
    while True:
        expanded = set(affected)
        for edge in state['connections']:
            if edge['from_instance'] in affected or edge['to_instance'] in affected or stale_evidence.intersection(edge.get('evidence_ids', [])):
                expanded.update([edge['from_instance'], edge['to_instance']])
        if expanded == affected:
            break
        affected = expanded
    invalidated = []
    for check in state['checks']:
        if (new_framework_notice or changed - assigned
                or affected.intersection(check['instance_ids'])
                or stale_evidence.intersection(check_evidence_ids(check))):
            check['status'] = 'needs_review'
            check['review_reason'] = '材料、依赖边界或知识版本变化；旧结论保留，须回源复核。'
            invalidated.append(check['id'])
    for item in state['coverage']:
        if changed.intersection(item.get('material_ids', [])) or new_framework_notice:
            item['status'] = 'needs_review'
    for finding in state['findings']:
        if set(finding['check_ids']).intersection(invalidated) or stale_evidence.intersection(finding['evidence_ids']):
            if finding['status'] != 'withdrawn':
                finding['status'] = 'needs_review'
    for control in state['controls']:
        if (set(control.get('check_ids', [])).intersection(invalidated)
                or stale_evidence.intersection(control.get('evidence_ids', []))):
            control['effectiveness'] = 'needs_review'
    state.update(materials=mats, inventory_exclusions=skipped, skill_fingerprint=current_skill)
    state['pending_framework'] = available if framework_changed and not adopt else None
    if adopt:
        state['framework'] = available
    save(workspace, state)
    return {'changed_materials': sorted(changed), 'checks_needing_review': invalidated,
            'pending_framework': state['pending_framework'], 'adopted': adopt and framework_changed,
            'schema_migrated': migrated,
            'dropped_read_receipts': dropped_reads if migrated else 0}


def new_check(cid, instance, mode, baseline):
    return {
        'id': cid, 'instance_ids': [instance], 'failure_mode_id': mode['id'], 'baseline_id': baseline,
        'local_definition': None, 'applicability': 'unknown',
        # Seed coverage tasks, not a mandatory checklist copied from the catalogue.
        'prerequisites': [], 'criteria': [],
        'status': 'not_started', 'verdict': None, 'scope': [], 'explanation': '',
        'evidence_ids': [], 'counterevidence_ids': [], 'missing_evidence': [],
    }


def route_objects(state, data):
    """Objects the recorded profile places outside this round's plan, with the basis.

    Unknown capability is not absence: a dimension with no recorded value, or a value
    without evidence, rules nothing out. Routing never writes `not_applicable` either
    - that verdict needs counterevidence on a specific check. It only decides what is
    planned, and every exclusion keeps the dimension and evidence that justified it.
    """
    governed, enabled = {}, set()
    for dimension in data['audit_profile']['dimensions']:
        affects = dimension.get('affects_ids') or {}
        if not affects:
            continue
        record = state['profile'].get(dimension['id']) or {}
        value = record.get('value')
        values = value if isinstance(value, list) else ([value] if value else [])
        decided = bool(values) and bool(record.get('evidence_ids'))
        for option, object_ids in affects.items():
            for oid in object_ids:
                governed.setdefault(oid, set()).add(dimension['id'])
                if not decided or option == '*' or option in values:
                    enabled.add(oid)
    return {oid: sorted(dims) for oid, dims in governed.items() if oid not in enabled}


def _next_check_id(token, taken):
    if token:
        from units import allocate
        return allocate('CHK', token, taken, width=4)
    number = len(taken) + 1
    while f'CHK-{number:04d}' in taken:
        number += 1
    return f'CHK-{number:04d}'


def _plan_checks(data, instances, checks, baseline, excluded, rebase=False):
    """One candidate check per instance x mapped object x proposition.

    Ids carry the owning unit's token when the instance declares one, so two units
    being audited at the same time cannot allocate the same check id.
    """
    taken = {c['id'] for c in checks}
    made, rebased, skipped = [], [], []
    for instance in instances:
        token = None
        if instance.get('unit_id'):
            from units import unit_token
            token = unit_token(instance['unit_id'])
        for oid in instance['framework_object_ids']:
            if oid not in objects(data):
                raise ValueError('Unknown framework object: ' + oid)
            if oid in excluded:
                skipped.append({'instance_id': instance['id'], 'object_id': oid,
                                'dimensions': excluded[oid]})
                continue
            for mode in data['failure_modes'].values():
                if mode['object_id'] != oid:
                    continue
                matches = [c for c in checks if c['instance_ids'] == [instance['id']] and c.get('failure_mode_id') == mode['id']]
                if matches:
                    for c in matches:
                        if rebase and c['baseline_id'] != baseline:
                            replacement = new_check(c['id'], instance['id'], mode, baseline)
                            c.clear()
                            c.update(replacement)
                            rebased.append(c['id'])
                    continue
                cid = _next_check_id(token, taken)
                taken.add(cid)
                checks.append(new_check(cid, instance['id'], mode, baseline))
                made.append(cid)
    return made, rebased, skipped


def seed(workspace, state, rebase=False, unit=None, route=False):
    baseline = state['framework']['baseline_id']
    data, _, _ = load_bundle(baseline_dir(workspace, baseline))
    if rebase:
        archive(workspace, state, 'before-rebase')
    excluded = route_objects(state, data) if route else {}
    instances = [i for i in state['instances'] if unit is None or i.get('unit_id') == unit]
    if unit is not None and not instances:
        raise ValueError('No instances are registered for ' + unit)
    made, rebased, skipped = _plan_checks(data, instances, state['checks'], baseline, excluded, rebase)
    if route:
        state['route_excluded'] = [
            {'object_id': oid, 'dimensions': dims,
             'evidence_ids': sorted({e for d in dims for e in state['profile'][d]['evidence_ids']}),
             'note': '画像已记录且有证据的能力范围未覆盖该对象，本轮不生成其命题检查；'
                     '这不是不适用判定，画像或范围变化后重跑 seed --route'}
            for oid, dims in sorted(excluded.items())]
    for f in state['findings']:
        if set(f['check_ids']).intersection(rebased):
            f['status'] = 'needs_review'
    save(workspace, state)
    return {'created': made, 'reset_for_new_baseline': rebased,
            'scope': unit or 'whole audit', 'route_excluded_objects': sorted(excluded),
            'instances_without_checks': [row['instance_id'] for row in skipped]}


def seed_partial(workspace, state, partial, route=False):
    """Materialise a unit's checks inside its own product; the shared record is untouched."""
    path = Path(partial)
    payload = read(path)
    unit_id = payload.get('unit_id')
    units = {u['id']: u for u in state.get('units', [])}
    if unit_id not in units:
        raise ValueError('The product names no known unit: ' + str(unit_id))
    baseline = state['framework']['baseline_id']
    data, _, _ = load_bundle(baseline_dir(workspace, baseline))
    excluded = route_objects(state, data) if route else {}
    instances = payload.get('instances') or []
    for instance in instances:
        instance.setdefault('unit_id', unit_id)
        if instance['unit_id'] != unit_id:
            raise ValueError(str(instance.get('id')) + ': instance belongs to another unit')
    checks = payload.setdefault('checks', [])
    made, _, skipped = _plan_checks(data, instances, checks, baseline, excluded)
    write_json(path, payload)
    return {'unit': unit_id, 'created': made, 'checks': len(checks),
            'route_excluded_objects': sorted({row['object_id'] for row in skipped})}


def dispatch(workspace, state, unit_ids, round_number=None):
    """Write each unit's brief. That file is the worker's whole input: cold-started
    subagents inherit nothing, so the knowledge is pre-cut here rather than queried
    by the worker."""
    from knowledge import brief as compose_brief
    from units import write_brief
    units = {u['id']: u for u in state.get('units', [])}
    if not unit_ids:
        raise ValueError('dispatch requires at least one --unit')
    if (state.get('queue') or {}).get('phase2_rows_frozen') is None:
        raise ValueError('Freeze the phase 2 queue before dispatching')
    written = []
    for uid in unit_ids:
        unit = units.get(uid)
        if unit is None:
            raise ValueError('Unknown unit: ' + uid)
        if unit['phase'] == 3 and state['queue'].get('phase3_rows_frozen') is None:
            raise ValueError(uid + ': freeze the phase 3 queue before dispatching it')
        slice_path = workspace / 'surface' / (uid + '.json')
        result = write_brief(workspace, state, unit, compose_brief(workspace, state, unit),
                             str(slice_path) if slice_path.is_file() else None)
        unit['status'] = 'dispatched'
        if round_number is not None:
            unit['round'] = round_number
        written.append({'unit': uid, **result})
    if round_number is not None:
        rounds = state.setdefault('rounds', [])
        row = next((r for r in rounds if r['n'] == round_number), None)
        if row is None:
            rounds.append({'n': round_number, 'phase': max(units[u]['phase'] for u in unit_ids),
                           'unit_ids': sorted(unit_ids), 'started_at': now(), 'returns': []})
        else:
            row['unit_ids'] = sorted(set(row['unit_ids']) | set(unit_ids))
    save(workspace, state)
    return {'dispatched': written, 'round': round_number,
            'note': '派单时给绝对路径；brief 之外不要再让 worker 全量查询框架知识'}


def propositions_main_argv(entry, workspace):
    """Run the proposition survey with its own argv, so one implementation serves both."""
    import sys as _sys
    saved = _sys.argv
    _sys.argv = ['propositions.py', str(workspace)]
    try:
        return entry()
    finally:
        _sys.argv = saved


def build_parser():
    """The command surface, as an object. Separated from main so a check can enumerate it:
    an option nobody is ever told to use is dead weight, and the only way to notice is to
    compare what the tool offers against what the protocol and the contracts route."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'refresh', 'plan', 'cluster', 'cross',
                                            'surface', 'dispatch', 'seed', 'merge', 'gate',
                                            'validate', 'report', 'snapshot', 'review',
                                            'sarif', 'propositions', 'recall', 'decide',
                                            'note'])
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--name', default='target')
    parser.add_argument('--target', action='append', default=[])
    parser.add_argument('--exclude', action='append', default=[])
    parser.add_argument('--adopt-framework', action='store_true')
    parser.add_argument('--rebase', action='store_true')
    parser.add_argument('--finding')
    parser.add_argument('--review-file', type=Path)
    parser.add_argument('--pack', action='store_true',
                        help='retired: use plan --apply with model-authored boundaries')
    parser.add_argument('--replace-all', action='store_true',
                        help='recall --apply: treat the product as the complete set '
                             'instead of merging by pattern id (needed to withdraw one)')
    parser.add_argument('--text', help='note: one method note for the record; it is '
                                       'rendered in the final report')
    parser.add_argument('--decision', help='decide: the DEC-… row to answer')
    parser.add_argument('--resolution',
                        help='decide: the answer. object_scope takes involved/'
                             'not_involved, exposure EXT/ADJ/INT, depth triage/standard/'
                             'deep, object_mapping a comma separated object list or '
                             '"none", cluster_representative a member unit, '
                             'out_of_scope_candidate in_scope/out_of_scope')
    parser.add_argument('--reason', help='decide: why. Required — an answer without one '
                                         'is refused')
    parser.add_argument('--apply', type=Path,
                        help='plan: explicit partition JSON; recall: optional target patterns JSON')
    parser.add_argument('--matches', metavar='SYMBOL', help='recall: locate textual matching lines; not call counts')
    parser.add_argument('--call-form', metavar='REGEX', help='recall --matches: explicit search expression')
    parser.add_argument('--brief', action='store_true',
                        help="recall: cut the recall agent's input to units/_recall/brief.md")
    parser.add_argument('--status', action='store_true',
                        help="recall: compare the kept knowledge base against the target's "
                             'current revision and list what must be re-recalled')
    parser.add_argument('--prepare', action='store_true',
                        help='review: emit a verification worklist; gate: check report readiness '
                             'while leaving presentation todos open')
    parser.add_argument('--withdraw', metavar='REASON',
                        help='review: withdraw this finding\'s review (with the reason) so '
                             'it can be reworked; the withdrawn review stays in the ledger')
    parser.add_argument('--replace', action='store_true',
                        help='merge / review --prepare: trial an atomic replacement; '
                             'changed reviewed conclusions require review withdrawal')
    parser.add_argument('--unit', action='append', default=[])
    parser.add_argument('--partial', type=Path)
    parser.add_argument('--round', type=int)
    parser.add_argument('--route', action='store_true')
    parser.add_argument('--freeze', action='store_true')
    parser.add_argument('--phase', type=int, choices=[1, 2, 3], default=1)
    parser.add_argument('--group-depth', type=int, default=1)
    parser.add_argument('--artifact-depth', type=int, default=2)
    parser.add_argument('--threshold', type=float, default=0.8)
    parser.add_argument('--rebuild', action='store_true',
                        help='plan: rebuild every unit from the directory shape, '
                             'discarding any --split results (asked for explicitly)')
    parser.add_argument('--split')
    parser.add_argument('--by', choices=['directory', 'file'], default='directory')
    parser.add_argument('--cross-type')
    parser.add_argument('--title')
    parser.add_argument('--seed-file', type=Path)
    return parser


def main():
    from records import validate, render_report, summary
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.adopt_framework and args.command != 'refresh':
            raise ValueError('--adopt-framework is only valid with refresh')
        if args.rebase and args.command != 'seed':
            raise ValueError('--rebase is only valid with seed')
        if (args.target or args.exclude) and args.command != 'init':
            raise ValueError('--target and --exclude are init options; edit the declared targets/exclusions before refresh')
        if (args.freeze or args.split) and args.command != 'plan':
            raise ValueError('--freeze and --split are only valid with plan')
        if args.freeze and args.split:
            raise ValueError('Split the unit first, then freeze')
        if args.route and args.command != 'seed':
            raise ValueError('--route is only valid with seed')
        if args.partial and args.command not in {'seed', 'merge'}:
            raise ValueError('--partial is only valid with seed and merge')
        if args.prepare and args.command not in {'review', 'gate'}:
            raise ValueError('--prepare is only valid with review and gate')
        workspace = workspace_path(args.workspace)
        if args.command != 'init':
            checked = read(workspace / 'audit.json')
            if checked.get('schema_version') not in set(MIGRATABLE) | {SCHEMA_VERSION}:
                raise ValueError('Unsupported target knowledge schema')
            if checked.get('schema_version') != SCHEMA_VERSION and args.command != 'refresh':
                raise ValueError('Run refresh to migrate the old target schema')
        if args.command == 'gate':
            # One implementation, three exit codes, both entry points identical:
            # 0 passed, 1 read fine but not closed, 2 could not read or parse.
            from gate import main as gate_main
            return gate_main(['gate', str(workspace)] + (['--prepare'] if args.prepare else []))
        if args.command == 'note':
            # The orchestrator's own method notes had no write path: only a worker's
            # product could carry `method_notes`, while the protocol told the main agent
            # to record things there — so the first full phase-1 run had to park "why the
            # unit count cannot reach 24" in a side file, and the final report (which
            # renders method_notes) never saw it.
            state = read(workspace / 'audit.json')
            if not str(args.text or '').strip():
                raise ValueError('note requires --text')
            notes = state.setdefault('method_notes', [])
            text = args.text.strip()
            if text not in notes:
                notes.append(text)
            save(workspace, state)
            print(json.dumps({'method_notes': len(notes), 'added': text not in notes[:-1]},
                             ensure_ascii=False, indent=2))
            return 0
        if args.command == 'decide':
            from decide import decide as record_decision
            state = read(workspace / 'audit.json')
            if not (args.decision and args.resolution):
                raise ValueError('decide requires --decision and --resolution, '
                                 'plus --reason')
            result = record_decision(workspace, state, args.decision,
                                     args.resolution, args.reason or '')
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == 'recall':
            from recall import apply_patterns, brief as recall_brief, status, search_call_sites
            state = read(workspace / 'audit.json')
            if args.matches:
                selected = None
                if args.unit:
                    unit_map = {u['id']: u for u in state.get('units', [])}
                    if set(args.unit) - set(unit_map):
                        raise ValueError('Unknown unit in recall --matches')
                    selected = [m for uid in args.unit for m in unit_map[uid]['material_ids']]
                result = search_call_sites(workspace, state, [args.matches],
                                           {args.matches: args.call_form}, selected)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.status:
                print(json.dumps(status(workspace, state), ensure_ascii=False, indent=2))
                return 1 if status(workspace, state)['unresolved'] else 0
            if args.brief:
                print(json.dumps(recall_brief(workspace, state), ensure_ascii=False, indent=2))
                return 0
            if not args.apply:
                raise ValueError('recall takes --apply <patterns.json> or --status')
            result = apply_patterns(workspace, state, args.apply,
                                    replace_all=bool(args.replace_all))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == 'propositions':
            # One implementation, both entry points: 0 accounted for, 1 some divergence
            # has no written account, 2 could not read the record.
            from propositions import main as propositions_main
            return propositions_main_argv(propositions_main, workspace)
        if args.command == 'init':
            result = initialize(workspace, args.name, args.target, args.exclude)
        else:
            state = read(workspace / 'audit.json')
            if state.get('schema_version') not in set(MIGRATABLE) | {SCHEMA_VERSION}:
                raise ValueError('Unsupported target knowledge schema')
            if state['schema_version'] in MIGRATABLE and args.command != 'refresh':
                raise ValueError('Run refresh to migrate the old target schema')
            if args.command == 'refresh':
                result = refresh(workspace, state, args.adopt_framework)
            elif args.command == 'plan':
                from units import freeze, pack_units, plan_census, split_unit, apply_plan
                if sum(bool(v) for v in (args.apply, args.split, args.pack, args.freeze)) > 1:
                    raise ValueError('Choose one plan action: --apply, --split, --pack, --freeze')
                if args.apply:
                    result = apply_plan(workspace, state, read(args.apply))
                elif args.split:
                    result = split_unit(workspace, state, args.split, args.by)
                elif args.pack:
                    result = pack_units(workspace, state)
                elif args.freeze:
                    result = freeze(workspace, state, args.phase)
                else:
                    result = plan_census(workspace, state, args.group_depth,
                                         args.artifact_depth, args.rebuild)
            elif args.command == 'cluster':
                from units import cluster
                result = cluster(workspace, state, args.threshold)
            elif args.command == 'cross':
                from units import add_cross
                if not args.cross_type or not args.title:
                    raise ValueError('cross requires --cross-type and --title')
                result = add_cross(workspace, state, args.cross_type, args.title,
                                   read(args.seed_file) if args.seed_file else {})
            elif args.command == 'surface':
                from surface import build
                result = build(workspace, state, args.unit or None)
            elif args.command == 'dispatch':
                result = dispatch(workspace, state, args.unit, args.round)
            elif args.command == 'merge':
                from merge import merge_unit
                if len(args.unit) != 1:
                    raise ValueError('merge takes exactly one --unit')
                result = merge_unit(workspace, state, args.unit[0], args.partial,
                                    replace=args.replace)
            elif args.command == 'seed':
                result = (seed_partial(workspace, state, args.partial, args.route) if args.partial
                          else seed(workspace, state, args.rebase,
                                    args.unit[0] if args.unit else None, args.route))
            elif args.command == 'review':
                if args.withdraw:
                    from review import withdraw_review
                    if not args.finding:
                        raise ValueError('review --withdraw requires --finding')
                    result = withdraw_review(workspace, state, args.finding, args.withdraw)
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                    return 0
                if args.prepare:
                    from review_prepare import prepare
                    if len(args.unit) != 1:
                        raise ValueError('review --prepare takes exactly one --unit')
                    result = prepare(workspace, state, args.unit[0], replace=args.replace)
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                    return 0 if result['mechanical'] == 'PASS' else 1
                from review import record_review
                if not args.finding or not args.review_file:
                    raise ValueError('review requires --finding and --review-file, '
                                     'or --prepare with --unit')
                result = record_review(workspace, state, args.finding, read(args.review_file))
            else:
                errors = validate(workspace, state)
                result = {'valid': not errors, 'errors': errors, 'coverage': summary(state, workspace)}
                if errors:
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                    return 1
                if args.command in {'report', 'snapshot', 'sarif'}:
                    from sarif import export_sarif
                    write_json(workspace / 'report.sarif.json', export_sarif(state, workspace))
                    result['sarif'] = str(workspace / 'report.sarif.json')
                if args.command in {'report', 'snapshot'}:
                    report = render_report(state, workspace)
                    from records import render_coverage
                    appendix = render_coverage(state, workspace)
                    for name in ('report.md', 'coverage-details.md'):
                        if (workspace / name).is_symlink():
                            raise ValueError('Report path is a symlink: ' + name)
                    (workspace / 'coverage-details.md').write_text(appendix, encoding='utf-8')
                    (workspace / 'report.md').write_text(report, encoding='utf-8')
                    result['report'] = str(workspace / 'report.md')
                    result['coverage_details'] = str(workspace / 'coverage-details.md')
                    if args.command == 'snapshot':
                        result['snapshot'] = str(archive(workspace, state, 'audit', report))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
