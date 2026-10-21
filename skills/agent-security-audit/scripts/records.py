"""Target-record consistency checks and a report derived from those records."""
from collections import Counter
import html
import re

from knowledge import baseline_dir, digest, load_bundle, objects, read

SCOPES = {'design', 'code', 'configuration', 'observed_records', 'runtime'}
STATUSES = {'not_started', 'in_progress', 'complete', 'needs_review'}
VERDICTS = {'confirmed', 'not_established', 'insufficient_evidence', 'not_applicable'}
LABELS = {'confirmed': '成立', 'not_established': '不成立（限已检查范围）',
          'insufficient_evidence': '证据不足', 'not_applicable': '不适用',
          'not_started': '尚未检查', 'in_progress': '检查中', 'needs_review': '待复核',
          'complete': '已检查'}


def summary(state, workspace):
    from units import completion_errors
    checks = state['checks']
    present = {mid for mid, m in state['materials'].items() if m['status'] == 'present'}
    accounted = {mid for c in state['coverage'] if c['status'] in {'reviewed', 'excluded'} for mid in c['material_ids']}
    data, _, _ = load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))
    routed_out = {row['object_id'] for row in state.get('route_excluded', [])}
    expected_checks = {(i['id'], m['id']) for i in state['instances'] for m in data['failure_modes'].values()
                       if m['object_id'] in i['framework_object_ids'] and m['object_id'] not in routed_out}
    planned_checks = {(iid, c.get('failure_mode_id')) for c in checks for iid in c['instance_ids']}
    unplanned = expected_checks - planned_checks
    inaccessible = [mid for mid in present if state['materials'][mid].get('access_error')]
    enumeration_errors = [r for r in state['inventory_exclusions'] if r['reason'].startswith('enumeration_failed')]
    observations = state.get('observations', [])
    return {
        'materials': len(present), 'materials_without_completed_coverage': len(present - accounted),
        'checks': len(checks), 'statuses': dict(Counter(c['status'] for c in checks)),
        'verdicts': dict(Counter(c['verdict'] for c in checks if c['status'] == 'complete')),
        'local_checks': sum(c.get('failure_mode_id') is None for c in checks),
        'framework_checks_not_planned': len(unplanned),
        'findings': len(state['findings']),
        'current_findings': sum(f['status'] == 'current' for f in state['findings']),
        'unreadable_materials': len(inaccessible), 'enumeration_errors': len(enumeration_errors),
        'material_visibility': dict(Counter(state['materials'][mid].get('visibility', 'unknown') for mid in present)),
        'dynamic_outcomes': dict(Counter(o['outcome'] for o in observations)),
        'units': len(state.get('units', [])),
        'unit_status': dict(Counter(u['status'] for u in state.get('units', []))),
        'surface_hits': sum(u.get('surface_hits') or 0 for u in state.get('units', [])),
        'hits_disposed': sum(u['progress']['hits_disposed'] for u in state.get('units', [])),
        'unresolved_decisions': sum(not d.get('resolution') for d in state.get('pending_decisions', [])),
        'queue': {k: (state.get('queue') or {}).get(k)
                  for k in ('phase1_frozen', 'phase2_rows_frozen',
                            'phase3_rows_frozen', 'phase3_critic')},
        'routed_out_objects': sorted(routed_out),
        'chains': len(state.get('chains', [])),
        'scope_notes': len(state.get('scope_notes', [])),
        'scope_review_complete': bool(present and state['instances'] and checks)
            and not (present - accounted) and not unplanned and all(c['status'] == 'complete' for c in checks)
            and not inaccessible and not enumeration_errors and not state.get('pending_framework')
            and all(f['status'] != 'needs_review' for f in state['findings'])
            and not any(completion_errors(u, require_merged=True) for u in state.get('units', [])),
    }


def _target_drift(workspace, state):
    """Messages for targets that moved since they were indexed, cheapest path first."""
    from vcs import dirty, revision
    problems = []
    for target in state.get('targets') or []:
        recorded = target.get('revision')
        if not recorded:
            continue                       # not a git target: by decision, not checked
        now = revision(target['path'])
        if now != recorded:
            problems.append('Target %s moved from %s to %s; run refresh before making '
                            'current conclusions' % (target['id'], recorded[:12],
                                                     (now or 'unknown')[:12]))
        elif dirty(target['path']) and not target.get('dirty'):
            problems.append('Target %s has uncommitted changes it did not have when '
                            'indexed; run refresh' % target['id'])
    return problems


def correction_errors(rows):
    """Presence of JSON values differs from truthiness; never stringify originals."""
    if not isinstance(rows, list):
        return ['corrections: must be a list']
    errors = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append('correction: must be an object')
            continue
        cid = str(row.get('id'))
        for field in ('id', 'target', 'field', 'reason', 'by'):
            value = row.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append('%s: a correction needs its %s' % (cid, field))
        for field in ('before', 'after'):
            if field not in row:
                errors.append('%s: a correction needs its %s' % (cid, field))
        if 'before' in row and 'after' in row and row['before'] == row['after'] and type(row['before']) is type(row['after']):
            errors.append(cid + ': a correction that changes nothing')
    return errors


def validate(workspace, state):
    try:
        return _validate(workspace, state)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        return ['Malformed or unreadable audit record: ' + str(exc)]


def _validate(workspace, state):
    from audit import SCHEMA_VERSION, inventory, material_path, check_evidence_ids, check_counterevidence_ids
    errors = []
    def require(test, message):
        if not test:
            errors.append(message)
    def index(name):
        rows = state[name]
        result = {r['id']: r for r in rows}
        require(len(result) == len(rows), 'Duplicate ids: ' + name)
        require(all(isinstance(k, str) and k for k in result), 'Invalid ids: ' + name)
        return result
    require(state['schema_version'] == SCHEMA_VERSION, 'Unsupported target schema; run refresh to migrate')
    # The skill fingerprint is recorded as provenance, not judged. It hashed every file
    # in the skill, so editing one line of prose put every finished check back into
    # review — while what actually decides whether a conclusion still holds is the
    # pinned framework baseline, which each check records and which `require(fingerprint
    # == key)` above already enforces. A changed proposition is a new baseline id and
    # `seed --rebase` resets those checks; changed prose cannot make an evidence-backed
    # verdict false.
    materials = state['materials']
    for mid, m in materials.items():
        require(mid == m['id'] and m['status'] in {'present', 'removed'}, 'Invalid material: ' + mid)
    # Did the target change under us? Re-enumerating and re-hashing 1891 files answered
    # that in 25-40 seconds on every call. For a git target the repository already knows:
    # HEAD plus a dirty check is 2.3 seconds and covers renames and deletions too. The
    # answer is only as good as git's view of the tree, so the cheap path is taken only
    # when every material is tracked — measured on a real target, 1891 of 1891 were, but
    # that is a property of the target, not a guarantee of the skill, so it is checked
    # rather than assumed. Non-git targets are not checked at all: a deliberate choice,
    # stated in `orchestration.md` as an assumption rather than left implicit here.
    drifted = _target_drift(workspace, state)
    for message in drifted:
        require(False, message)
    instances, evidence, checks, findings = [index(k) for k in ('instances', 'evidence', 'checks', 'findings')]
    for name in ('connections', 'assets', 'controls', 'attackers', 'hypotheses', 'coverage', 'dismissed_candidates'):
        index(name)
    baselines = {}
    def baseline(key):
        if key not in baselines:
            data, _, fingerprint = load_bundle(baseline_dir(workspace, key))
            require(fingerprint == key, 'Baseline directory does not match payload')
            baselines[key] = data
        return baselines[key]
    current = baseline(state['framework']['baseline_id'])
    def refs(ids, catalog, owner):
        require(isinstance(ids, list), owner + ': references must be an array')
        for rid in ids:
            require(rid in catalog, owner + ': unknown reference ' + str(rid))
    for inst in instances.values():
        require(bool(inst.get('name')), inst['id'] + ': missing instance name')
        refs(inst['framework_object_ids'], objects(current), inst['id'])
        refs(inst['material_ids'], materials, inst['id'])
        refs(inst.get('evidence_ids', []), evidence, inst['id'])
        require(bool(inst['framework_object_ids']) or bool(inst.get('mapping_gap')), inst['id'] + ': explain unmapped responsibility')
    for group in ('assets', 'controls', 'attackers', 'hypotheses'):
        for row in state[group]:
            require(bool(row.get('description')), row['id'] + ': missing description')
            refs(row.get('instance_ids', []), instances, row['id'])
            refs(row.get('evidence_ids', []), evidence, row['id'])
    for edge in state['connections']:
        refs([edge['from_instance'], edge['to_instance']], instances, edge['id'])
        refs(edge.get('evidence_ids', []), evidence, edge['id'])
        require(bool(edge.get('description')), edge['id'] + ': missing connection semantics')
    for profile in state['profile'].values():
        refs(profile['evidence_ids'], evidence, 'profile')
        require(profile.get('value') is not None or bool(profile.get('unknown_reason')), 'Unknown profile value needs a reason')
        require(profile.get('value') is None or bool(profile['evidence_ids']), 'Profile assertions need target evidence')
    from units import (DEPTHS, DIMENSIONS, DIMENSION_STATES, EXPOSURES, KINDS, PRIMITIVES,
                       CROSS_TYPES, STATUSES as UNIT_STATUSES, id_owner, partition_errors)
    unit_index = index('units') if state.get('units') else {}
    for row in state.get('units', []):
        uid = row['id']
        require(row['kind'] in KINDS, uid + ': invalid unit kind')
        require(row['status'] in UNIT_STATUSES, uid + ': invalid unit status')
        require(row['phase'] in {2, 3}, uid + ': invalid phase')
        require(row['exposure'] in EXPOSURES, uid + ': invalid exposure level')
        require(row['exposure'] == 'unknown' or bool(row.get('exposure_reason')),
                uid + ': an exposure level needs its basis')
        require(row['depth'] is None or row['depth'] in DEPTHS, uid + ': invalid depth')
        require(row['depth'] is None or bool(row.get('depth_reason')), uid + ': depth needs its reason')
        require(row['kind'] != 'cross' or row.get('cross_type') in CROSS_TYPES,
                uid + ': a cross unit needs a cross_type')
        refs(row['material_ids'], materials, uid)
        refs(row['object_ids'], objects(current), uid)
        require(bool(row['object_ids']) or bool(row.get('mapping_note')) or row['kind'] == 'cross',
                uid + ': map responsibilities or record why none apply')
        for name, dimension in (row.get('dimensions') or {}).items():
            require(name in DIMENSIONS, uid + ': unknown analysis dimension ' + str(name))
            require(dimension.get('state') in DIMENSION_STATES,
                    uid + ': invalid dimension state for ' + str(name))
            require(dimension.get('state') != 'na' or bool(dimension.get('reason')),
                    uid + ': an n.a. dimension needs its reason for ' + str(name))
        require(row['progress']['files_done'] <= row['file_count'],
                uid + ': more files processed than the unit owns')
    for message in (partition_errors(state) if state.get('units') else []):
        require(False, 'Unit partition: ' + message)
    for row in state.get('primitives', []):
        require(row.get('primitive') in PRIMITIVES, str(row.get('id')) + ': invalid attack primitive')
        refs(row.get('evidence_ids', []), evidence, str(row.get('id')))
        require(not unit_index or row.get('unit_id') in unit_index,
                str(row.get('id')) + ': unknown unit')
    for row in state.get('chains', []):
        cid = str(row.get('id'))
        require(bool(row.get('title')) and bool(row.get('steps')), cid + ': a chain needs a title and steps')
        require(row.get('entry_exposure') in EXPOSURES, cid + ': a chain needs its entry exposure')
        for step in row.get('steps', []):
            if step.get('check_id'):
                refs([step['check_id']], checks, cid)
            if step.get('finding_id'):
                refs([step['finding_id']], findings, cid)
            require(not step.get('primitive') or step['primitive'] in PRIMITIVES,
                    cid + ': invalid primitive on a step')
    for row in state.get('clusters', []):
        refs(row['member_unit_ids'], unit_index, row['id'])
        if row.get('representative_unit_id'):
            refs([row['representative_unit_id']], unit_index, row['id'])
    for target in state.get('targets', []):
        rev = target.get('revision')
        require(rev is None or (isinstance(rev, str) and len(rev) == 40),
                target['id'] + ': revision must be a full commit id or null')
    # An answered decision must be reflected where the record keeps the answer. Hand
    # editing `audit.json` writes the decision row and works — it just leaves the field
    # that actually governs behaviour untouched, and nothing downstream reads the row.
    # So the invariant is checked rather than merely documented.
    units_by_id = {u['id']: u for u in state.get('units', [])}
    scoped = {str(r.get('subject')) for r in state.get('object_scope', [])}
    clusters_by_id = {c['id']: c for c in state.get('clusters', [])}
    for row in state.get('pending_decisions', []):
        answer, kind, subject = row.get('resolution'), row.get('kind'), str(row.get('subject'))
        if not answer:
            continue
        where = '%s（%s %s）' % (row.get('id'), kind, subject)
        if kind == 'exposure':
            unit = units_by_id.get(subject) or {}
            require(unit.get('exposure') == answer,
                    where + ': 答案没有落到单元的 exposure 上')
        elif kind == 'depth':
            unit = units_by_id.get(subject) or {}
            require(unit.get('depth') == answer, where + ': 答案没有落到单元的 depth 上')
        elif kind == 'object_mapping':
            unit = units_by_id.get(subject) or {}
            require(bool(unit.get('object_ids')) or bool(str(unit.get('mapping_note') or '').strip()),
                    where + ': 答案没有落到单元的 object_ids 或 mapping_note 上')
        elif kind == 'object_scope':
            require(answer == 'involved' or subject in scoped,
                    where + ': 判了不涉及却没有 object_scope 条目')
        elif kind == 'cluster_representative':
            cluster = clusters_by_id.get(subject) or {}
            require((answer == 'none' and cluster.get('decision') == 'declined') or
                    cluster.get('representative_unit_id') == answer,
                    where + ': 答案没有落到簇的 representative_unit_id 上')
    unit_ids = {u['id'] for u in state.get('units', [])}
    for row in state.get('crossleads', []):
        if not isinstance(row, dict):
            continue
        where = 'crosslead ' + str(row.get('note') or row.get('observation') or '')[:40]
        # A cross-unit capability combination cannot give both ends by construction, so
        # it may name the units it still needs plus the phase-3 segment that judges it.
        # Without this the observation had nowhere to go and one was lost to a dimension
        # reason on a real run.
        if row.get('needs_units') or row.get('cross_type'):
            require(bool(row.get('reachable_from')),
                    str(row.get('id', '?')) + ': 跨单元线索仍要给你这端的 file:line')
            require(isinstance(row.get('needs_units'), list) and row['needs_units'],
                    str(row.get('id', '?')) + ': 跨单元线索要点名还需要哪几片（needs_units）')
            require(row.get('cross_type') in CROSS_TYPES,
                    str(row.get('id', '?')) + ': cross_type 必须是 '
                    + '、'.join(CROSS_TYPES))
        require('from_unit' in row or 'unit_id' in row,
                where + ': 交接要记谁看到的（from_unit）')
        target = row.get('to_unit')
        require(target is None or target in unit_ids,
                where + ': to_unit 指向不存在的单元 %s' % target)
    for row in state.get('object_scope', []):
        subject = str(row.get('subject') or '')
        require(bool(subject), str(row.get('id')) + ': an object scope row needs its subject')
        require(row.get('decision') in {'involved', 'not_involved'},
                subject + ': object scope decision must be involved or not_involved')
        require(bool(str(row.get('reason') or '').strip()),
                subject + ': ruling an object out needs its basis')
    from merge import dismissed_errors
    errors.extend(dismissed_errors(state))
    modes = {c.get('failure_mode_id') for c in state.get('checks', [])}
    for row in state.get('reconciliations', []):
        rid = str(row.get('id'))
        require(row.get('failure_mode_id') in modes,
                rid + ': accounts for a proposition no check refers to')
        status = row.get('status', 'complete')
        require(status in {'open', 'complete'}, rid + ': invalid reconciliation status')
        require(bool(str(row.get('reason' if status == 'open' else 'explanation') or '').strip()),
                rid + ': reconciliation needs reason (open) or explanation (complete)')
        refs(row.get('check_ids', []), checks, rid)
        require(status != 'open' or bool(row.get('check_ids')),
                rid + ': an explicit reconciliation task needs check_ids')
        require(bool(row.get('by')), rid + ': a reconciliation needs who wrote it')
    for row in state.get('withdrawn_reviews', []):
        require(bool(str(row.get('withdrawn_reason') or '').strip()),
                str(row.get('id')) + ': a withdrawn review needs its reason')
        require(bool(row.get('withdrawn_at')),
                str(row.get('id')) + ': a withdrawn review needs its timestamp')
    errors.extend(correction_errors(state.get('corrections', [])))
    for row in state.get('report_todos', []):
        tid = str(row.get('id'))
        require(bool(row.get('instruction')), tid + ': a report todo needs its instruction')
        require(row.get('status') in {'open', 'applied', 'dropped'},
                tid + ': invalid report todo status')
        require(row.get('status') != 'dropped' or bool(row.get('reason')),
                tid + ': a dropped report todo needs its reason')
    for row in state.get('pending_decisions', []):
        did = str(row.get('id'))
        require(bool(row.get('question')), did + ': a decision needs its question')
        require(not row.get('resolution') or bool(row.get('reason')),
                did + ': a resolved decision needs its reason')
    for name in ('instances', 'checks', 'evidence', 'findings', 'coverage'):
        for row in state[name]:
            token = id_owner(row['id'])
            require(not token or not unit_index or ('U-' + token) in unit_index,
                    row['id'] + ': id carries an unknown unit token')
    for unit in state['coverage']:
        require(unit['status'] in {'not_started', 'in_progress', 'reviewed', 'excluded', 'needs_review'}, unit['id'] + ': invalid coverage status')
        require(bool(unit['material_ids']), unit['id'] + ': empty coverage unit')
        refs(unit['material_ids'], materials, unit['id'])
        refs(unit.get('check_ids', []), checks, unit['id'])
        if unit['status'] in {'reviewed', 'excluded'}:
            require(bool(unit.get('reason')), unit['id'] + ': completed coverage needs its scope and reason')
        if unit['status'] == 'reviewed':
            # Unconditional. This used to fire only when read receipts did not cover the
            # material, and receipts reached 39 of 386 covered materials on a real run —
            # absent on exactly the unit where reading was least complete, 78k lines read
            # by range. So the discipline rested on the mechanism that was missing where
            # it mattered. Claiming a material reviewed now always says how and what was
            # left out: "didn't look" and "looked and found nothing" are the two readings
            # this keeps apart.
            require(bool(unit.get('analysis_method')) and bool(unit.get('limitations')),
                    unit['id'] + ': reviewed coverage needs analysis_method and limitations')
    for row in state['controls']:
        # `scope` means two different things: on a check it is the array of evidence
        # kinds, on a control it is prose about where the guarantee holds. Two of the
        # three units that registered controls wrote `["code"]` here, which renders as
        # 「范围：["code"]」 and says nothing. Nothing else distinguishes the two senses.
        scope = row.get('scope')
        require(not (isinstance(scope, list) and set(scope) <= SCOPES),
                row['id'] + ": a control's scope is prose about where the guarantee holds, "
                            'not the evidence-kind array used on checks')
    for eid, row in evidence.items():
        require(row['kind'] in SCOPES, eid + ': invalid evidence kind')
        require(row['status'] in {'current', 'needs_review'}, eid + ': invalid evidence status')
        require(bool(row.get('observation')), eid + ': missing observation')
        locator = row['locator']
        require(isinstance(locator, dict) and any(locator.get(k) for k in ('lines', 'section', 'page', 'json_pointer')), eid + ': missing location')
        if locator.get('lines'):
            lines = locator['lines']
            require(len(lines) == 2 and all(isinstance(n, int) and not isinstance(n, bool) for n in lines) and 1 <= lines[0] <= lines[1], eid + ': invalid line range')
        if row['kind'] == 'runtime':
            from dynamic import artifact_path, pointer, empty_observation
            obs = next((o for o in state['observations'] if o['id'] == row.get('observation_id')), None)
            require(obs is not None and not row.get('material_id'), eid + ': runtime evidence needs a unique observation source')
            if obs:
                require(obs['observation_mode'] != 'simulation' and obs['outcome'] == 'captured', eid + ': simulated or unsuccessful observation cannot prove runtime behavior')
                require(row['sha256'] == obs['sha256'], eid + ': stale runtime evidence')
                if row['status'] == 'current':
                    require(obs['status'] == 'current', eid + ': runtime observation needs review')
                require(bool(locator.get('json_pointer')), eid + ': runtime evidence needs a JSON pointer')
                if locator.get('json_pointer'):
                    value = pointer(read(artifact_path(workspace, obs['path'])), locator['json_pointer'])
                    require(not empty_observation(value), eid + ': empty observation cannot support a runtime conclusion')
            continue
        refs([row['material_id']], materials, eid)
        mat = materials.get(row['material_id'])
        if row['status'] == 'current' and mat:
            require(mat['status'] == 'present' and row['sha256'] == mat['sha256'], eid + ': stale content fingerprint')
            if mat['status'] == 'present':
                path = material_path(state, mat)
                require(digest(path) == row['sha256'], eid + ': file changed')
                if locator.get('lines'):
                    from materials import MAX_BYTES, decode, recovered_view
                    with path.open('rb') as handle:
                        source_text, _ = decode(handle.read(MAX_BYTES + 1), row.get('encoding'))
                    if row.get('view', 'original') == 'recovered':
                        candidate = recovered_view(source_text)
                        require(bool(candidate), eid + ': recovered view no longer available')
                        source_text = candidate['text'] if candidate else ''
                    require(locator['lines'][1] <= len(source_text.splitlines()), eid + ': line beyond end of material')
    for cid, check in checks.items():
        bid = check['baseline_id']
        data = baseline(bid)
        refs(check['instance_ids'], instances, cid)
        require(bool(check['instance_ids']), cid + ': no target instance')
        fid = check.get('failure_mode_id')
        if fid is None:
            definition = check.get('local_definition')
            require(isinstance(definition, dict), cid + ': unmapped check needs a local definition')
            if not isinstance(definition, dict):
                continue
            require(bool(definition.get('statement')) and bool(definition.get('requirement')), cid + ': incomplete local mechanism')
        else:
            require(fid in data['failure_modes'], cid + ': unknown framework proposition')
            if fid not in data['failure_modes']:
                continue
            definition = data['failure_modes'][fid]
            mapped_objects = {o for iid in check['instance_ids'] if iid in instances for o in instances[iid]['framework_object_ids']}
            require(definition['object_id'] in mapped_objects, cid + ': proposition does not belong to the mapped target object')
            require(check.get('local_definition') is None, cid + ': do not override framework propositions in a local field')
        # Optional model-authored notes. Their wording, number and states do not
        # mechanically decide the proposition's applicability or verdict.
        for field, label in (('prerequisites', 'condition'), ('criteria', 'criterion')):
            notes = check.get(field, [])
            require(isinstance(notes, list), cid + ': ' + field + ' must be an array')
            if not isinstance(notes, list):
                continue
            for row in notes:
                require(isinstance(row, dict), cid + ': analysis note must be an object')
                if not isinstance(row, dict):
                    continue
                require(isinstance(row.get(label), str) and bool(row[label].strip()),
                        cid + ': analysis note needs ' + label)
                require(row.get('state') in {'unknown', 'met', 'not_met'}, cid + ': invalid condition state')
                refs(row.get('evidence_ids', []), evidence, cid)
                if row.get('state') in {'met', 'not_met'}:
                    require(bool(row.get('evidence_ids')), cid + ': factual condition needs evidence')
        refs(check.get('evidence_ids', []), evidence, cid)
        refs(check.get('counterevidence_ids', []), evidence, cid)
        require(check['status'] in STATUSES, cid + ': invalid check status')
        require(check['verdict'] is None or check['verdict'] in VERDICTS, cid + ': invalid verdict')
        require(check['applicability'] in {'unknown', 'applicable', 'not_applicable'}, cid + ': invalid applicability')
        require(set(check['scope']) <= SCOPES, cid + ': invalid evidence scope')
        if check['status'] in {'not_started', 'in_progress'}:
            require(check['verdict'] is None, cid + ': uncompleted check cannot have a verdict')
        if check['status'] == 'complete':
            require(bid == state['framework']['baseline_id'], cid + ': conclusion still uses a previous framework baseline')
            require(check['verdict'] in VERDICTS and bool(check['explanation']) and bool(check['scope']), cid + ': incomplete conclusion')
            ids = check_evidence_ids(check)
            require(all(evidence[e]['status'] == 'current' for e in ids if e in evidence), cid + ': conclusion uses stale evidence')
            supported_scopes = {evidence[e]['kind'] for e in ids if e in evidence}
            if check['verdict'] != 'insufficient_evidence':
                require(set(check['scope']) <= supported_scopes, cid + ': claimed scope lacks matching evidence')
            verdict = check['verdict']
            if verdict in {'confirmed', 'not_established'}:
                require(check['applicability'] == 'applicable' and bool(ids), cid + ': finding needs applicable scope and evidence')
                if verdict == 'not_established':
                    require(bool(check_counterevidence_ids(check)), cid + ': not established requires counterevidence')
            elif verdict == 'not_applicable':
                require(check['applicability'] == 'not_applicable' and bool(ids),
                        cid + ': not applicable needs an explicit applicability decision and evidence')
            elif verdict == 'insufficient_evidence':
                require(bool(check['missing_evidence']), cid + ': identify missing evidence')
                require(check['applicability'] != 'not_applicable', cid + ': known non-applicability has its own verdict')
    for fid, finding in findings.items():
        refs(finding['check_ids'], checks, fid)
        refs(finding['evidence_ids'], evidence, fid)
        require(finding['status'] in {'current', 'needs_review', 'withdrawn'}, fid + ': invalid finding status')
        require(finding['severity'] in {'critical', 'high', 'medium', 'low', 'informational'}, fid + ': invalid severity')
        exposure = finding.get('exposure')
        require(exposure is None or exposure in EXPOSURES, fid + ': invalid exposure level')
        # A rating may not rest on something nobody audited. Excluded paths are named
        # path-shaped, because bare substrings misfire: `nix` matches 「Unix 域」 and
        # `.github` matches `api.github.com`. Mentioning an excluded component to say it
        # was NOT used is correct, so the co-located marker is what makes it legitimate.
        for key in ('title', 'mechanism', 'impact', 'severity_reason', 'remediation', 'responsibility', 'validation'):
            require(bool(finding.get(key)), fid + ': missing ' + key)
        require(bool(finding['check_ids']) and bool(finding['evidence_ids']), fid + ': missing supporting records')
        if finding['status'] == 'current':
            require(all(checks[c]['status'] == 'complete' and checks[c]['verdict'] == 'confirmed' for c in finding['check_ids'] if c in checks), fid + ': current finding requires confirmed checks')
            require(all(evidence[e]['status'] == 'current' for e in finding['evidence_ids'] if e in evidence), fid + ': current finding uses stale evidence')
    from audit import snapshot_manifest
    history = workspace / 'snapshots'
    if history.is_symlink():
        require(False, 'Snapshot directory is a symlink')
    elif history.exists():
        for directory in sorted(history.iterdir()):
            try:
                manifest = snapshot_manifest(directory)
            except (OSError, ValueError, TypeError) as exc:
                require(False, 'Snapshot integrity: ' + str(exc))
                continue
            for bid in manifest['baseline_ids']:
                baseline(bid)
    from review import validate_extensions
    validate_extensions(workspace, state, require)
    return errors


def _report_text(value):
    import json
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    # Markdown code spans already display angle brackets literally. Escaping inside
    # them would turn <T> into the visible text &lt;T&gt;. Escape only prose.
    parts, end = [], 0
    for match in re.finditer(r'(?<!`)(`+)(?!`)(.*?)(?<!`)\1(?!`)', value, re.S):
        parts.extend((html.escape(value[end:match.start()], quote=False), match.group()))
        end = match.end()
    parts.append(html.escape(value[end:], quote=False))
    return ''.join(parts).replace('|', '\\|')


def render_coverage(state, workspace):
    """Lossless coverage appendix from the same records; no inferred analysis."""
    import json
    from units import _object_scatter
    counts = summary(state, workspace)
    out = ['# 覆盖明细', '', '由 audit.json 生成；记录存在不证明实际分析充分。', '',
           '材料 %d；未完成覆盖 %d；尚未建立的框架检查 %d。'
           % (counts['materials'], counts['materials_without_completed_coverage'],
              counts['framework_checks_not_planned']), '']
    sections = [
        ('调度与单元覆盖', state.get('units', [])),
        ('队列与冻结来源', state.get('queue', {})),
        ('当前对象散布（按单元职责重算）', _object_scatter(state)),
        ('对象范围', state.get('object_scope', [])),
        ('覆盖记录', state.get('coverage', [])),
        ('枚举排除', state.get('inventory_exclusions', [])),
        ('材料可见性', state.get('materials', {})),
        ('检索形态缺口', state.get('form_gaps', [])),
        ('旧契约来源', state.get('contract_history', [])),
    ]
    for title, rows in sections:
        body = json.dumps(rows, ensure_ascii=False, indent=2)
        fence = '`' * max(3, 1 + max((len(m.group()) for m in re.finditer(r'`+', body)), default=0))
        out += ['## ' + title, '', fence + 'json', body, fence, '']
    return '\n'.join(out) + '\n'


def render_report(state, workspace):
    text = _report_text
    counts = summary(state, workspace)
    out = ['# ' + text(state['target_id']) + ' 安全审计', '',
           ('本报告包含静态分析与单独记录的动态观测；各结论的证据范围分别标明。' if state.get('observations') else
            '本报告来自静态分析记录；未启动目标程序、执行目标脚本或发起主动测试。'), '',
           '范围核查状态：' + ('已完成已登记范围的核查。' if counts['scope_review_complete'] else '仍有未检查、待复核或未完成覆盖的范围。'),
           '“已检查”包括证据不足的结论，不代表系统安全或已完成动态验证。', '',
           '框架版本：' + text(state['framework']['version']) + '；知识指纹：`' + state['framework']['baseline_id'] + '`。', '',
           '## 范围与目标画像', '']
    for target in state['targets']:
        out.append('- ' + text(target['id']) + '：`' + text(target['path']) + '`')
    out += ['', '| 画像维度 | 记录 |', '|---|---|']
    for key, value in state['profile'].items():
        out.append('| ' + text(key) + ' | ' + text(value['value'] if value['value'] is not None else value['unknown_reason']) + ' |')
    out += ['', '## 对象与连接', '', '| 实际实例 | 框架对象 | 职责 |', '|---|---|---|']
    for row in state['instances']:
        out.append('| ' + text(row['id'] + ' ' + row['name']) + ' | ' + text(', '.join(row['framework_object_ids']) or row.get('mapping_gap', '')) + ' | ' + text(row.get('responsibility', '')) + ' |')
    for edge in state['connections']:
        out += ['', '- ' + text(edge['from_instance'] + ' → ' + edge['to_instance']) + '：' + text(edge['description'])]
    for key, title in [('assets', '关键资产'), ('attackers', '攻击者与能力'), ('controls', '已有控制与保证边界')]:
        out += ['', '## ' + title, '']
        for row in state[key]:
            out.append('- ' + text(row['id']) + '：' + text(row['description']))
    out += ['', '## 发现（按暴露层级排序，外部可直达在前）', '']
    if not state['findings']:
        out.append('尚无已记录发现。请结合下方覆盖状态与证据缺口阅读。')
    exposure_order = {'EXT': 0, 'ADJ': 1, 'INT': 2}
    for finding in sorted(state['findings'], key=lambda f: exposure_order.get(f.get('exposure'), 3)):
        risk_ids, object_ids = set(), set()
        for check in state['checks']:
            if check['id'] not in finding['check_ids']:
                continue
            for inst in state['instances']:
                if inst['id'] in check['instance_ids']:
                    object_ids.update(inst['framework_object_ids'])
            if check.get('failure_mode_id'):
                data, _, _ = load_bundle(baseline_dir(workspace, check['baseline_id']))
                risk_ids.update(data['failure_modes'][check['failure_mode_id']]['risk_ids'])
        out += ['### ' + text(finding['id'] + ' ' + finding['title']), '',
                '严重度：' + text(finding['severity']) + '；暴露层级：'
                + text(finding.get('exposure') or '未记录') + '；记录状态：' + text(finding['status']) + '。', '',
                text(finding['mechanism']), '', '影响：' + text(finding['impact']), '',
                '定级依据：' + text(finding['severity_reason']), '',
                '检查项：' + text(', '.join(finding['check_ids'])) + '；证据：' + text(', '.join(finding['evidence_ids'])) + '。', '',
                '框架对象：' + text(', '.join(sorted(object_ids)) or '目标本地职责') + '；目录标签（分类参考）：' + text(', '.join(sorted(risk_ids)) or '未映射，本地检查独立判定') + '。', '',
                '责任方：' + text(finding['responsibility']), '',
                '修复：' + text(finding['remediation']), '', '验证说明：' + text(finding['validation']), '',
                '剩余风险：' + text(finding.get('residual_risk', '未另行记录')), '']
        for review in state.get('reviews', []):
            if review['finding_id'] == finding['id']:
                out += ['- 复核 ' + text(review['id']) + '（' + text(review['decision']) + '；' + text(review['reviewer']) + '；' + text(review['created_at']) + '）：' + text(review['rationale']),
                        '  反证核查：' + text(review['counterevidence_analysis']) + '；证据：' + text(', '.join(review['evidence_ids'] + review['counterevidence_ids'])), '']
    if state.get('chains'):
        out += ['## 攻击链', '',
                '每条链标出起点的暴露层级；链上每段都要有已成立的检查支撑，中间不留空白环节。', '']
        for row in state['chains']:
            out += ['### ' + text(row['id'] + ' ' + row['title']), '',
                    '起点暴露层级：' + text(row.get('entry_exposure', '未记录')) + '；终点资产：'
                    + text(row.get('asset_id') or '未记录') + '；状态：' + text(row.get('status', '')) + '。', '']
            for step in row.get('steps', []):
                out.append('- ' + text(step.get('unit_id', '')) + ' / ' + text(step.get('primitive', ''))
                           + '：' + text(step.get('check_id') or step.get('finding_id') or '')
                           + ' ' + text(step.get('note', '')))
            out.append('')
    if state.get('scope_notes'):
        out += ['## 残余前沿清单', '',
                '逐条给落点：观察、为什么不属于任何已有单元、建议下次怎么覆盖。', '']
        for row in state['scope_notes']:
            out.append('- ' + text(row.get('id', '')) + '：' + text(row.get('observation', ''))
                       + '；不属于已有单元的理由：' + text(row.get('why_unowned', ''))
                       + '；下次怎么覆盖：' + text(row.get('next_coverage', '')))
        out.append('')
    out += ['## 控制有效性与反证', '']
    assessed = [c for c in state['controls'] if c.get('effectiveness', 'unassessed') != 'unassessed']
    if not assessed:
        out.append('尚无单独记录的控制有效性评估。')
    for c in assessed:
        out += ['- ' + text(c['id']) + ' / ' + text(c['effectiveness']) + '：' + text(c['description']),
                '  范围：' + text(c.get('scope', '')) + '；依据：' + text(c.get('rationale', '')),
                '  局限：' + text(c.get('limitations', '')) + '；复测：' + text(c.get('retest', '')),
                '  检查：' + text(c.get('check_ids', [])) + '；证据：' + text(c.get('evidence_ids', [])), '']
    out += ['## 检查结论与缺口', '', '| 检查 | 命题 | 状态/结论 | 证据范围 | 解释与缺口 |', '|---|---|---|---|---|']
    for row in state['checks']:
        verdict = LABELS.get(row['verdict'] if row['status'] == 'complete' else row['status'], '尚未检查')
        out.append('| ' + text(row['id']) + ' | ' + text(row.get('failure_mode_id') or '目标本地命题') + ' | ' + verdict + ' | ' + text(', '.join(row['scope'])) + ' | ' + text(row['explanation'] + ' ' + '; '.join(row['missing_evidence'])) + ' |')
    ruled_out = [row for row in state.get('object_scope', [])
                 if row.get('decision') == 'not_involved']
    declared = {oid for unit in state.get('units', []) for oid in unit.get('object_ids') or []}
    out += ['', '## 覆盖记录', '',
            '材料 %d；未完成覆盖 %d；尚未建立的框架检查 %d；涉及对象 %d，不涉及 %d。'
            % (counts['materials'], counts['materials_without_completed_coverage'],
               counts['framework_checks_not_planned'], len(declared), len(ruled_out)),
            '单元、方法、局限、可见性及旧契约来源见[完整覆盖明细](coverage-details.md)。', '']
    from propositions import render as render_propositions
    out += ['', render_propositions(state)]
    corrections = state.get('corrections', [])
    if corrections:
        out += ['', '## 复核订正日志', '',
                '复核者当场改掉的记录，逐条带改前／改后／理由——这条结论经过了复核者之手，'
                '读者应当看得出来。', '',
                '| 记录 | 字段 | 改前 | 改后 | 理由 | 由谁 |', '|---|---|---|---|---|---|']
        for row in corrections:
            out.append('| %s | %s | %s | %s | %s | %s |'
                       % (text(str(row.get('target'))), text(str(row.get('field'))),
                          text(str(row.get('before')))[:80], text(str(row.get('after')))[:80],
                          text(str(row.get('reason')))[:80], text(str(row.get('by')))))
        out.append('')
    recalled = state.get('target_patterns', [])
    if recalled:
        out += ['', '## 目标专属模式（本次召回）', '',
                '通用模式是语言级的，目标通常把危险构造包在自己的抽象里。下面每条带依据链：'
                '定义位置，以及它最终走到哪个语言级构造。', '',
                '| 模式 | 符号 | 对象 | 定义位置 | 走到 | 模型确认位置数 |', '|---|---|---|---|---|---|']
        for row in recalled:
            where = row.get('defined_at') or {}
            # A guard justifies itself by the refusal it controls, so a pattern may have
            # gates and no reaches. Reading only `reaches[0]` printed `None（None）` for
            # 17 such patterns, which is the evidence chain rendered as an absence.
            steps = row.get('reaches') or []
            if steps:
                reach = '%s（%s）' % (steps[0].get('construct'), steps[0].get('via'))
            else:
                gate = (row.get('gates') or [{}])[0]
                reach = ('把守 %s（%s:%s）' % (gate.get('refusal'), gate.get('path'),
                                             gate.get('line'))
                         if gate.get('refusal') else '—')
            out.append('| %s | %s | %s | %s | %s | %s |'
                       % (text(str(row.get('kind'))), text(str(row.get('symbol'))),
                          text('、'.join(row.get('object_ids') or [])),
                          text('%s:%s' % (where.get('path'), where.get('lines'))),
                          text(reach),
                          text(str(len(row['call_sites'])) if 'call_sites' in row else '未提供（旧 callers 未核实）')))
        out.append('')
    out += ['', '## 证据索引', '']
    for row in state['evidence']:
        mat = state['materials'].get(row.get('material_id'))
        source = mat['target_id'] + '/' + mat['path'] if mat else row.get('observation_id', '未知来源')
        out += ['- ' + text(row['id']) + '：' + text(source) + ' ' + text(row['locator']) + '；' + text(row['kind'] + ' / ' + row['status']) + '。' + text(row['observation'])]
    out += ['', '## 动态观测', '', '统计：' + text(counts['dynamic_outcomes']), '',
            'Canary 命中仅为观测信号；HTTP 回复不能单独证明工具执行或外部副作用。模拟结果不能支持运行时成立结论。', '']
    for obs in state.get('observations', []):
        out.append('- ' + text(obs['id'] + ' / ' + obs['observation_mode'] + ' / ' + obs['outcome']) + '：[脱敏请求与响应](' + obs['path'] + ')；SHA-256：`' + obs['sha256'] + '`')
    out += ['', '## 待核实假设与方法限制', '']
    for row in state['hypotheses']:
        out.append('- ' + text(row['id']) + '：' + text(row['description']))
    out.extend('- ' + text(note) for note in state['method_notes'])
    return '\n'.join(out) + '\n'
