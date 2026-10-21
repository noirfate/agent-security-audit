#!/usr/bin/env python3
"""Fold one unit's product into the shared record. Idempotent, and it rejects rather than ignores.

A worker never writes audit.json. It writes `units/<id>/partial.json`, and this module
validates that product before any of it is accepted:

* ids carry the unit token, so two units running at once cannot collide;
* evidence fingerprints must equal the material's current fingerprint, so a product
  built on材料 that has since changed is refused instead of silently merged;
* unknown keys are refused, not dropped. The products come from reading attacker
  controlled material, so an unexpected field is treated as a defect, not as data to
  be tolerated. Refused products stay in place; the error names the reason.

Merging the same product twice changes nothing: records are matched by id and content
digest, so an interrupted round can simply be replayed.
"""
import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from knowledge import read
from records import validate
from units import PREFIXES, id_owner, unit_token

# What a worker may contribute. method_notes is a list of strings; the rest are records.
COLLECTIONS = ('instances', 'connections', 'assets', 'attackers', 'controls', 'hypotheses',
               'evidence', 'checks', 'findings', 'dismissed_candidates', 'coverage', 'primitives')
ALLOWED_KEYS = set(COLLECTIONS) | {'unit_id', 'schema_version', 'method_notes',
                                  'surface_dispositions', 'progress', 'return_line',
                                  'crossleads', 'stale_notes', 'corrections', 'report_todos',
                                  'dimensions',
                                  'reconciliations',
                                  # Model-authored cross-unit chains and scope notes.
                                  'chains', 'scope_notes'}


def digest_record(record):
    return hashlib.sha256(json.dumps(record, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def _check_ids(payload, unit, errors):
    token = unit_token(unit['id'])
    for collection in COLLECTIONS:
        prefix = PREFIXES[collection]
        for record in payload.get(collection, []):
            rid = record.get('id')
            if not rid:
                errors.append('%s: a record without an id' % collection)
                continue
            if id_owner(rid) != token:
                errors.append('%s %s: id must carry this unit token (%s-%s-NNN)'
                              % (collection, rid, prefix, token))
            elif not rid.startswith(prefix + '-'):
                errors.append('%s %s: id prefix for this collection is %s' % (collection, rid, prefix))


def _check_scope(payload, state, unit, errors):
    owned = set(unit['material_ids'])
    materials = state['materials']
    for collection in ('instances', 'coverage'):
        for record in payload.get(collection, []):
            outside = [m for m in record.get('material_ids', []) if m not in owned]
            if outside and unit['kind'] != 'cross':
                errors.append('%s %s: materials outside this unit: %s'
                              % (collection, record['id'], ', '.join(sorted(outside)[:3])))
    for record in payload.get('evidence', []):
        mid = record.get('material_id')
        if mid is None:
            continue
        if mid not in materials:
            errors.append('evidence %s: unknown material %s' % (record['id'], mid))
            continue
        if unit['kind'] != 'cross' and mid not in owned:
            errors.append('evidence %s: material %s is outside this unit' % (record['id'], mid))
        current = materials[mid]
        if current['status'] != 'present' or record.get('sha256') != current.get('sha256'):
            errors.append('evidence %s: fingerprint does not match the material now on disk; '
                          'the product was built on changed material' % record['id'])
    baseline = state['framework']['baseline_id']
    for record in payload.get('checks', []):
        if record.get('baseline_id') != baseline:
            errors.append('check %s: baseline_id must be the pinned baseline' % record['id'])


def legacy_product(workspace, unit, payload, path=None):
    """Only an unchanged, previously merged legacy product retains its old count meaning."""
    if not unit.get('legacy_schema_version') or not unit.get('partial_sha256'):
        return False
    path = Path(path) if path else Path(workspace) / 'units' / unit['id'] / 'partial.json'
    try:
        return (hashlib.sha256(path.read_bytes()).hexdigest() == unit['partial_sha256']
                and read(path) == payload)
    except (OSError, ValueError):
        return False


def dismissed_errors(state, payload=None):
    """Candidate identity and explicit countercheck associations, never semantic falsity."""
    payload = state if payload is None else payload
    checks = {r['id']: r for r in state.get('checks') or []}
    checks.update({r['id']: r for r in payload.get('checks') or []})
    findings = {r['id'] for r in state.get('findings') or []} | {r['id'] for r in payload.get('findings') or []}
    errors, seen = [], set()
    for row in payload.get('dismissed_candidates') or []:
        rid = row.get('id')
        if rid in seen or rid in findings:
            errors.append('%s: duplicate candidate or candidate also retained as finding' % rid)
        seen.add(rid)
        if not str(row.get('reason') or '').strip():
            errors.append('%s: dismissed candidate needs a reason' % rid)
        ids = row.get('check_ids')
        if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)):
            errors.append('%s: dismissed candidate needs unique check_ids' % rid)
            continue
        for cid in ids:
            check = checks.get(cid) or {}
            if (check.get('status') != 'complete' or check.get('verdict') != 'not_established'
                    or not check.get('counterevidence_ids')):
                errors.append('%s: %s must be a complete not_established check with counterevidence' % (rid, cid))
    return errors


def validate_partial(state, unit, payload, legacy=False, *, replace=False):
    errors = []
    if not isinstance(payload, dict):
        return ['product is not a JSON object']
    from audit import SCHEMA_VERSION
    if not legacy and payload.get('schema_version') not in (None, SCHEMA_VERSION):
        errors.append('new product requires current schema_version ' + SCHEMA_VERSION)
    unknown = sorted(set(payload) - ALLOWED_KEYS)
    if unknown:
        errors.append('unknown keys are refused, not ignored: ' + ', '.join(unknown))
    if payload.get('unit_id') != unit['id']:
        errors.append('unit_id in the product (%s) is not this unit' % payload.get('unit_id'))
    for collection in COLLECTIONS:
        if collection in payload and not isinstance(payload[collection], list):
            errors.append(collection + ': must be a list')
        elif any(not isinstance(row, dict) for row in payload.get(collection, [])):
            errors.append(collection + ': records must be objects')
    if not isinstance(payload.get('method_notes', []), list):
        errors.append('method_notes: must be a list of strings')
    for note in payload.get('method_notes', []):
        if not isinstance(note, str):
            errors.append('method_notes: entries must be strings')
    if errors:
        return errors
    for record in payload.get('primitives', []):
        from units import PRIMITIVES
        if record.get('primitive') not in PRIMITIVES:
            errors.append('primitive %s: must be one of %s'
                          % (record.get('id'), ', '.join(PRIMITIVES)))
    if errors:
        return errors
    _check_ids(payload, unit, errors)
    _check_scope(payload, state, unit, errors)
    candidate_state = state
    if replace:
        # A withdrawn finding may move into dismissed_candidates on replacement.
        # Its old row is not part of the resulting finding set.
        candidate_state = dict(state, findings=[
            f for f in state.get('findings', []) if id_owner(f['id']) != unit_token(unit['id'])])
    errors += dismissed_errors(candidate_state, payload)
    for collection in ('chains', 'scope_notes'):
        rows = payload.get(collection, [])
        if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
            errors.append(collection + ': records must be a list of objects')
            continue
        seen = set()
        for row in rows:
            rid = row.get('id')
            if not isinstance(rid, str) or not rid.strip() or rid in seen:
                errors.append(collection + ': records need unique nonempty ids')
            else:
                seen.add(rid)
            if row.get('unit_id') not in (None, unit['id']):
                errors.append(collection + ': cannot claim another unit as owner')
    from units import completion_errors
    errors += completion_errors(unit, payload)
    if not legacy and payload.get('return_line'):
        from review_prepare import RETURN_RE
        match = RETURN_RE.search(payload['return_line'])
        if match and int(match.group(3)) != len({r['id'] for r in payload.get('dismissed_candidates') or []}):
            errors.append('fp must equal the number of explicit dismissed_candidates')
    return errors


def frozen_conclusions(state, token, new_findings=None):
    """Reviewed findings of this unit that a rework would drop or restate.

    Frozen means "a reviewed conclusion would change", not "a reviewed conclusion
    exists". `subject_digest` already records what each review covered, so comparing is
    both available and the thing the guard was reaching for.
    """
    from review import subject_digest
    from units import id_owner
    ledgers = {r['finding_id']: r for r in state.get('reviews', [])}
    incoming = {f['id']: f for f in (new_findings or [])}
    frozen = []
    for finding in state.get('findings', []):
        if id_owner(finding['id']) != token or finding['id'] not in ledgers:
            continue
        replacement = incoming.get(finding['id'])
        if replacement is None or (subject_digest(state, replacement)
                                   != ledgers[finding['id']]['subject_sha256']):
            frozen.append(finding['id'])
    return frozen


def retract_unit(workspace, state, unit_id, new_findings=None, *, commit=True):
    """Take one unit's merged records back out, so its product can be merged again.

    Record ids carry the unit token, so "this unit's records" is exactly identifiable —
    which is what made the first run's four hand edits of audit.json possible, and what
    makes them unnecessary now. Two things are deliberately NOT retracted:

    * a finding that has a recorded review. A review is a judgement about a specific
      text; retracting the finding under it would leave the review pointing at something
      nobody judged. Reviewed findings are frozen: withdraw the review first.
    * crossleads, scope notes and corrections. They are observations and change logs,
      not conclusions, and the unit's rework does not unmake them.
    """
    from audit import save
    from units import id_owner, unit_token
    token = unit_token(unit_id)
    unit = next((u for u in state.get('units', []) if u['id'] == unit_id), None)
    if unit is None:
        raise ValueError('Unknown unit: ' + unit_id)
    # Frozen means "a reviewed conclusion would change", not "a reviewed conclusion
    # exists". The guard used to refuse on existence, so adding two sentences to six
    # coverage rows demanded withdrawing five sound reviews — a price out of all
    # proportion to the change, and the kind of friction that invites hand-editing the
    # record instead. `subject_digest` already records what each review covered, and
    # `records.validate` already refuses a review whose subject moved, so comparing is
    # both available and the thing the guard was reaching for.
    frozen = frozen_conclusions(state, token, new_findings)
    if frozen:
        raise ValueError('这些发现的复核结论会被改动，先撤回再重做；内容不变的改动不受此限：'
                         "`review --withdraw '<理由>' --finding <编号>`："
                         + '、'.join(sorted(frozen)))
    removed = {}
    for collection in COLLECTIONS:
        rows = state.get(collection) or []
        keep = [r for r in rows if id_owner(r.get('id')) != token]
        if len(keep) != len(rows):
            removed[collection] = len(rows) - len(keep)
            state[collection] = keep
    old_chains = state.get('chains', [])
    state['chains'] = [r for r in old_chains if r.get('unit_id') != unit_id]
    if len(state['chains']) != len(old_chains):
        removed['chains'] = len(old_chains) - len(state['chains'])
    # `returned`, not `in_progress`: the product is still on disk and awaiting a merge,
    # and `in_progress` is not a unit status at all — it belongs to coverage rows. Using
    # it here left the record invalid after every retraction, which blocked `validate`
    # and `report` with no hint as to why.
    unit['status'] = 'returned'
    unit['partial_sha256'] = None
    unit['merged_at'] = None
    for row in state.get('rounds', []):
        row['returns'] = [e for e in row.get('returns', []) if e.get('unit_id') != unit_id]
    if commit:
        save(workspace, state)
    return {'unit': unit_id, 'removed': removed, 'status': unit['status'],
            'note': 'crosslead、残余与订正日志保留；再次 merge 即可重新合入'}


def would_introduce(workspace, state, unit_id, partial=None, *, replace=False):
    """Which validation errors a real merge of this product would introduce.

    The same code path as the merge itself, run on a copy: one implementation, so the
    reviewer's preflight and the merge's own refusal can never disagree.
    """
    try:
        merge_unit(workspace, deepcopy(state), unit_id, partial, commit=False, replace=replace)
    except ValueError as exc:
        return [str(exc)]
    return []


def merge_unit(workspace, state, unit_id, partial=None, commit=True, *, replace=False):
    from audit import save
    workspace = Path(workspace)
    units = {u['id']: u for u in state.get('units', [])}
    unit = units.get(unit_id)
    if unit is None:
        raise ValueError('Unknown unit: ' + unit_id)
    path = Path(partial) if partial else workspace / 'units' / unit_id / 'partial.json'
    if not path.is_file():
        raise ValueError('No product to merge at ' + str(path))
    payload = read(path)

    def refuse(headline, problems):
        """Refuse the product, naming what was wrong.

        It used to also copy the payload into `_quarantine/`. Three real workspaces have
        no such directory — no product was ever refused — and the copy was of a file that
        stays where it is: the worker's `partial.json` is not consumed by a failed merge,
        so the snapshot preserved nothing that was at risk.
        """
        raise ValueError('%s (%d problems): %s'
                         % (headline, len(problems), '; '.join(problems[:3])))

    errors = validate_partial(state, unit, payload, legacy=legacy_product(workspace, unit, payload, path), replace=replace)
    if errors:
        refuse('Product refused', errors)
    # Everything below works on a copy, and the record is written only if merging did
    # not introduce a validation error. A `--dry-run` flag would not have helped: a guard
    # you have to remember to pass is not a guard, and the merge that first landed a
    # broken record was an ordinary merge by someone with no reason to suspect it.
    # Only errors this merge *introduces* can refuse it — the record may already carry
    # one (a changed skill fingerprint, say), and that must not block every later merge.
    before = set(validate(workspace, state))
    working = deepcopy(state)
    if replace:
        # Retraction and re-merge form one trial. A rejected replacement must leave
        # records, reviews, return ledgers and index annotations unchanged.
        retract_unit(workspace, working, unit_id, payload.get('findings') or [], commit=False)
    unit = {u['id']: u for u in working.get('units', [])}[unit_id]
    added, skipped, conflicts = {}, {}, []
    for collection in COLLECTIONS:
        incoming = payload.get(collection, [])
        if not incoming:
            continue
        existing = {record['id']: record for record in working.setdefault(collection, [])}
        for record in incoming:
            rid = record['id']
            if rid in existing:
                if digest_record(existing[rid]) == digest_record(record):
                    skipped[collection] = skipped.get(collection, 0) + 1
                else:
                    conflicts.append('%s %s already merged with different content' % (collection, rid))
                continue
            working[collection].append(record)
            added[collection] = added.get(collection, 0) + 1
    for collection in ('chains', 'scope_notes'):
        rows = working.setdefault(collection, [])
        existing = {r['id']: index for index, r in enumerate(rows)}
        for record in payload.get(collection, []):
            record = dict(record, unit_id=unit_id)
            rid = record['id']
            if rid not in existing:
                existing[rid] = len(rows)
                rows.append(record)
                added[collection] = added.get(collection, 0) + 1
            elif rows[existing[rid]] == record:
                skipped[collection] = skipped.get(collection, 0) + 1
            elif replace and rows[existing[rid]].get('unit_id') == unit_id:
                rows[existing[rid]] = record
                added[collection] = added.get(collection, 0) + 1
            else:
                conflicts.append('%s %s already merged with different content' % (collection, rid))
    if conflicts:
        refuse('Product conflicts with records already merged', conflicts)
    for note in payload.get('method_notes', []):
        if note not in working['method_notes']:
            working['method_notes'].append(note)
    disposed = None
    if payload.get('surface_dispositions'):
        # Counted now, written only once the record validates: the index slice lives on
        # disk, so writing it before the decision would leave it changed by a merge that
        # was then refused.
        from surface import preview_dispositions
        disposed = preview_dispositions(workspace, unit_id, payload['surface_dispositions'])
    progress = payload.get('progress') or {}
    unit['progress'] = {
        'files_done': progress.get('files_done', unit['progress']['files_done']),
        'hits_disposed': disposed['disposed'] if disposed else unit['progress']['hits_disposed']}
    # The six analysis dimensions had no write path at all. `gate.py` fails G2 while any
    # of them is `pending`, no role could set one, and neither contract so much as named
    # them — so the gate stood on a field nothing could ever fill. The worker reports how
    # each dimension came out; `na` needs a reason, same as everywhere else.
    for name, row in (payload.get('dimensions') or {}).items():
        if name not in unit['dimensions']:
            raise ValueError('%s: 不认识的分析维度 %s（只有 %s）'
                             % (unit['id'], name, '、'.join(sorted(unit['dimensions']))))
        reported = str((row or {}).get('state') or '').strip()
        if reported not in ('done', 'na'):
            raise ValueError('%s/%s: 维度状态只能是 done 或 na，收到 %r'
                             % (unit['id'], name, reported))
        reason = str((row or {}).get('reason') or '').strip()
        if reported == 'na' and not reason:
            raise ValueError('%s/%s: 判 n.a. 要写理由' % (unit['id'], name))
        unit['dimensions'][name] = {'state': reported, 'reason': reason}
    # An instance belongs to the unit whose product carried it — the product names one
    # unit and nothing else can own its rows. Three workers filled this in and one did
    # not, and the merge did not supply it: the proposition denominator resolves a check
    # to its unit through `instance.unit_id`, so that unit's 19 judged propositions were
    # reported by G7 as "never instantiated" while the checks sat in the record. Placed
    # here and not in `_check_scope`, which has no `unit_id` — the same slip twice, both
    # times because that function holds the only other loop over the payload.
    for row in payload.get('instances') or []:
        if not row.get('unit_id'):
            row['unit_id'] = unit_id
    # Folded where `working` and `unit_id` actually exist: this loop was written into
    # `_check_scope`, which has neither, so any product carrying the key raised NameError.
    # Opening the key was verified; merging one was not.
    for row in payload.get('reconciliations') or []:
        item = dict(row, by=row.get('by') or unit_id)
        entries = working.setdefault('reconciliations', [])
        if item not in entries:
            entries.append(item)
    # A retained review already decided this finding's status; `retract_unit` keeps the
    # ledger, so the status has to come back with the finding instead of waiting for
    # someone to remember to re-record all of them. Measured: a replace that changed only
    # six coverage sentences sent four reviewed findings back to `needs_review`, and
    # nothing in the protocol said to undo that.
    from review import subject_digest, evidence_digest
    ledgers = {r['finding_id']: r for r in state.get('reviews', [])}
    old_findings = {f['id']: f for f in state.get('findings', [])}
    for finding in working.get('findings', []):
        row = ledgers.get(finding['id'])
        if replace and row:
            old = old_findings.get(finding['id'])
            review_ids = row.get('evidence_ids', []) + row.get('counterevidence_ids', [])
            if (old is None or subject_digest(state, old) != subject_digest(working, finding)
                    or evidence_digest(state, review_ids) != evidence_digest(working, review_ids)):
                refuse('Reviewed subject changed; withdraw its review before replacement',
                       [finding['id']])
        if row and row['subject_sha256'] == subject_digest(working, finding):
            finding['status'] = {'retain': 'current', 'reject': 'withdrawn',
                                 'needs_evidence': 'needs_review'}[row['decision']]
    unit['status'] = 'merged'
    unit['partial_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    unit['merged_at'] = datetime.now(timezone.utc).isoformat()
    rounds = working.setdefault('rounds', [])
    current = next((r for r in rounds if r['n'] == unit.get('round')), None)
    if current is not None:
        current.setdefault('returns', [])
        line = payload.get('return_line') or ''
        if {'unit_id': unit_id, 'line': line} not in current['returns']:
            current['returns'].append({'unit_id': unit_id, 'line': line})
    # A crosslead's `unit_id` used to mean two opposite things: the producing unit for
    # rows folded in from a product, and the receiving unit for rows written during
    # recon. So "directed to that unit" could not be resolved from the record at all,
    # and the unit with the most specific task waiting for it had no way to find it.
    # `from_unit` is who saw it, `to_unit` is who must answer it (null = nobody yet).
    for row in payload.get('crossleads') or []:
        if isinstance(row, dict):
            row.setdefault('from_unit', unit_id)
            row.setdefault('to_unit', None)
    for name, items in (('crossleads', payload.get('crossleads') or []),
                        ('stale_notes', payload.get('stale_notes') or []),
                        ('corrections', payload.get('corrections') or []),
                        ('report_todos', payload.get('report_todos') or [])):
        store = working.setdefault(name, [])
        for item in items:
            row = {'unit_id': unit_id, 'note': item} if isinstance(item, str) else dict(item, unit_id=unit_id)
            if row not in store:
                store.append(row)
    introduced = sorted(set(validate(workspace, working)) - before)
    if introduced:
        refuse('Merging would break the record, nothing written', introduced)
    if not commit:
        return {'unit': unit_id, 'added': added, 'already_present': skipped,
                'surface': disposed, 'progress': unit['progress'], 'committed': False}
    if payload.get('surface_dispositions'):
        from surface import apply_dispositions
        apply_dispositions(workspace, unit_id, payload['surface_dispositions'])
    state.clear()
    state.update(working)
    save(workspace, state)
    return {'unit': unit_id, 'added': added, 'already_present': skipped,
            'surface': disposed, 'progress': unit['progress'],
            'files': '%d/%d' % (unit['progress']['files_done'], unit['file_count'])}
