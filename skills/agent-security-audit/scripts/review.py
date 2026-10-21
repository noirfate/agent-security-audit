"""Append adjudications and bind them to the exact finding and evidence state."""
import hashlib
import json
import uuid


def subject_digest(state, finding):
    check_ids = set(finding['check_ids'])
    checks = [c for c in state['checks'] if c['id'] in check_ids]
    from audit import check_evidence_ids
    ids = set(finding['evidence_ids'])
    for c in checks:
        ids.update(check_evidence_ids(c))
    subject = {'finding': {k: v for k, v in finding.items() if k not in {'status', 'review_ids'}},
               'checks': checks, 'evidence': [e for e in state['evidence'] if e['id'] in ids]}
    return hashlib.sha256(json.dumps(subject, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def latest_review(state, finding):
    rows = [r for r in state.get('reviews', []) if r['finding_id'] == finding['id']]
    return rows[-1] if rows else None


def evidence_digest(state, ids):
    rows = sorted((e for e in state['evidence'] if e['id'] in ids), key=lambda e: e['id'])
    return hashlib.sha256(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def record_review(workspace, state, finding_id, payload):
    from audit import now, save
    finding = next((f for f in state['findings'] if f['id'] == finding_id), None)
    if finding is None:
        raise ValueError('Unknown finding')
    if payload.get('decision') not in {'retain', 'reject', 'needs_evidence'}:
        raise ValueError('Review decision must be retain, reject or needs_evidence')
    for key in ('reviewer', 'rationale', 'counterevidence_analysis'):
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            raise ValueError('Review requires ' + key)
    ids = payload.get('evidence_ids', []) + payload.get('counterevidence_ids', [])
    evidence = {e['id']: e for e in state['evidence']}
    if not ids or any(e not in evidence or evidence[e]['status'] != 'current' for e in ids):
        raise ValueError('Review requires current target evidence')
    if payload['decision'] == 'retain':
        checks = {c['id']: c for c in state['checks']}
        if not finding['check_ids'] or any(cid not in checks or checks[cid]['status'] != 'complete' or checks[cid]['verdict'] != 'confirmed' for cid in finding['check_ids']):
            raise ValueError('Retaining a finding requires confirmed, completed checks')
    row = {k: payload.get(k, []) for k in ('reviewer', 'decision', 'rationale', 'counterevidence_analysis', 'evidence_ids', 'counterevidence_ids')}
    row.update(id='REV-' + uuid.uuid4().hex[:12], finding_id=finding_id, created_at=now(),
               subject_sha256=subject_digest(state, finding), evidence_sha256=evidence_digest(state, ids))
    state.setdefault('reviews', []).append(row)
    finding['status'] = {'retain': 'current', 'reject': 'withdrawn', 'needs_evidence': 'needs_review'}[row['decision']]
    save(workspace, state)
    return row


def withdraw_review(workspace, state, finding_id, reason):
    """Take the review off a finding so it can be reworked, and say why in the record.

    A reviewed finding is frozen — `merge --replace` refuses to retract one — because a
    review is a judgement about a specific text. This is the way out of that freeze, and
    it is deliberately not silent: the withdrawn review stays in the ledger with the
    reason, so "reviewed, then changed, then reviewed again" is readable afterwards.
    """
    from audit import now, save
    finding = next((f for f in state['findings'] if f['id'] == finding_id), None)
    if finding is None:
        raise ValueError('Unknown finding')
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError('Withdrawing a review requires its reason')
    rows = [r for r in state.get('reviews', []) if r['finding_id'] == finding_id]
    if not rows:
        raise ValueError('No review to withdraw for ' + finding_id)
    withdrawn = state.setdefault('withdrawn_reviews', [])
    for row in rows:
        withdrawn.append(dict(row, withdrawn_at=now(), withdrawn_reason=reason.strip()))
    state['reviews'] = [r for r in state.get('reviews', []) if r['finding_id'] != finding_id]
    finding['status'] = 'needs_review'
    save(workspace, state)
    return {'finding': finding_id, 'withdrawn': len(rows), 'status': finding['status'],
            'note': '该发现已回到 needs_review；改完必须重出复核账本'}


def validate_extensions(workspace, state, require):
    """Mechanical freshness and linkage constraints; never judge evidence semantics."""
    from dynamic import artifact_path
    from knowledge import digest, read
    evidence = {e['id']: e for e in state['evidence']}
    checks = {c['id']: c for c in state['checks']}
    findings = {f['id']: f for f in state['findings']}
    for key in ('reviews', 'observations', 'dynamic_sessions'):
        rows = state[key]
        require(len({r['id'] for r in rows}) == len(rows), 'Duplicate ids: ' + key)
    for observation in state['observations']:
        path = artifact_path(workspace, observation['path'])
        require(digest(path) == observation['sha256'], observation['id'] + ': observation changed')
        doc = read(path)
        require(doc['id'] == observation['id'] and doc['outcome'] == observation['outcome'] and doc['observation_mode'] == observation['observation_mode'], observation['id'] + ': artifact metadata mismatch')
        require(observation['observation_mode'] in {'live_http', 'recorded_runtime', 'simulation'}, observation['id'] + ': invalid observation mode')
        require(observation['outcome'] in {'pending', 'captured', 'truncated', 'error'}, observation['id'] + ': invalid observation outcome')
        require(observation['status'] in {'current', 'needs_review'}, observation['id'] + ': invalid observation status')
        if observation['observation_mode'] == 'live_http':
            require(any(s['id'] == observation.get('session_id') == doc.get('session_id') for s in state['dynamic_sessions']), observation['id'] + ': unknown dynamic session')
    for session in state['dynamic_sessions']:
        require(digest(artifact_path(workspace, session['config_path'])) == session['config_sha256'], session['id'] + ': configuration changed')
    for row in state['reviews']:
        require(row['finding_id'] in findings, row['id'] + ': unknown finding')
        require(row['decision'] in {'retain', 'reject', 'needs_evidence'}, row['id'] + ': invalid review decision')
        for field in ('reviewer', 'rationale', 'counterevidence_analysis', 'subject_sha256', 'evidence_sha256', 'created_at'):
            require(bool(row.get(field)), row['id'] + ': missing ' + field)
        ids = row.get('evidence_ids', []) + row.get('counterevidence_ids', [])
        require(bool(ids) and all(e in evidence for e in ids), row['id'] + ': missing review evidence')
    for fid, finding in findings.items():
        if finding['status'] != 'current':
            continue
        review = latest_review(state, finding)
        require(bool(review), fid + ': current finding requires a recorded review')
        if review:
            require(review['decision'] == 'retain' and review['subject_sha256'] == subject_digest(state, finding), fid + ': review is stale or does not retain finding')
            review_ids = review.get('evidence_ids', []) + review.get('counterevidence_ids', [])
            require(review['evidence_sha256'] == evidence_digest(state, review_ids), fid + ': review evidence changed')
            ids = review.get('evidence_ids', []) + review.get('counterevidence_ids', [])
            require(all(evidence[e]['status'] == 'current' for e in ids if e in evidence), fid + ': review uses stale evidence')
    for control in state['controls']:
        effect = control.get('effectiveness', 'unassessed')
        require(effect in {'unassessed', 'effective', 'limited', 'ineffective', 'unknown', 'needs_review'}, control['id'] + ': invalid effectiveness')
        if effect not in {'effective', 'limited', 'ineffective'}:
            continue
        for field in ('scope', 'limitations', 'rationale', 'retest', 'check_ids', 'evidence_ids'):
            require(bool(control.get(field)), control['id'] + ': assessment needs ' + field)
        selected = [checks[c] for c in control.get('check_ids', []) if c in checks]
        require(len(selected) == len(control.get('check_ids', [])), control['id'] + ': unknown check')
        require(all(c['status'] == 'complete' for c in selected), control['id'] + ': assessment uses stale or incomplete checks')
        require(all(e in evidence and evidence[e]['status'] == 'current' for e in control.get('evidence_ids', [])), control['id'] + ': stale control evidence')
        if effect in {'effective', 'limited'}:
            from audit import check_counterevidence_ids
            counter = {eid for c in selected if c['verdict'] == 'not_established'
                       for eid in check_counterevidence_ids(c)}
            require(bool(counter.intersection(control.get('evidence_ids', []))), control['id'] + ': effective control needs matching counterevidence')
            if effect == 'effective':
                require(all(c['verdict'] == 'not_established' for c in selected), control['id'] + ': effective control cannot include failed or unknown checks')
        else:
            require(any(c['verdict'] == 'confirmed' for c in selected), control['id'] + ': ineffective control needs a confirmed failure')
