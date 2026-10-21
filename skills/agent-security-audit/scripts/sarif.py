"""SARIF 2.1.0 projection of validated, reviewed target findings."""
import hashlib
import json
from urllib.parse import quote

from knowledge import baseline_dir, load_bundle


def export_sarif(state, workspace):
    from records import summary
    checks = {c['id']: c for c in state['checks']}
    evidence = {e['id']: e for e in state['evidence']}
    rules, results = {}, []
    for finding in state['findings']:
        if finding['status'] != 'current':
            continue
        linked = [checks[cid] for cid in finding['check_ids']]
        rule_ids, risks = [], set()
        for c in linked:
            rid = c.get('failure_mode_id') or 'LOCAL/' + c['id']
            rule_ids.append(rid)
            if c.get('failure_mode_id'):
                data, _, _ = load_bundle(baseline_dir(workspace, c['baseline_id']))
                definition = data['failure_modes'][rid]
                risks.update(definition['risk_ids'])
                title = definition['statement']
            else:
                title = c['local_definition']['statement']
            rules[rid] = {'id': rid, 'shortDescription': {'text': title}}
        locations, related = [], []
        for eid in finding['evidence_ids']:
            e = evidence[eid]
            mat = state['materials'].get(e.get('material_id'))
            if mat:
                uri = quote(mat['target_id'] + '/' + mat['path'], safe='/')
                physical = {'artifactLocation': {'uri': uri}}
                # SARIF line numbers refer to original text; decoded/recovered views remain annotations.
                if e.get('view', 'original') == 'original' and e['locator'].get('lines'):
                    physical['region'] = {'startLine': e['locator']['lines'][0], 'endLine': e['locator']['lines'][1]}
                location = {'physicalLocation': physical, 'message': {'text': e['observation']}}
                if location not in locations:
                    locations.append(location)
            else:
                related.append({'evidence_id': eid, 'observation_id': e.get('observation_id'), 'locator': e['locator']})
        identity = {'target': state['target_id'], 'id': finding['id'], 'rules': sorted(rule_ids)}
        result = {
            'ruleId': rule_ids[0], 'kind': 'fail',
            'level': {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note', 'informational': 'note'}[finding['severity']],
            'message': {'text': finding['title'] + '\n' + finding['mechanism'] + '\n影响：' + finding['impact'] + '\n修复：' + finding['remediation']},
            'partialFingerprints': {'findingIdentity/v1': hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()},
            'properties': {'findingId': finding['id'], 'checkIds': finding['check_ids'], 'ruleIds': rule_ids,
                           'riskIds': sorted(risks), 'severity': finding['severity'], 'evidenceIds': finding['evidence_ids'],
                           'runtimeObservations': related, 'remediation': finding['remediation'],
                           'scope': sorted({s for c in linked for s in c['scope']})},
        }
        if locations:
            result['locations'] = locations
        results.append(result)
    counts = summary(state, workspace)
    complete = counts['scope_review_complete']
    invocation = {'executionSuccessful': complete}
    if not complete:
        invocation['toolExecutionNotifications'] = [{'level': 'warning', 'message': {'text': 'Audit scope is incomplete; zero findings do not establish safety. Consult coverage and evidence gaps.'}}]
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'agent-security-audit', 'version': '1.1.0', 'rules': [rules[k] for k in sorted(rules)]}},
        'results': results, 'invocations': [invocation],
        'properties': {'coverage': counts, 'baselineId': state['framework']['baseline_id'],
                       'omittedFindings': [{'id': f['id'], 'status': f['status']} for f in state['findings'] if f['status'] != 'current']},
    }]}
