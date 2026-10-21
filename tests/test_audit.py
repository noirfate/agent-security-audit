"""Exercise audit state and evidence rules; fixtures are read, never imported."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(os.environ.get('AUDIT_REPO_TEST_DIR', Path(__file__).resolve().parents[1]))
SKILL = Path(os.environ.get('AUDIT_SKILL_TEST_DIR', ROOT / 'skills/agent-security-audit'))
sys.path.insert(0, str(SKILL / 'scripts'))
import audit
import knowledge
import records
import review


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.target = self.base / 'target'
        shutil.copytree(ROOT / 'tests/fixtures/audit', self.target)
        # Beside the target, never inside it: a workspace in the audited work tree keeps
        # it permanently dirty, and `init` refuses it. This fixture used to encode the
        # old default ("agent_audit/ under the current directory"), which is how the real
        # audit ended up inside the framework repo.
        self.ws = self.base / 'agent_audit' / 'test'
        audit.initialize(self.ws, 'test', ['app=' + str(self.target)], [])
        self.state = knowledge.read(self.ws / 'audit.json')

    def material(self, suffix):
        return next(m for m in self.state['materials'].values() if m['path'] == suffix)

    def instance(self, oid='A5.2', path='framework/memory.py', iid='I-1'):
        mat = self.material(path)
        row = {'id': iid, 'name': 'fixture', 'framework_object_ids': [oid] if oid else [],
               'material_ids': [mat['id']], 'evidence_ids': [], 'responsibility': 'fixture responsibility'}
        if not oid:
            row['mapping_gap'] = 'Target-specific responsibility'
        self.state['instances'].append(row)
        return row

    def evidence(self, path='framework/memory.py', kind='code', eid='E-1'):
        mat = self.material(path)
        row = {'id': eid, 'material_id': mat['id'], 'sha256': mat['sha256'], 'kind': kind,
               'locator': {'lines': [1, 3]}, 'observation': 'Read fixture facts; no target execution.', 'status': 'current'}
        self.state['evidence'].append(row)
        return row

    def prepared(self, fid='FM-A5.2-03', path='framework/memory.py', kind='code'):
        self.instance(path=path)
        audit.seed(self.ws, self.state)
        check = next(c for c in self.state['checks'] if c['failure_mode_id'] == fid)
        self.evidence(path, kind)
        check.update(status='complete', applicability='applicable', verdict='confirmed',
                     scope=[kind], evidence_ids=['E-1'], explanation='Fixture analysis of the scoped behavior.')
        # Explicit fixture annotations, independent of the catalogue's wording.
        check['prerequisites'] = [{'condition': 'The scoped fixture mechanism is reachable.',
                                   'state': 'met', 'evidence_ids': ['E-1']}]
        check['criteria'] = [{'criterion': 'The fixture admits the scoped unsafe operation.',
                              'state': 'met', 'evidence_ids': ['E-1']}]
        return check

    def finding(self, check):
        finding = {'id': 'F-1', 'check_ids': [check['id']], 'title': 'Fixture finding',
                   'mechanism': 'Target-specific static mechanism', 'evidence_ids': ['E-1'],
                   'impact': 'Scoped target asset', 'severity': 'medium', 'severity_reason': 'Fixture role and impact',
                   'remediation': 'Bind the checked identity', 'responsibility': 'Application owner',
                   'validation': 'Static walkthrough only; no test was executed.', 'residual_risk': 'Deployment unknown',
                   'status': 'current'}
        self.state['findings'].append(finding)
        review.record_review(self.ws, self.state, finding['id'], {
            'reviewer': 'Test fixture reviewer', 'decision': 'retain',
            'rationale': 'Re-read the static fixture and matched all necessary criteria.',
            'counterevidence_analysis': 'Checked the fixture call path and its upstream guard.',
            'evidence_ids': ['E-1'], 'counterevidence_ids': []})
        return finding

    def valid(self):
        self.assertEqual(records.validate(self.ws, self.state), [])

    def test_model_decision_does_not_require_catalogue_condition_rows(self):
        check = self.prepared()
        check['prerequisites'] = []
        check['criteria'] = []
        self.valid()
        check.pop('prerequisites')
        check.pop('criteria')
        self.valid()
        self.finding(check)
        self.valid()

    def test_optional_notes_do_not_compute_the_proposition_verdict(self):
        check = self.prepared()
        check['prerequisites'] = [
            {'condition': 'An alternative deployment is selected.', 'state': 'not_met', 'evidence_ids': ['E-1']}]
        check['criteria'] = [
            {'criterion': 'A distinct attack variant is reachable.', 'state': 'unknown', 'evidence_ids': []}]
        # The verdict concerns the scoped fixture path, not these optional variants.
        self.valid()
        check.update(verdict='not_established', counterevidence_ids=['E-1'],
                     explanation='Model records a scoped counterexample in the cited fixture.')
        self.valid()
        check.update(verdict='not_applicable', applicability='not_applicable',
                     explanation='Model records why this proposition does not apply to the scoped fixture.')
        self.valid()

    def test_optional_notes_still_need_valid_shapes_and_evidence_references(self):
        check = self.prepared()
        good = copy.deepcopy(check['criteria'])
        for invalid in (
            'not-an-array',
            [None],
            [{'criterion': '', 'state': 'unknown', 'evidence_ids': []}],
            [{'criterion': 'Chosen target fact', 'state': 'invalid', 'evidence_ids': []}],
            [{'criterion': 'Chosen target fact', 'state': 'met', 'evidence_ids': []}],
            [{'criterion': 'Chosen target fact', 'state': 'met', 'evidence_ids': ['E-MISSING']}],
        ):
            with self.subTest(invalid=invalid):
                check['criteria'] = invalid
                self.assertTrue(records.validate(self.ws, self.state))
        check['criteria'] = good
        self.valid()

    def test_complete_marker_alone_does_not_supply_a_review_result(self):
        check = self.prepared()
        check.update(prerequisites=[], criteria=[])
        self.valid()
        for patch_value in ({'explanation': ''}, {'verdict': None}, {'evidence_ids': []},
                            {'evidence_ids': ['E-MISSING']}, {'failure_mode_id': 'FM-UNKNOWN'}):
            with self.subTest(patch_value=patch_value):
                before = copy.deepcopy(check)
                check.update(patch_value)
                self.assertTrue(records.validate(self.ws, self.state))
                check.clear()
                check.update(before)
        self.valid()

    def test_counterevidence_is_explicit_without_required_condition_rows(self):
        check = self.prepared()
        check.update(prerequisites=[], criteria=[], verdict='not_established',
                     counterevidence_ids=['E-1'])
        self.valid()
        check['counterevidence_ids'] = []
        self.assertTrue(any('requires counterevidence' in error
                            for error in records.validate(self.ws, self.state)))
        # Old annotations remain valid evidence references without rewriting history.
        check['criteria'] = [{'criterion': 'Legacy target counterexample', 'state': 'not_met',
                              'evidence_ids': ['E-1']}]
        self.valid()

    def test_local_definition_does_not_require_a_second_condition_list(self):
        check = self.prepared()
        check.update(failure_mode_id=None,
                     local_definition={'statement': 'A scoped target invariant is violated.',
                                       'requirement': 'Preserve the target invariant.'},
                     prerequisites=[], criteria=[])
        self.finding(check)
        self.valid()

    def test_proposition_coverage_is_independent_of_condition_count(self):
        self.instance()
        audit.seed(self.ws, self.state)
        self.state['coverage'] = [{
            'id': 'COV-1', 'material_ids': list(self.state['materials']), 'check_ids': [],
            'status': 'reviewed', 'reason': 'Synthetic coverage fixture',
            'analysis_method': 'Static fixture inspection', 'limitations': 'Synthetic test only'}]
        for check in self.state['checks']:
            check.update(status='complete', applicability='unknown', verdict='insufficient_evidence',
                         scope=['code'], explanation='Reviewed the scoped fixture; deployment is unavailable.',
                         missing_evidence=['Deployment configuration'], prerequisites=[], criteria=[])
        self.valid()
        self.assertTrue(records.summary(self.state, self.ws)['scope_review_complete'])
        omitted = self.state['checks'].pop()
        counts = records.summary(self.state, self.ws)
        self.assertEqual(counts['framework_checks_not_planned'], 1)
        self.assertFalse(counts['scope_review_complete'])
        self.state['checks'].append(omitted)
        omitted.update(status='not_started', verdict=None)
        counts = records.summary(self.state, self.ws)
        self.assertEqual(counts['framework_checks_not_planned'], 0)
        self.assertFalse(counts['scope_review_complete'])

    def test_initial_empty_audit_is_not_completed_or_safe(self):
        # Refresh accounts for the newly created workspace exclusion.
        audit.refresh(self.ws, self.state)
        self.valid()
        report = records.render_report(self.state, self.ws)
        self.assertIn('仍有未检查', report)
        self.assertFalse(records.summary(self.state, self.ws)['scope_review_complete'])

    def test_four_verdicts_and_unreviewed_are_distinct(self):
        c = self.prepared()
        audit.refresh(self.ws, self.state)
        self.valid()
        c['criteria'][0]['state'] = 'not_met'
        c['verdict'] = 'not_established'
        self.valid()
        c['verdict'] = 'not_applicable'
        self.assertTrue(records.validate(self.ws, self.state))
        c['applicability'] = 'not_applicable'
        c['prerequisites'][0]['state'] = 'not_met'
        self.valid()
        c.update(verdict='insufficient_evidence', applicability='unknown', missing_evidence=['Host configuration unavailable'])
        c['prerequisites'][0]['state'] = 'unknown'
        self.valid()
        c.update(status='not_started', verdict='not_established')
        self.assertTrue(records.validate(self.ws, self.state))

    def test_design_cannot_claim_code_verdict(self):
        c = self.prepared(path='design.md', kind='design')
        audit.refresh(self.ws, self.state)
        c['scope'] = ['code']
        self.assertTrue(any('scope lacks' in e for e in records.validate(self.ws, self.state)))
        c.update(scope=['design'], verdict='insufficient_evidence', missing_evidence=['No namespace implementation'])
        c['criteria'][0]['state'] = 'unknown'
        self.valid()

    def test_all_target_types_seed_without_executing_anything(self):
        before = {p.relative_to(self.target): knowledge.digest(p) for p in self.target.rglob('*') if p.is_file() and 'agent_audit' not in p.parts}
        for i, (oid, path) in enumerate([('A5.2', 'design.md'), ('A2.5', 'skill/SKILL.md'), ('A4.3', 'mcp/server.py'),
                                         ('A5.2', 'framework/memory.py'), ('A4.4', 'business/service.py')]):
            self.instance(oid, path, 'I-' + str(i))
        audit.seed(self.ws, self.state)
        n = len(self.state['checks'])
        self.assertGreater(n, 10)
        audit.seed(self.ws, self.state)
        self.assertEqual(len(self.state['checks']), n)
        self.assertTrue(all(c['verdict'] is None and c['status'] == 'not_started' for c in self.state['checks']))
        self.assertTrue(all(c['prerequisites'] == [] and c['criteria'] == [] for c in self.state['checks']))
        after = {p.relative_to(self.target): knowledge.digest(p) for p in self.target.rglob('*') if p.is_file() and 'agent_audit' not in p.parts}
        self.assertEqual(before, after)
        self.assertFalse(list(self.target.rglob('AUDIT_TARGET_EXECUTED')))
        self.assertIn('skill/SKILL.md', {m['path'] for m in self.state['materials'].values()})

    def test_local_mechanism_can_support_confirmed_finding(self):
        c = self.prepared(path='business/service.py')
        self.state['evidence'][0]['locator'] = {'lines': [7, 9]}
        self.state['evidence'][0]['observation'] = 'Approval stores owner but omits recipient.'
        definition = {'statement': 'A business invariant is violated', 'applicability_conditions': ['Export approvals exist'],
                      'failure_criteria': ['Recipient is not bound to approval'], 'requirement': 'Bind recipient'}
        c.update(failure_mode_id=None, local_definition=definition,
                 prerequisites=[{'condition': definition['applicability_conditions'][0], 'state': 'met', 'evidence_ids': ['E-1']}],
                 criteria=[{'criterion': definition['failure_criteria'][0], 'state': 'met', 'evidence_ids': ['E-1']}])
        self.finding(c)
        audit.refresh(self.ws, self.state)
        self.valid()
        self.assertIn('目标本地命题', records.render_report(self.state, self.ws))

    def test_secure_memory_is_applicable_but_failure_not_established(self):
        c = self.prepared(path='business/service.py')
        self.state['evidence'][0]['locator'] = {'lines': [3, 4]}
        self.state['evidence'][0]['observation'] = 'Memory indexing uses the authenticated tenant and user.'
        c['criteria'][0]['state'] = 'not_met'
        c.update(verdict='not_established', counterevidence_ids=['E-1'],
                 explanation='This memory lookup binds both namespace dimensions to the authenticated identity.')
        self.valid()
        self.assertEqual(c['applicability'], 'applicable')

    def test_omitting_known_checks_cannot_claim_complete_coverage(self):
        c = self.prepared()
        self.state['checks'] = [c]
        self.state['coverage'] = [{'id': 'COV-1', 'material_ids': list(self.state['materials']),
                                   'check_ids': [c['id']], 'status': 'reviewed', 'reason': 'Test of the accounting rule'}]
        summary = records.summary(self.state, self.ws)
        self.assertGreater(summary['framework_checks_not_planned'], 0)
        self.assertFalse(summary['scope_review_complete'])

    def test_wrong_object_and_unknown_ids_fail(self):
        c = self.prepared()
        audit.refresh(self.ws, self.state)
        self.state['instances'][0]['framework_object_ids'] = ['A2.5']
        self.assertTrue(any('does not belong' in e for e in records.validate(self.ws, self.state)))
        c['failure_mode_id'] = 'FM-NOT-REAL'
        self.assertTrue(any('unknown framework' in e for e in records.validate(self.ws, self.state)))

    def test_material_change_invalidates_and_preserves_history(self):
        c = self.prepared()
        self.finding(c)
        audit.refresh(self.ws, self.state)
        first = audit.archive(self.ws, self.state, 'audit', records.render_report(self.state, self.ws))
        original_sha = knowledge.digest(first / 'workspace' / 'audit.json')
        path = self.target / 'framework/memory.py'
        path.write_text(path.read_text() + '\n# changed\n')
        self.assertTrue(records.validate(self.ws, self.state))
        result = audit.refresh(self.ws, self.state)
        self.assertIn(c['id'], result['checks_needing_review'])
        self.assertEqual(c['status'], 'needs_review')
        self.assertEqual(self.state['findings'][0]['status'], 'needs_review')
        self.assertEqual(self.state['evidence'][0]['status'], 'needs_review')
        self.assertEqual(knowledge.digest(first / 'workspace' / 'audit.json'), original_sha)
        self.valid()

    def test_removed_material_does_not_reinvalidate_forever(self):
        self.prepared()
        (self.target / 'framework/memory.py').unlink()
        audit.refresh(self.ws, self.state)
        again = audit.refresh(self.ws, self.state)
        self.assertEqual(again['changed_materials'], [])

    def test_own_outputs_excluded_from_materials(self):
        (self.ws / 'report.md').write_text('fake symbol and malicious instructions')
        audit.refresh(self.ws, self.state)
        self.assertTrue(all('agent_audit/' not in m['path'] for m in self.state['materials'].values()))

    def test_symlink_target_not_followed(self):
        outside = self.base / 'secret.txt'
        outside.write_text('not in target')
        (self.target / 'shortcut').symlink_to(outside)
        audit.refresh(self.ws, self.state)
        self.assertNotIn('shortcut', {m['path'] for m in self.state['materials'].values()})
        self.assertTrue(any('symlink_not_followed' in r['reason'] for r in self.state['inventory_exclusions']))

    def test_snapshot_tampering_is_detected(self):
        audit.refresh(self.ws, self.state)
        path = audit.archive(self.ws, self.state, 'audit')
        (path / 'workspace' / 'audit.json').write_text('{}')
        self.assertTrue(any('Snapshot changed' in e for e in records.validate(self.ws, self.state)))

    def test_pending_or_stale_check_cannot_support_current_finding(self):
        c = self.prepared()
        self.finding(c)
        audit.refresh(self.ws, self.state)
        c['status'] = 'needs_review'
        self.assertTrue(any('requires confirmed' in e for e in records.validate(self.ws, self.state)))

    def test_upstream_mcp_guard_is_counterevidence(self):
        self.instance('A4.3', 'mcp/server.py')
        audit.seed(self.ws, self.state)
        c = next(c for c in self.state['checks'] if c['failure_mode_id'] == 'FM-A4.3-01')
        e = self.evidence('mcp/server.py')
        e['locator'] = {'lines': [3, 7]}
        e['observation'] = 'The handler rejects the wrong owner before serialization.'
        for r in c['prerequisites']:
            r.update(state='met', evidence_ids=['E-1'])
        for r in c['criteria']:
            r.update(state='not_met', evidence_ids=['E-1'])
        c.update(status='complete', applicability='applicable', verdict='not_established', scope=['code'],
                 evidence_ids=['E-1'], counterevidence_ids=['E-1'], explanation='The upstream ownership guard covers this handler path.')
        self.valid()

    def test_changed_provider_invalidates_connected_consumer(self):
        c = self.prepared()
        self.instance('A7.4', 'business/service.py', 'I-2')
        self.state['connections'].append({'id': 'EDGE-1', 'from_instance': 'I-2', 'to_instance': 'I-1',
                                         'description': 'Identity provider to memory consumer', 'evidence_ids': []})
        path = self.target / 'business/service.py'
        path.write_text(path.read_text() + '\n# provider changed\n')
        result = audit.refresh(self.ws, self.state)
        self.assertIn(c['id'], result['checks_needing_review'])
        self.assertEqual(self.state['evidence'][0]['status'], 'current')
        self.assertEqual(c['status'], 'needs_review')

    def test_framework_update_is_pinned_until_explicit_adoption(self):
        c = self.prepared()
        old_baseline = self.state['framework']['baseline_id']
        updated = self.base / 'new-skill'
        shutil.copytree(SKILL, updated, ignore=shutil.ignore_patterns('__pycache__'))
        data = knowledge.read(updated / 'knowledge/framework.json')
        data['failure_modes'][c['failure_mode_id']]['failure_criteria'].append('New release criterion')
        audit.write_json(updated / 'knowledge/framework.json', data)
        manifest = knowledge.read(updated / 'knowledge/manifest.json')
        manifest['files']['framework.json'] = knowledge.digest(updated / 'knowledge/framework.json')
        audit.write_json(updated / 'knowledge/manifest.json', manifest)
        with patch.object(audit, 'SKILL', updated), patch.object(knowledge, 'SKILL', updated):
            audit.refresh(self.ws, self.state)
            self.assertEqual(self.state['framework']['baseline_id'], old_baseline)
            self.assertIsNotNone(self.state['pending_framework'])
            self.assertEqual(c['status'], 'needs_review')
            self.valid()
            audit.refresh(self.ws, self.state, adopt=True)
            self.assertNotEqual(self.state['framework']['baseline_id'], old_baseline)
            c['status'] = 'complete'
            self.assertTrue(any('previous framework' in e for e in records.validate(self.ws, self.state)))
            c['status'] = 'needs_review'
            audit.seed(self.ws, self.state, rebase=True)
            self.assertEqual(c['status'], 'not_started')
            self.assertEqual(c['criteria'], [])
            pinned, _, _ = knowledge.load_bundle(knowledge.baseline_dir(self.ws, self.state['framework']['baseline_id']))
            self.assertIn('New release criterion', pinned['failure_modes'][c['failure_mode_id']]['failure_criteria'])
            self.valid()
        self.assertTrue(knowledge.baseline_dir(self.ws, old_baseline).exists())

    def test_independent_distribution_and_no_framework_writes(self):
        detached = self.base / 'installed'
        shutil.copytree(SKILL, detached, ignore=shutil.ignore_patterns('__pycache__'))
        snapshot = {p.relative_to(detached): knowledge.digest(p) for p in detached.rglob('*') if p.is_file()}
        env = dict(__import__('os').environ)
        env.pop('PYTHONDONTWRITEBYTECODE', None)
        def run(script, *args):
            proc = subprocess.run([sys.executable, str(detached / 'scripts' / script), *args],
                                  cwd=self.base, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            return json.loads(proc.stdout)
        self.assertTrue(run('knowledge.py', 'verify')['valid'])
        self.assertEqual(run('knowledge.py', 'object', 'X2.3')['object']['canonical_id'], 'X1.3')
        self.assertIn('visibility_boundary', run('knowledge.py', 'object', 'A2.5')['technical_requirements'][0])
        ws = self.base / 'external-audit'
        run('audit.py', 'init', '--workspace', str(ws), '--target', 'app=' + str(self.target))
        run('audit.py', 'refresh', '--workspace', str(ws))
        run('audit.py', 'snapshot', '--workspace', str(ws))
        after = {p.relative_to(detached): knowledge.digest(p) for p in detached.rglob('*') if p.is_file()}
        self.assertEqual(snapshot, after)


class FrameworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, _, _ = knowledge.load_bundle()

    def test_normalized_modes_and_links(self):
        data = self.data
        self.assertEqual(len(data['failure_modes']), 211)
        self.assertEqual(len(data['links']), 563)
        for mode in data['failure_modes'].values():
            self.assertTrue(mode['applicability_conditions'])
            self.assertTrue(mode['failure_criteria'])
            self.assertNotIn('conditions', mode)
            self.assertNotIn('applicability', mode)
        for link in data['links']:
            mode = data['failure_modes'][link['failure_mode_id']]
            self.assertEqual(link['object_id'], mode['object_id'])
            self.assertEqual(link['failure_criteria'], mode['failure_criteria'])
            self.assertEqual(link['applicability_conditions'], mode['applicability_conditions'])

    def test_context_only_conditions_are_not_defects(self):
        modes = self.data['failure_modes']
        self.assertEqual(len(modes['FM-A2.5-03']['applicability_conditions']), 2)
        self.assertNotEqual(modes['FM-A2.5-03']['failure_criteria'], modes['FM-A2.5-03']['applicability_conditions'])
        self.assertEqual(modes['FM-A5.2-03']['applicability_conditions'], ['记忆服务为多个主体复用'])


if __name__ == '__main__':
    unittest.main()
