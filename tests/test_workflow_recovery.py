"""Regression fixtures for recoverable review, reporting and workspace snapshots.

Only synthetic targets and isolated workspaces are used; no real audit conclusions
are copied into these tests. AUDIT_REPO_TEST_DIR and AUDIT_SKILL_TEST_DIR allow the
same fixtures to exercise a detached candidate or the pre-change implementation.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(os.environ.get('AUDIT_REPO_TEST_DIR', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT / 'tests'))
import test_audit_scale as fixtures

audit = fixtures.audit
decide = fixtures.decide
gate = fixtures.gate
knowledge = fixtures.knowledge
merge = fixtures.merge
records = fixtures.records
review = fixtures.review
surface = fixtures.surface
units = fixtures.units


class CliMixin:
    def cli(self, *args, expected=0):
        proc = subprocess.run(
            [sys.executable, '-B', str(fixtures.SKILL / 'scripts' / 'audit.py'),
             *args, '--workspace', str(self.ws)],
            cwd=self.base, capture_output=True, text=True, timeout=30,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
        return json.loads(proc.stdout or proc.stderr)


class WorkspaceSnapshotTests(fixtures.ScaleBase):
    def populate_workspace(self):
        files = {
            'units/U-SH101/partial.json': b'{"findings": [], "not_merged": true}\n',
            'units/U-SH101/progress.json': b'{"files_done": 2, "files_total": 7}\n',
            'units/U-SH101/progress.md': '已完成部分阅读，尚未合入。\n'.encode(),
            'units/U-SH101/verify/claim-01.md': b'# Verify\nUnresolved counterevidence.\n',
            'units/_review_1.json': b'{"reviews": [], "corrections": []}\n',
            'units/_review_1.md': b'# Review ledger\nPending verification.\n',
            'run-state.json': b'{"phase": 2, "round": 1, "merged": false}\n',
            'run-logs/worker-deliverables-round-1/U-SH101/partial.json': b'{"original": true}\n',
            'run-logs/.checkpoint': b'fixture checkpoint\x00\xff',
            'run-logs/snapshots/local-checkpoint.txt': b'Nested directory is workspace content.\n',
            'observations/OBS-fixture.json': b'{"observation_mode": "simulation"}\n',
            'STATUS.md': b'Segment delivery complete; review pending.\n',
            'process-observations.md': b'Unmerged products must survive archival.\n',
            # A workspace may already contain a file with the snapshot metadata name.
            'manifest.json': b'{"belongs_to": "workspace", "preserve": true}\n',
            'report.md': b'[Synthetic observation](observations/OBS-fixture.json)\n',
            'report.sarif.json': b'{"runs": []}\n',
        }
        for name, data in files.items():
            path = self.ws / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.ws / 'units' / 'U-SH102' / 'verify').mkdir(parents=True, exist_ok=True)
        return {path.relative_to(self.ws).as_posix(): path.read_bytes()
                for path in self.ws.rglob('*')
                if path.is_file() and path.relative_to(self.ws).parts[0] != 'snapshots'}

    def new_snapshot(self):
        self.populate_workspace()
        snapshot = audit.archive(self.ws, self.state, 'mid-review')
        self.assertEqual(knowledge.read(snapshot / 'manifest.json').get('format_version'), 2)
        self.assertTrue((snapshot / 'workspace' / 'run-state.json').is_file())
        self.assertEqual(records.validate(self.ws, self.state), [])
        return snapshot

    def test_snapshot_preserves_every_workspace_file_without_recursive_history(self):
        original = self.populate_workspace()
        first = audit.archive(self.ws, self.state, 'first')
        original['run-state.json'] = b'{"phase": 2, "round": 2, "merged": false}\n'
        (self.ws / 'run-state.json').write_bytes(original['run-state.json'])
        second = audit.archive(self.ws, self.state, 'second')
        payload = second / 'workspace'
        copied = {p.relative_to(payload).as_posix(): p.read_bytes()
                  for p in payload.rglob('*') if p.is_file()}
        self.assertEqual(set(copied), set(original))
        for name, data in original.items():
            self.assertEqual(hashlib.sha256(copied[name]).hexdigest(),
                             hashlib.sha256(data).hexdigest(), name)
        self.assertFalse((payload / 'snapshots').exists(), 'do not recursively archive older snapshots')
        self.assertTrue((payload / 'units' / 'U-SH102' / 'verify').is_dir(),
                        'empty output directories are part of the recoverable workspace')
        self.assertTrue(any(name.startswith('baselines/') for name in copied), 'pin the actual baseline too')
        manifest = knowledge.read(second / 'manifest.json')
        self.assertEqual(manifest['format_version'], 2)
        expected = {'workspace/' + name: knowledge.digest(payload / name) for name in original}
        self.assertEqual(manifest['files'], expected)
        self.assertEqual(manifest['directories'],
                         sorted(p.relative_to(second).as_posix()
                                for p in second.rglob('*') if p.is_dir()))
        self.assertIn(self.state['framework']['baseline_id'], manifest['baseline_ids'])
        self.assertEqual((first / 'workspace' / 'run-state.json').read_bytes(),
                         b'{"phase": 2, "round": 1, "merged": false}\n')
        self.assertEqual(records.validate(self.ws, self.state), [])

    def test_snapshot_report_links_resolve_inside_its_copied_workspace(self):
        self.populate_workspace()
        report = (self.ws / 'report.md').read_text()
        snapshot = audit.archive(self.ws, self.state, 'with-report', report)
        report_path = snapshot / 'workspace' / 'report.md'
        self.assertEqual(report_path.read_text(), report)
        href = re.search(r'\]\(([^)]+)\)', report_path.read_text()).group(1)
        linked = (report_path.parent / href).resolve()
        self.assertTrue(linked.is_relative_to(snapshot.resolve()))
        original_observation = self.ws / 'observations' / 'OBS-fixture.json'
        original_observation.unlink()
        self.assertEqual(linked.read_bytes(), b'{"observation_mode": "simulation"}\n',
                         'archived report must not depend on mutable live-workspace artifacts')

    def test_nested_content_tampering_and_deletion_are_detected(self):
        for mutation in ('change', 'delete', 'unlisted'):
            with self.subTest(mutation=mutation):
                snapshot = self.new_snapshot()
                nested = snapshot / 'workspace' / 'units' / 'U-SH101' / 'partial.json'
                if mutation == 'change':
                    nested.write_bytes(b'{"different": true}\n')
                elif mutation == 'delete':
                    nested.unlink()
                else:
                    manifest_path = snapshot / 'manifest.json'
                    manifest = knowledge.read(manifest_path)
                    del manifest['files'][nested.relative_to(snapshot).as_posix()]
                    audit.write_json(manifest_path, manifest)
                self.assertTrue(records.validate(self.ws, self.state), mutation)
                shutil.rmtree(snapshot)

    def test_snapshot_rejects_manifest_paths_that_escape_the_payload(self):
        outside = self.base / 'outside.txt'
        outside.write_bytes(b'outside the snapshot\n')
        for name in ('../outside.txt', 'workspace/../../outside.txt', str(outside.resolve())):
            with self.subTest(name=name):
                snapshot = self.new_snapshot()
                manifest_path = snapshot / 'manifest.json'
                manifest = knowledge.read(manifest_path)
                manifest['files'][name] = knowledge.digest(outside)
                audit.write_json(manifest_path, manifest)
                self.assertTrue(records.validate(self.ws, self.state), name)
                shutil.rmtree(snapshot)

    def test_source_symlinks_are_refused_without_publishing_partial_snapshots(self):
        self.populate_workspace()
        outside = self.base / 'external'
        outside.mkdir()
        (outside / 'evidence.txt').write_bytes(b'outside bytes\n')
        for name, target in (('linked-file', outside / 'evidence.txt'), ('linked-dir', outside)):
            with self.subTest(name=name):
                link = self.ws / 'run-logs' / name
                link.symlink_to(target)
                before = set((self.ws / 'snapshots').glob('*'))
                with self.assertRaises((ValueError, OSError)):
                    audit.archive(self.ws, self.state, 'must-not-publish')
                self.assertEqual(set((self.ws / 'snapshots').glob('*')), before,
                                 'failure must leave neither a complete-looking snapshot nor staging debris')
                link.unlink()
        self.assertEqual((outside / 'evidence.txt').read_bytes(), b'outside bytes\n')

    def test_archived_file_and_directory_symlinks_fail_even_when_hashes_match(self):
        for mode in ('file', 'directory'):
            with self.subTest(mode=mode):
                snapshot = self.new_snapshot()
                if mode == 'file':
                    victim = snapshot / 'workspace' / 'run-state.json'
                    target = self.base / 'same-bytes.json'
                    target.write_bytes(victim.read_bytes())
                    victim.unlink()
                else:
                    victim = snapshot / 'workspace' / 'run-logs'
                    target = self.base / 'same-files'
                    victim.rename(target)
                victim.symlink_to(target)
                self.assertTrue(records.validate(self.ws, self.state), mode)
                victim.unlink()
                shutil.rmtree(snapshot)

    def test_copy_failure_and_concurrent_workspace_changes_do_not_publish_snapshots(self):
        original_copy = shutil.copy2
        for mutation in ('copy-error', 'new-file', 'deleted-file', 'changed-file'):
            with self.subTest(mutation=mutation):
                self.populate_workspace()
                trigger = self.ws / 'run-state.json'
                added = self.ws / 'units' / 'new-worker-output.json'
                before = set((self.ws / 'snapshots').glob('*'))
                injected = []

                def copy_with_mutation(source, destination, *args, **kwargs):
                    result = original_copy(source, destination, *args, **kwargs)
                    if Path(source) == trigger and not injected:
                        injected.append(mutation)
                        if mutation == 'copy-error':
                            raise OSError('Fixture copy interrupted after writing a file')
                        if mutation == 'new-file':
                            added.write_text('{"arrived_during_snapshot": true}\n')
                        elif mutation == 'deleted-file':
                            (self.ws / 'units' / 'U-SH101' / 'partial.json').unlink()
                        else:
                            trigger.write_text('{"round": "changed during copy"}\n')
                    return result

                with mock.patch.object(audit.shutil, 'copy2', side_effect=copy_with_mutation):
                    with self.assertRaises((ValueError, OSError)):
                        audit.archive(self.ws, self.state, 'interrupted-' + mutation)
                self.assertEqual(injected, [mutation], 'the failure must occur during actual copying')
                self.assertEqual(set((self.ws / 'snapshots').glob('*')), before)
                added.unlink(missing_ok=True)

    def test_legacy_three_file_snapshot_remains_verifiable(self):
        snapshot = self.ws / 'snapshots' / 'legacy-three-file'
        snapshot.mkdir(parents=True)
        audit.write_json(snapshot / 'audit.json', self.state)
        (snapshot / 'report.md').write_text('Historical report.\n')
        audit.write_json(snapshot / 'report.sarif.json', {'runs': []})
        files = {p.name: knowledge.digest(p) for p in snapshot.iterdir()}
        audit.write_json(snapshot / 'manifest.json', {
            'created_at': audit.now(), 'purpose': 'audit', 'files': files,
            'baseline_ids': [self.state['framework']['baseline_id']]})
        self.assertEqual(records.validate(self.ws, self.state), [])
        (snapshot / 'report.md').write_text('Changed historical report.\n')
        self.assertTrue(records.validate(self.ws, self.state))


class ReviewLifecycleTests(CliMixin, fixtures.ProductBase):
    def finding_product(self):
        unit, path = self._product()
        payload = self._complete(path, unit)
        finding = payload['findings'][0]
        check = next(c for c in payload['checks'] if c['id'] == finding['check_ids'][0])
        for criterion in check['prerequisites'] + check['criteria']:
            criterion.update(state='met', evidence_ids=finding['evidence_ids'])
        check.update(applicability='applicable', verdict='confirmed',
                     explanation='Synthetic fixture: all prerequisites and failure criteria established.')
        payload['return_line'] = payload['return_line'].replace('confirmed=0, fp=0, unclosed=1',
                                                              'confirmed=1, fp=0, unclosed=0')
        audit.write_json(path, payload)
        review_path = self.ws / 'units' / unit['id'] / 'finding-review.json'
        audit.write_json(review_path, {
            'reviewer': 'fixture-reviewer', 'decision': 'retain',
            'rationale': 'Synthetic fixture evidence supports each selected criterion.',
            'counterevidence_analysis': 'The fixture provides no disqualifying control.',
            'evidence_ids': finding['evidence_ids'], 'counterevidence_ids': []})
        return unit, finding['id'], review_path

    def test_prepare_then_merge_then_review_binds_to_the_merged_finding(self):
        unit, finding_id, review_path = self.finding_product()
        self.assertFalse(self.reload()['findings'])
        premature = self.cli('review', '--finding', finding_id,
                             '--review-file', str(review_path), expected=1)
        self.assertTrue(premature.get('error'))
        self.assertEqual(self.reload()['reviews'], [])
        prepared = self.cli('review', '--prepare', '--unit', unit['id'])
        self.assertEqual(prepared['mechanical'], 'PASS')
        self.assertEqual(self.reload()['findings'], [], 'prepare must not implicitly merge')
        self.cli('merge', '--unit', unit['id'])
        finding = next(f for f in self.reload()['findings'] if f['id'] == finding_id)
        self.assertEqual(finding['status'], 'needs_review')
        written = self.cli('review', '--finding', finding_id, '--review-file', str(review_path))
        finding = next(f for f in self.reload()['findings'] if f['id'] == finding_id)
        ledger = review.latest_review(self.state, finding)
        self.assertEqual(finding['status'], 'current')
        self.assertEqual(written['id'], ledger['id'])
        self.assertEqual(ledger['finding_id'], finding_id)
        self.assertEqual(ledger['subject_sha256'], review.subject_digest(self.state, finding))
        self.assertEqual(ledger['evidence_sha256'], review.evidence_digest(
            self.state, ledger['evidence_ids'] + ledger['counterevidence_ids']))
        self.assertEqual(records.validate(self.ws, self.state), [])

    def test_registered_review_cannot_silently_cover_later_content_changes(self):
        unit, finding_id, review_path = self.finding_product()
        self.cli('review', '--prepare', '--unit', unit['id'])
        self.cli('merge', '--unit', unit['id'])
        self.cli('review', '--finding', finding_id, '--review-file', str(review_path))
        pristine = copy.deepcopy(self.reload())
        for section, field in (('findings', 'title'), ('checks', 'explanation'),
                               ('evidence', 'observation')):
            with self.subTest(section=section):
                changed = copy.deepcopy(pristine)
                finding = next(f for f in changed['findings'] if f['id'] == finding_id)
                if section == 'findings':
                    subject = finding
                else:
                    selected = finding['check_ids' if section == 'checks' else 'evidence_ids'][0]
                    subject = next(row for row in changed[section] if row['id'] == selected)
                subject[field] += ' Changed after review.'
                ledger = review.latest_review(changed, finding)
                self.assertNotEqual(ledger['subject_sha256'], review.subject_digest(changed, finding))
                self.assertTrue(records.validate(self.ws, changed))


class ClosedWorkspaceBase(CliMixin, fixtures.ScaleBase):
    target_subdir = 'tests/fixtures/audit/design.md'

    def close_workspace(self):
        self.plan()
        self.resolve_all()
        self.freeze1()
        unit = self.state['units'][0]
        evidence_id = 'E-%s-001' % unit['id'][2:]
        path = self.product(unit)
        payload = knowledge.read(path)
        payload['evidence'][0]['kind'] = 'design'
        audit.write_json(path, payload)
        audit.seed_partial(self.ws, self.state, path)
        merge.merge_unit(self.ws, self.state, unit['id'])
        self.reload()
        for check in self.state['checks']:
            for prerequisite in check['prerequisites']:
                prerequisite.update(state='not_met', evidence_ids=[evidence_id])
            check.update(status='complete', applicability='not_applicable',
                         verdict='not_applicable', scope=['design'], evidence_ids=[evidence_id],
                         explanation='Design document; the implementation is not present in this fixture.')
        for row in self.state['units']:
            for name in units.DIMENSIONS:
                row['dimensions'][name] = {'state': 'na', 'reason': 'design-only material'}
        self.state['coverage'].append({
            'id': 'COV-%s-01' % unit['id'][2:], 'material_ids': unit['material_ids'],
            'check_ids': [c['id'] for c in self.state['checks']], 'status': 'reviewed',
            'reason': 'Synthetic design scope read in full', 'analysis_method': 'full read',
            'limitations': 'design scope only'})
        audit.save(self.ws, self.state)
        self.freeze2()
        self.reload()
        for kind in units.CROSS_TYPES:
            decide.decide(self.ws, self.state, 'cross_scope:' + kind,
                          'not_needed', 'Fixture has no cross-unit work.')
        self.state['queue']['phase3_critic'] = 'Fixture critique completed.'
        units.freeze(self.ws, self.state, 3)
        self.reload()
        result = gate.run(self.ws, self.state)
        self.assertEqual(result['gate'], 'PASS', result)

    def open_report_todo(self):
        self.state['report_todos'] = [{'id': 'RT-01', 'status': 'open',
                                      'instruction': 'State the design-only scope in the report.'}]
        audit.save(self.ws, self.state)


class ReportPreparationGateTests(ClosedWorkspaceBase):
    def test_prepare_gate_defers_only_open_report_todos_without_closing_them(self):
        self.close_workspace()
        self.open_report_todo()
        pristine = copy.deepcopy(self.state)
        raw = (self.ws / 'audit.json').read_bytes()
        final = gate.run(self.ws, self.state)
        self.assertEqual(final['gate'], 'FAIL')
        self.assertEqual(final['failed'], ['G7'])
        preparation = gate.run(self.ws, self.state, prepare_report=True)
        self.assertEqual(preparation['gate'], 'PASS', preparation)
        self.assertEqual(preparation['rows'], gate.evaluate(self.ws, self.state, prepare_report=True))
        self.assertEqual(self.state, pristine, 'preparation must not mark report work complete')
        self.assertEqual((self.ws / 'audit.json').read_bytes(), raw)
        self.assertEqual(gate.run(self.ws, self.state, prepare_report=False)['gate'], 'FAIL')

    def test_prepare_gate_preserves_other_gate_and_structural_failures(self):
        self.close_workspace()
        self.open_report_todo()
        clean = copy.deepcopy(self.state)
        mutations = (
            ('incomplete check', lambda state: state['checks'][0].update(status='pending'), 'G7'),
            ('unfinished file', lambda state: state['units'][0]['progress'].update(files_done=0), 'G2'),
            ('missing coverage', lambda state: state['coverage'].clear(), 'G8'),
            ('invalid todo', lambda state: state['report_todos'][0].update(instruction=''), None),
        )
        for name, mutate, gate_id in mutations:
            with self.subTest(name=name):
                changed = copy.deepcopy(clean)
                mutate(changed)
                result = gate.run(self.ws, changed, prepare_report=True)
                self.assertEqual(result['gate'], 'FAIL', result)
                if gate_id:
                    self.assertIn(gate_id, result['failed'])
                else:
                    self.assertTrue(result['structural_errors'])

    def test_cli_prepare_allows_report_work_but_default_gate_requires_it_done(self):
        self.close_workspace()
        self.open_report_todo()
        self.assertEqual(self.cli('gate', expected=1)['gate'], 'FAIL')
        self.assertEqual(self.cli('gate', '--prepare')['gate'], 'PASS')
        self.assertEqual(self.reload()['report_todos'][0]['status'], 'open')
        self.state['report_todos'][0]['status'] = 'applied'
        audit.save(self.ws, self.state)
        self.assertEqual(self.cli('gate')['gate'], 'PASS')


class ObjectScopeCorrectionTests(ClosedWorkspaceBase):
    def gate_rows(self):
        return {row['id']: row for row in gate.evaluate(self.ws, self.state)}

    def test_formal_scope_corrections_preserve_freeze_and_current_coverage_obligations(self):
        self.close_workspace()
        frozen = copy.deepcopy(self.state['queue']['phase1_frozen'])
        ruled_out = self.state['object_scope'][0]['subject']
        decide.decide(self.ws, self.state, 'object_scope:' + ruled_out,
                      'involved', 'Later fixture evidence establishes this responsibility.')
        self.reload()
        self.assertEqual(len(self.state['object_scope']), frozen['object_scope'] - 1)
        self.assertEqual(self.state['queue']['phase1_frozen'], frozen)
        rows = self.gate_rows()
        self.assertEqual(rows['G6']['status'], 'pass', rows['G6'])
        self.assertEqual(rows['G8']['status'], 'fail', 'involved needs an actual owning unit')
        self.assertIn(ruled_out, rows['G8']['detail'])
        unit = self.state['units'][0]
        previous_objects = list(unit['object_ids'])
        decide.decide(self.ws, self.state, 'object_mapping:' + unit['id'],
                      ','.join(previous_objects + [ruled_out]), 'Fixture responsibility belongs here.')
        self.reload()
        self.assertEqual(self.gate_rows()['G8']['status'], 'pass')
        self.assertEqual(self.gate_rows()['G6']['status'], 'pass')
        self.assertEqual(self.state['queue']['phase1_frozen'], frozen)

    def test_formal_new_noninvolvement_ruling_can_increase_count_after_freeze(self):
        self.close_workspace()
        frozen = copy.deepcopy(self.state['queue']['phase1_frozen'])
        unit = self.state['units'][0]
        formerly_declared = list(unit['object_ids'])
        self.assertTrue(formerly_declared)
        decide.decide(self.ws, self.state, 'object_mapping:' + unit['id'], 'none',
                      'Re-read synthetic design; it implements no framework responsibility.')
        for object_id in formerly_declared:
            decide.decide(self.ws, self.state, 'object_scope:' + object_id, 'not_involved',
                          'This synthetic design has no implementation of this responsibility.')
        self.reload()
        self.assertGreater(len(self.state['object_scope']), frozen['object_scope'])
        rows = self.gate_rows()
        self.assertEqual(rows['G6']['status'], 'pass', rows['G6'])
        self.assertEqual(rows['G8']['status'], 'pass', rows['G8'])
        self.assertEqual(self.state['queue']['phase1_frozen'], frozen)

    def test_current_scope_still_requires_reasons_and_unit_count_remains_frozen(self):
        self.close_workspace()
        saved = copy.deepcopy(self.state)
        missing_reason = self.state['object_scope'][0]
        missing_reason['reason'] = '   '
        rows = self.gate_rows()
        self.assertEqual(rows['G8']['status'], 'fail')
        self.assertTrue(records.validate(self.ws, self.state))
        self.state = saved
        self.state['units'].append(units.new_unit('U-SH99', 'repo_shard', 'unexpected unit',
                                                 material_ids=[]))
        self.assertEqual(self.gate_rows()['G6']['status'], 'fail')


class DocumentedContractTests(fixtures.ProductBase):
    def local_example(self):
        text = (fixtures.SKILL / 'references' / 'roles' / 'worker.md').read_text(encoding='utf-8')
        selected = []
        for block in re.findall(r'```json\s*\n(.*?)```', text, re.S):
            value = json.loads(block)
            if isinstance(value, dict) and 'local_definition' in value:
                selected.append((block, value))
        self.assertEqual(len(selected), 1, 'the worker must have one unambiguous complete local-check example')
        block, row = selected[0]
        return text, block, row

    def installed_check(self, name):
        import self_check
        registered = dict(self_check.CHECKS)
        self.assertIn(name, registered, 'the regression must exercise the registered skill self-check')
        return self_check, registered[name]

    def test_worker_local_check_example_can_be_merged_and_validated_as_given(self):
        _, _, sample = self.local_example()
        unit, path = self._product()
        payload = knowledge.read(path)
        sample['id'] = 'CHK-%s-0901' % unit['id'][2:]
        sample['instance_ids'] = [payload['instances'][0]['id']]
        sample['baseline_id'] = self.state['framework']['baseline_id']
        # Only identities are substituted. Reconstructing the row with new_check()
        # would silently fill omissions in the very example being tested.
        payload['checks'].append(sample)
        audit.write_json(path, payload)
        merge.merge_unit(self.ws, self.state, unit['id'])
        self.reload()
        merged = next(c for c in self.state['checks'] if c['id'] == sample['id'])
        self.assertEqual(merged, sample)
        self.assertEqual(records.validate(self.ws, self.state), [])

    def test_cli_example_self_check_rejects_a_retired_command(self):
        self_check, checker = self.installed_check('documented-cli-commands')
        document = self.base / 'commands.md'
        current = '```bash\npython3 -B "$S/audit.py" validate --workspace "$W"\n```\n'
        document.write_text(current, encoding='utf-8')
        with mock.patch.object(self_check, 'DOCS', [document]):
            self.assertEqual(checker(), [])
            document.write_text(current + '\n```bash\npython3 -B "$S/audit.py" read '
                                '--workspace "$W" --material MAT-fixture\n```\n', encoding='utf-8')
            self.assertTrue(checker(), 'a parser-retired command in an executable example must fail')

    def test_local_example_self_check_rejects_met_as_a_field_name(self):
        self_check, checker = self.installed_check('local-check-example')
        text, block, sample = self.local_example()
        candidate_skill = self.base / 'contract-skill'
        document = candidate_skill / 'references' / 'roles' / 'worker.md'
        document.parent.mkdir(parents=True)
        document.write_text(text, encoding='utf-8')
        with mock.patch.object(self_check, 'SKILL', candidate_skill):
            self.assertEqual(checker(), [])
            sample['prerequisites'] = [
                {'condition': 'Model-selected target fact', 'state': 'unknown', 'evidence_ids': []}]
            valid_sample = json.dumps(sample, ensure_ascii=False, indent=2) + '\n'
            document.write_text(text.replace(block, valid_sample, 1), encoding='utf-8')
            self.assertEqual(checker(), [], 'custom optional notes must not require a matching definition list')
            condition = sample['prerequisites'][0]
            condition['met'] = condition.pop('state')
            replacement = json.dumps(sample, ensure_ascii=False, indent=2) + '\n'
            self.assertEqual(text.count(block), 1)
            document.write_text(text.replace(block, replacement, 1), encoding='utf-8')
            self.assertTrue(checker(), 'a complete-looking example with a retired field must fail')



class ReplacementTransactionTests(CliMixin, fixtures.ProductBase):
    finding_product = ReviewLifecycleTests.finding_product

    def reviewed_product(self):
        unit, finding, review_path = self.finding_product()
        self.cli('merge', '--unit', unit['id'])
        self.cli('review', '--finding', finding, '--review-file', str(review_path))
        self.reload()
        return unit, self.ws / 'units' / unit['id'] / 'partial.json'

    def frozen_files(self):
        return {str(p.relative_to(self.ws)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.ws.rglob('*') if p.is_file()
                and p.name != 'review_worklist.md'}

    def test_replace_preflight_and_merge_preserve_unchanged_reviews(self):
        unit, path = self.reviewed_product()
        payload = knowledge.read(path)
        payload['coverage'][0]['reason'] += ' Reviewed description correction.'
        audit.write_json(path, payload)
        before = self.frozen_files()
        state_before = copy.deepcopy(self.state)
        ledgers = copy.deepcopy(self.state['reviews'])
        result = self.cli('review', '--prepare', '--replace', '--unit', unit['id'])
        self.assertEqual(result['mechanical'], 'PASS', result)
        self.assertEqual(self.frozen_files(), before, 'prepare may only write the worklist')
        self.assertEqual(self.state, state_before)
        self.cli('merge', '--replace', '--unit', unit['id'])
        self.reload()
        self.assertEqual(self.state['reviews'], ledgers)
        self.assertEqual(self.state['findings'][0]['status'], 'current')
        self.assertEqual(self.state['coverage'][0]['reason'], payload['coverage'][0]['reason'])
        self.assertEqual(knowledge.read(path)['findings'][0]['status'], 'needs_review')
        self.assertEqual(records.validate(self.ws, self.state), [])

    def test_changed_review_subjects_and_broken_references_leave_no_partial_retraction(self):
        unit, path = self.reviewed_product()
        original = knowledge.read(path)
        for collection, field in (('findings', 'title'), ('checks', 'explanation'),
                                  ('evidence', 'observation'), ('coverage', 'check_ids')):
            with self.subTest(collection=collection):
                payload = copy.deepcopy(original)
                if collection == 'coverage':
                    payload[collection][0][field] = ['CHK-missing-0001']
                else:
                    payload[collection][0][field] += ' changed'
                audit.write_json(path, payload)
                before = self.frozen_files()
                state_before = copy.deepcopy(self.state)
                result = self.cli('review', '--prepare', '--replace', '--unit', unit['id'], expected=1)
                self.assertEqual(result['mechanical'], 'FAIL')
                self.cli('merge', '--replace', '--unit', unit['id'], expected=1)
                with self.assertRaises(ValueError):
                    merge.merge_unit(self.ws, self.state, unit['id'], replace=True)
                self.assertEqual(self.state, state_before)
                self.assertEqual(self.frozen_files(), before)

    def test_withdrawn_candidate_can_be_replaced_by_its_counterevidence_record(self):
        unit, path = self.reviewed_product()
        payload = knowledge.read(path)
        finding = payload['findings'].pop()
        self.cli('review', '--withdraw', 'Synthetic refutation', '--finding', finding['id'])
        self.reload()
        check = next(c for c in payload['checks'] if c['id'] in finding['check_ids'])
        self.assertEqual(check['criteria'], [])
        check.update(verdict='not_established', counterevidence_ids=finding['evidence_ids'])
        payload['dismissed_candidates'] = [
            {'id': finding['id'], 'check_ids': finding['check_ids'], 'reason': 'Synthetic counterevidence'}]
        payload['return_line'] = payload['return_line'].replace('confirmed=1, fp=0', 'confirmed=0, fp=1')
        audit.write_json(path, payload)
        self.assertEqual(self.cli('review', '--prepare', '--replace', '--unit', unit['id'])['mechanical'], 'PASS')
        self.cli('merge', '--replace', '--unit', unit['id'])
        self.reload()
        self.assertEqual(self.state['findings'], [])
        self.assertEqual(self.state['dismissed_candidates'][0]['id'], finding['id'])
        self.assertEqual(len(self.state['withdrawn_reviews']), 1)

    def test_accepted_chains_and_scope_notes_reach_the_record_and_replace_without_duplicates(self):
        unit, path = self.reviewed_product()
        payload = knowledge.read(path)
        payload['chains'] = [{'id': 'CHAIN-fixture', 'title': 'Synthetic chain',
                              'entry_exposure': 'INT',
                              'steps': [{'check_id': payload['findings'][0]['check_ids'][0]}]}]
        payload['scope_notes'] = [{'id': 'SCOPE-fixture', 'observation': 'External contract absent',
                                   'why_unowned': 'Outside fixture inputs', 'next_coverage': 'Obtain contract'}]
        audit.write_json(path, payload)
        self.cli('review', '--prepare', '--replace', '--unit', unit['id'])
        self.cli('merge', '--replace', '--unit', unit['id'])
        self.reload()
        for collection in ('chains', 'scope_notes'):
            self.assertEqual(self.state[collection], [dict(payload[collection][0], unit_id=unit['id'])])
        payload['scope_notes'][0]['next_coverage'] = 'Obtain versioned contract'
        audit.write_json(path, payload)
        self.cli('merge', '--replace', '--unit', unit['id'])
        self.reload()
        self.assertEqual(len(self.state['chains']), 1)
        self.assertEqual(len(self.state['scope_notes']), 1)
        self.assertEqual(self.state['scope_notes'][0]['next_coverage'], 'Obtain versioned contract')
        payload['chains'][0]['steps'] = [{'check_id': 'CHK-unknown-01'}]
        audit.write_json(path, payload)
        before = self.frozen_files()
        self.cli('review', '--prepare', '--replace', '--unit', unit['id'], expected=1)
        self.cli('merge', '--replace', '--unit', unit['id'], expected=1)
        self.assertEqual(self.frozen_files(), before)

    def test_ordinary_merge_still_refuses_conflicts(self):
        unit, path = self.reviewed_product()
        result = self.cli('review', '--prepare', '--unit', unit['id'], expected=1)
        self.assertEqual(result['mechanical'], 'FAIL')
        before = self.frozen_files()
        self.cli('merge', '--unit', unit['id'], expected=1)
        self.assertEqual(self.frozen_files(), before)


class CompletionContractTests(ClosedWorkspaceBase):
    def test_cross_zero_files_cannot_hide_undelivered_or_incomplete_work(self):
        self.close_workspace()
        cross = units.new_unit('U-CX01', 'cross', 'Synthetic joint analysis',
                               phase=3, cross_type='joint', status='dispatched')
        self.state['units'].append(cross)
        def row():
            return next(r for r in gate.evaluate(self.ws, self.state) if r['id'] == 'G2')
        failed = row()
        self.assertEqual(failed['status'], 'fail')
        self.assertIn('U-CX01', failed['detail'])
        for name in units.DIMENSIONS:
            self.assertIn(name, failed['detail'], 'all missing dimensions must be actionable')
        cross['dimensions'] = {name: {'state': 'done', 'reason': 'Synthetic cross evidence compared.'}
                               for name in units.DIMENSIONS}
        self.assertEqual(row()['status'], 'fail', '0/0 and dimensions do not prove delivery')
        self.assertFalse(records.summary(self.state, self.ws)['scope_review_complete'])
        cross['status'] = 'merged'
        self.assertEqual(row()['status'], 'pass')
        self.assertTrue(records.summary(self.state, self.ws)['scope_review_complete'])
        cross['dimensions'].pop(units.DIMENSIONS[0])
        self.assertEqual(row()['status'], 'fail', 'missing is not completed')

    def test_prepare_and_merge_reject_missing_progress_or_dimensions_before_writing(self):
        self.plan()
        self.resolve_all()
        unit = self.state['units'][0]
        path = self.product(unit)
        pristine = knowledge.read(path)
        for field in ('progress', 'dimensions'):
            payload = copy.deepcopy(pristine)
            payload.pop(field)
            audit.write_json(path, payload)
            before = (self.ws / 'audit.json').read_bytes()
            self.assertTrue(merge.validate_partial(self.state, unit, payload))
            result = self.cli('review', '--prepare', '--unit', unit['id'], expected=1)
            self.assertEqual(result['mechanical'], 'FAIL')
            self.cli('merge', '--unit', unit['id'], expected=1)
            self.assertEqual((self.ws / 'audit.json').read_bytes(), before)

    def test_dimension_reason_and_progress_types_are_required(self):
        unit = units.new_unit('U-CX01', 'cross', 'Fixture', phase=3, cross_type='joint')
        source = {'progress': {'files_done': 0},
                  'dimensions': {name: {'state': 'na', 'reason': 'Synthetic non-applicability.'}
                                 for name in units.DIMENSIONS}}
        self.assertEqual(units.completion_errors(unit, source), [])
        for bad in (False, None, '0', -1):
            changed = copy.deepcopy(source)
            changed['progress']['files_done'] = bad
            self.assertTrue(units.completion_errors(unit, changed))
        for state in ('done', 'na', 'pending'):
            changed = copy.deepcopy(source)
            changed['dimensions'][units.DIMENSIONS[0]] = {'state': state, 'reason': ' '}
            self.assertTrue(units.completion_errors(unit, changed))


class CorrectionValueTests(ClosedWorkspaceBase):
    def test_empty_original_values_have_the_same_meaning_in_validation_and_gate(self):
        self.close_workspace()
        row = {'id': 'COR-01', 'target': 'fixture', 'field': 'data',
               'before': [], 'after': ['supported value'], 'reason': 'Synthetic correction', 'by': 'reviewer'}
        for original in ([], {}, '', 0, False, None):
            with self.subTest(original=original):
                self.state['corrections'] = [dict(row, before=original)]
                saved = copy.deepcopy(self.state)
                self.assertEqual(records.validate(self.ws, self.state), [])
                self.assertEqual(gate.run(self.ws, self.state)['gate'], 'PASS')
                self.assertEqual(self.state, saved, 'checking must not stringify original values')
        for field in ('before', 'after', 'reason'):
            bad = dict(row)
            bad.pop(field)
            self.state['corrections'] = [bad]
            self.assertTrue(records.validate(self.ws, self.state))
            self.assertIn('G7', gate.run(self.ws, self.state)['failed'])
        self.assertTrue(records.correction_errors([dict(row, reason=' ')]))
        self.assertTrue(records.correction_errors([dict(row, after=[])]))


class DerivedViewTests(fixtures.ScaleBase):
    def test_object_decisions_and_refresh_update_scatter_without_changing_freezes(self):
        self.plan()
        self.resolve_all()
        self.freeze2()
        self.reload()
        self.assertGreaterEqual(len(self.state['units']), 2)
        first, second = self.state['units'][:2]
        frozen = {k: copy.deepcopy(v) for k, v in self.state['queue'].items() if 'frozen' in k}
        judgments = {k: copy.deepcopy(self.state['queue'].get(k))
                     for k in ('joint_objects', 'joint_objects_reason', 'cross_scope')}
        # An object absent from the cached scatter becomes shared after two explicit decisions.
        for unit in (first, second):
            decide.decide(self.ws, self.state, 'object_mapping:' + unit['id'],
                          'A4.4', 'Synthetic explicit responsibility correction.')
        self.reload()
        shared = next(r for r in self.state['queue']['object_scatter'] if r['object'] == 'A4.4')
        self.assertEqual(shared['units'], sorted([first['id'], second['id']]))
        self.state['queue']['object_scatter'] = [{'object': 'fake', 'units': ['U-fake']}]
        audit.write_json(self.ws / 'audit.json', self.state)
        audit.refresh(self.ws, self.state)
        self.reload()
        self.assertEqual(self.state['queue']['object_scatter'], units._object_scatter(self.state))
        for key, value in frozen.items():
            self.assertEqual(self.state['queue'][key], value)
        for key, value in judgments.items():
            self.assertEqual(self.state['queue'].get(key), value)
        decide.decide(self.ws, self.state, 'object_mapping:' + second['id'],
                      'none', 'Synthetic object removed from this unit.')
        self.assertFalse(any(r['object'] == 'A4.4' for r in self.state['queue']['object_scatter']))

    def test_decision_consumers_ignore_a_stale_cache(self):
        self.plan()
        self.resolve_all()
        self.freeze2()
        self.reload()
        self.state['queue'].pop('joint_objects', None)
        self.state['queue']['object_scatter'] = []
        pending = units.pending_decisions(self.ws, self.state)
        self.assertTrue(any(r['kind'] == 'cross_cutting_objects' for r in pending))
        actual = units._object_scatter(self.state)[0]['object']
        decide.decide(self.ws, self.state, 'cross_cutting_objects:queue', actual,
                      'Fixture explicit joint selection, despite stale cache.')
        self.assertEqual(self.state['queue']['joint_objects'], actual)


class CoverageDeliveryTests(CliMixin, fixtures.ScaleBase):
    def test_report_and_snapshot_deliver_lossless_appendix_with_compact_main_section(self):
        self.plan()
        self.resolve_all()
        self.freeze1()
        unit = self.state['units'][0]
        for count in (0, 1, 400):
            self.state['coverage'] = [
                {'id': 'COV-%s-%04d' % (unit['id'][2:], index),
                 'status': 'reviewed', 'material_ids': unit['material_ids'], 'check_ids': [],
                 'reason': 'Synthetic scope ' + 'detail ' * 200, 'analysis_method': 'range analysis',
                 'limitations': 'Not runtime verification; <redacted> ``code`marker``'}
                for index in range(count)]
            audit.save(self.ws, self.state)
            result = self.cli('report')
            report = Path(result['report']).read_text(encoding='utf-8')
            appendix = Path(result['coverage_details']).read_text(encoding='utf-8')
            section = report.split('## 覆盖记录', 1)[1].split('\n## ', 1)[0]
            self.assertLessEqual(len('## 覆盖记录' + section) / len(report), .15)
            self.assertIn('[完整覆盖明细](coverage-details.md)', report)
            match = re.search(r'## 覆盖记录\n\n(`{3,})json\n(.*?)\n\1\n', appendix, re.S)
            self.assertIsNotNone(match)
            self.assertEqual(json.loads(match.group(2)), self.state['coverage'])
            self.assertEqual(records.render_coverage(self.state, self.ws), appendix)
            self.assertEqual(records.render_report(self.state, self.ws), report)
        result = self.cli('snapshot')
        snap = Path(result['snapshot'])
        self.assertTrue((snap / 'workspace' / 'coverage-details.md').is_file())
        self.assertEqual((snap / 'workspace' / 'coverage-details.md').read_text(encoding='utf-8'), appendix)
        self.assertEqual(audit.snapshot_manifest(snap)['format_version'], 2)

    def test_markdown_escapes_prose_but_preserves_code_literals(self):
        text = '代码 `<T>&`、``<tag>`token``；正文 <external-db-secret> &lt;tag&gt;'
        expected = '代码 `<T>&`、``<tag>`token``；正文 &lt;external-db-secret&gt; &amp;lt;tag&amp;gt;'
        self.assertEqual(records._report_text(text), expected)
        self.assertEqual(records._report_text('unclosed `<tag>'), 'unclosed `&lt;tag&gt;')
        self.assertEqual(records._report_text({'value': '<tag>'}), '{"value": "&lt;tag&gt;"}')


class ReviewSummaryTests(fixtures.ProductBase):
    def test_summary_accounts_for_not_established_without_hiding_worklist_items(self):
        unit, path = self._product()
        payload = self._complete(path, unit)
        check = payload['checks'][0]
        eid = payload['evidence'][0]['id']
        for prerequisite in check['prerequisites']:
            prerequisite.update(state='met', evidence_ids=[eid])
        self.assertEqual(check['criteria'], [])
        check.update(applicability='applicable', verdict='not_established',
                     counterevidence_ids=[eid])
        audit.write_json(path, payload)
        result = fixtures.review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'PASS', result)
        counts = result['semantic_items']
        self.assertEqual(counts['checks_total'], len(payload['checks']))
        self.assertEqual(counts['verdicts']['not_established'], 1)
        self.assertEqual(counts['negative'], len(payload['checks']))
        self.assertEqual(sum(counts['verdicts'].values()), counts['checks_total'])
        worklist = Path(result['worklist']).read_text(encoding='utf-8')
        for row in payload['checks']:
            self.assertIn('## 检查 ' + row['id'], worklist)

if __name__ == '__main__':
    unittest.main()
