"""Counterexamples for the boundary between text mechanics and model judgments.

Target fixtures are read as material, never executed. Each structural rejection starts
from a valid product and checks that the specific defect was actually introduced.
"""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import unittest

from test_audit_scale import (
    ROOT, ProductBase, ScaleBase, audit, gate, knowledge, merge,
    propositions, recall, review_prepare, surface, units,
)


FIXTURES = ROOT / 'tests/fixtures/script_boundaries'


def write_payload(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class ProductBoundaryTests(ProductBase):
    def ready_product(self):
        unit, path = self._product()
        payload = self._complete(path, unit)
        before = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(before['mechanical'], 'PASS', before['problems'])
        return unit, path, payload

    def refuted_check(self, payload, suffix):
        check = deepcopy(payload['checks'][0])
        check['id'] = units.allocate('CHK', payload['unit_id'][2:],
                                     [row['id'] for row in payload['checks']])
        evidence_id = payload['evidence'][0]['id']
        for row in check['prerequisites']:
            row.update(state='met', evidence_ids=[evidence_id])
        for row in check['criteria']:
            row.update(state='not_met', evidence_ids=[evidence_id])
        check.update(status='complete', applicability='applicable',
                     verdict='not_established', evidence_ids=[evidence_id],
                     counterevidence_ids=[evidence_id],
                     explanation='The reviewed criterion does not hold in this scope: ' + suffix)
        payload['checks'].append(check)
        return check

    def test_an_optional_index_may_be_absent_during_prepare(self):
        unit, path, payload = self.ready_product()
        payload.pop('surface_dispositions')
        index = self.ws / 'surface' / (unit['id'] + '.json')
        self.assertTrue(index.is_file())
        index.unlink()
        unit['surface_hits'] = None
        self.assertIsNone(surface.load_hits(self.ws, unit['id']))
        write_payload(path, payload)
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'PASS', result['problems'])

    def test_raw_matches_do_not_need_individual_dispositions_to_prepare(self):
        unit, path, payload = self.ready_product()
        indexed = surface.load_hits(self.ws, unit['id'])
        self.assertTrue(indexed['spots'], 'counterexample needs actual raw matches')
        payload.pop('surface_dispositions')
        write_payload(path, payload)
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'PASS', result['problems'])

    def test_negations_and_quotes_reach_semantic_review(self):
        unit, path, payload = self.ready_product()
        for note in knowledge.read(FIXTURES / 'phrases.json'):
            with self.subTest(note=note):
                payload['method_notes'] = [note]
                write_payload(path, payload)
                result = review_prepare.prepare(self.ws, self.state, unit['id'])
                self.assertEqual(result['mechanical'], 'PASS', result['problems'])
                self.assertTrue(Path(result['worklist']).is_file())

    def test_internal_high_impact_candidate_reaches_review_without_a_chain(self):
        unit, path, payload = self.ready_product()
        self.assertEqual(payload['findings'][0]['exposure'], 'INT')
        self.assertFalse(self.state['chains'])
        for severity in ('high', 'critical'):
            with self.subTest(severity=severity):
                payload['findings'][0].update(
                    severity=severity,
                    severity_reason='Impact is assessed under the stated internal attacker model.')
                write_payload(path, payload)
                result = review_prepare.prepare(self.ws, self.state, unit['id'])
                self.assertEqual(result['mechanical'], 'PASS', result['problems'])

    def test_a_changed_fingerprint_still_blocks_prepare_without_writing_state(self):
        unit, path, payload = self.ready_product()
        evidence = payload['evidence'][0]
        current = self.state['materials'][evidence['material_id']]['sha256']
        evidence['sha256'] = '0' * 64
        self.assertNotEqual(evidence['sha256'], current)
        write_payload(path, payload)
        before = (self.ws / 'audit.json').read_bytes()
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'FAIL', result)
        self.assertTrue(any('fingerprint' in e for e in result['problems']), result)
        self.assertIsNone(result['worklist'])
        self.assertEqual((self.ws / 'audit.json').read_bytes(), before)

    def test_a_missing_evidence_reference_still_blocks_prepare(self):
        unit, path, payload = self.ready_product()
        missing = 'E-%s-missing' % unit['id'][2:]
        self.assertNotIn(missing, {e['id'] for e in payload['evidence']})
        payload['checks'][0]['evidence_ids'] = [missing]
        write_payload(path, payload)
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'FAIL', result)
        self.assertTrue(any(missing in e for e in result['problems']), result)

    def test_an_out_of_range_evidence_locator_still_blocks_prepare(self):
        unit, path, payload = self.ready_product()
        evidence = payload['evidence'][0]
        material = self.state['materials'][evidence['material_id']]
        length = len(audit.material_path(self.state, material).read_text().splitlines())
        evidence['locator'] = {'lines': [length + 1, length + 1]}
        self.assertGreater(evidence['locator']['lines'][1], length)
        write_payload(path, payload)
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'FAIL', result)
        self.assertTrue(any('line beyond end' in e for e in result['problems']), result)

    def test_unrelated_negative_checks_cannot_fill_a_false_positive_count(self):
        unit, path, payload = self.ready_product()
        self.refuted_check(payload, 'unrelated')
        payload['return_line'] = payload['return_line'].replace(
            '候选 1 (confirmed=0, fp=0, unclosed=1)',
            '候选 2 (confirmed=0, fp=1, unclosed=1)')
        self.assertNotIn('dismissed_candidates', payload)
        self.assertEqual(sum(c['verdict'] == 'not_established' for c in payload['checks']), 1)
        write_payload(path, payload)
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'FAIL', result)
        self.assertTrue(any('fp' in e or 'dismissed_candidates' in e
                            for e in result['problems']), result)

    def test_one_dismissed_candidate_can_have_multiple_refuting_checks(self):
        unit, path, payload = self.ready_product()
        first = self.refuted_check(payload, 'refutation-a')
        second = self.refuted_check(payload, 'refutation-b')
        candidate_id = 'F-%s-999' % unit['id'][2:]
        payload['dismissed_candidates'] = [{
            'id': candidate_id, 'check_ids': [first['id'], second['id']],
            'reason': 'Both checks concern this withdrawn candidate under the recorded scope.',
        }]
        payload['return_line'] = payload['return_line'].replace(
            '候选 1 (confirmed=0, fp=0, unclosed=1)',
            '候选 2 (confirmed=0, fp=1, unclosed=1)')
        write_payload(path, payload)
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'PASS', result['problems'])
        worklist = Path(result['worklist']).read_text(encoding='utf-8')
        self.assertIn(candidate_id, worklist)
        self.assertIn(first['id'], worklist)
        self.assertIn(second['id'], worklist)

    def test_a_dismissed_candidate_cannot_also_remain_a_finding(self):
        unit, path, payload = self.ready_product()
        check = self.refuted_check(payload, 'refutation')
        candidate_id = payload['findings'][0]['id']
        payload['dismissed_candidates'] = [{
            'id': candidate_id, 'check_ids': [check['id']], 'reason': 'Conflicting disposition.',
        }]
        write_payload(path, payload)
        result = review_prepare.prepare(self.ws, self.state, unit['id'])
        self.assertEqual(result['mechanical'], 'FAIL', result)
        self.assertTrue(any(candidate_id in e for e in result['problems']), result)


class PlanningBoundaryTests(ScaleBase):
    target_subdir = 'tests/fixtures/surface'

    def test_phase_one_does_not_require_an_exploratory_scan(self):
        self.plan()
        self.resolve_all()
        self.assertTrue(all(u['surface_hits'] is None for u in self.state['units']))
        result = units.freeze(self.ws, self.state, 1)
        self.assertIn('phase1_frozen', result)

    def test_absent_or_open_raw_matches_do_not_fail_a_gate(self):
        self.plan()
        self.resolve_all()
        for indexed in (False, True):
            with self.subTest(indexed=indexed):
                if indexed:
                    surface.build(self.ws, self.state)
                    self.reload()
                    self.assertGreater(sum(u['surface_hits'] for u in self.state['units']), 0)
                rows = {r['id']: r for r in gate.evaluate(self.ws, self.state)}
                # G3 may be retained as an informational compatibility row or removed.
                self.assertNotEqual(rows.get('G3', {}).get('status'), 'fail', rows.get('G3'))

    def test_duplicate_material_ownership_still_blocks_freezing(self):
        self.plan()
        self.resolve_all()
        self.assertEqual(units.partition_errors(self.state), [])
        duplicated = deepcopy(self.state['units'][0])
        duplicated['id'] = 'U-SH999'
        self.state['units'].append(duplicated)
        material_id = duplicated['material_ids'][0]
        self.assertEqual(sum(material_id in u['material_ids'] for u in self.state['units']), 2)
        self.assertTrue(any('more than one unit' in e for e in units.partition_errors(self.state)))
        with self.assertRaisesRegex(ValueError, 'Partition'):
            units.freeze(self.ws, self.state, 1)

    def test_formally_created_checks_still_require_a_disposition(self):
        self.plan()
        self.resolve_all()
        unit = self.state['units'][0]
        path = self.product(unit)
        audit.seed_partial(self.ws, self.state, path)
        merge.merge_unit(self.ws, self.state, unit['id'])
        self.reload()
        self.assertTrue(self.state['checks'])
        self.assertTrue(all(c['status'] == 'not_started' for c in self.state['checks']))
        rows = {r['id']: r for r in gate.evaluate(self.ws, self.state)}
        self.assertEqual(rows['G7']['status'], 'fail', rows['G7'])

    def cross_scope(self, needed=()):
        self.plan()
        self.resolve_all()
        self.freeze2()
        self.reload()
        decisions = self.state.setdefault('queue', {}).setdefault('cross_scope', {})
        for kind in ('joint', 'chain', 'goal', 'xartifact'):
            choice = 'needed' if kind in needed else 'not_needed'
            reason = 'Model reviewed the target boundary and recorded this explicit decision.'
            decisions[kind] = {'decision': choice, 'reason': reason}
            for row in self.state['pending_decisions']:
                if row['kind'] == 'cross_scope' and row['subject'] == kind:
                    row.update(resolution=choice, reason=reason)
        self.state['queue']['phase3_critic'] = '第 1 轮，补入 0 项；已逐类评估跨域需要。'
        audit.save(self.ws, self.state)

    def test_explicitly_unneeded_cross_work_allows_a_zero_unit_phase_three(self):
        self.cross_scope()
        self.assertFalse(self.state['checks'])
        self.assertFalse([u for u in self.state['units'] if u['kind'] == 'cross'])
        result = units.freeze(self.ws, self.state, 3)
        self.assertEqual(result['phase3_rows_frozen'], 0)

    def test_explicitly_needed_cross_work_cannot_disappear(self):
        self.cross_scope(needed=('goal',))
        self.assertEqual(self.state['queue']['cross_scope']['goal']['decision'], 'needed')
        before = (self.ws / 'audit.json').read_bytes()
        with self.assertRaises(ValueError) as caught:
            units.freeze(self.ws, self.state, 3)
        self.assertIn('goal', str(caught.exception))
        self.assertEqual((self.ws / 'audit.json').read_bytes(), before)

    def test_confirmed_does_not_automatically_settle_the_same_instance_dispute(self):
        data, _, baseline_id = knowledge.load_bundle()
        mode = next(iter(data['failure_modes'].values()))
        self.state['instances'] = [{'id': 'INST-SAME', 'unit_id': 'U-SH01'}]
        common = {'instance_ids': ['INST-SAME'], 'failure_mode_id': mode['id'],
                  'baseline_id': baseline_id, 'status': 'complete', 'scope': ['code'],
                  'applicability': 'applicable'}
        self.state['checks'] = [dict(common, id='CHK-A', verdict='confirmed'),
                                dict(common, id='CHK-B', verdict='not_established')]
        self.state['reconciliations'] = []
        survey = propositions.survey(self.state)
        self.assertTrue(survey[0]['divergent'])
        result = propositions.unaccounted(self.ws, self.state)
        self.assertFalse(result.get('settled'), result)
        self.assertTrue(result.get('differences'), result)
        self.assertFalse(result.get('missing'), 'Unclaimed differences are candidates for model review.')


class NoiseBoundaryTests(ScaleBase):
    target_subdir = 'tests/fixtures/script_boundaries/noise.md'

    def test_121_documentation_mentions_do_not_force_a_split_or_disposition(self):
        content = (FIXTURES / 'noise.md').read_text(encoding='utf-8')
        for i in range(120):
            (self.target / ('mention_%03d.md' % i)).write_text(content, encoding='utf-8')
        audit.refresh(self.ws, self.state)
        self.reload()
        self.plan()
        self.resolve_all()
        before = [(u['id'], list(u['material_ids'])) for u in self.state['units']]
        surface.build(self.ws, self.state)
        self.reload()
        self.assertGreaterEqual(sum(u['surface_hits'] for u in self.state['units']), 121)
        self.assertEqual([(u['id'], u['material_ids']) for u in self.state['units']], before)
        oversized = [d for d in self.state['pending_decisions'] if d['kind'] == 'oversized_unit']
        self.assertFalse(oversized, oversized)
        units.freeze(self.ws, self.state, 1)

    def test_pack_cannot_merge_unrelated_directories_without_an_explicit_plan(self):
        (self.target / 'noise.md').unlink()
        content = (FIXTURES / 'pure.py.txt').read_text(encoding='utf-8')
        for name in ('billing', 'calendar', 'telemetry'):
            directory = self.target / name
            directory.mkdir()
            (directory / 'logic.py').write_text(content * 1400, encoding='utf-8')
        audit.refresh(self.ws, self.state)
        self.reload()
        self.plan()
        surface.build(self.ws, self.state)
        self.reload()
        self.assertEqual(len(self.state['units']), 3)
        self.assertTrue(all(u['surface_hits'] == 0 for u in self.state['units']))
        before_state = deepcopy(self.state)
        before_file = (self.ws / 'audit.json').read_bytes()
        with self.assertRaisesRegex(ValueError, '--apply'):
            units.pack_units(self.ws, self.state)
        self.assertEqual(self.state, before_state)
        self.assertEqual((self.ws / 'audit.json').read_bytes(), before_file)


class RecallBoundaryTests(ScaleBase):
    target_subdir = 'tests/fixtures/script_boundaries/call_shapes.py'

    def pattern(self, symbol='launch_job', callers=1):
        path = next(iter(self.state['materials'].values()))['path']
        return {'target': 'fixture', 'baseline_id': self.state['framework']['baseline_id'],
                'patterns': [{
                    'id': 'TP-BOUNDARY', 'regex': symbol + r'\s*\(', 'kind': 'sink',
                    'object_ids': ['A4.6'], 'symbol': symbol,
                    'defined_at': {'path': path, 'lines': [1, 2]},
                    'gates': [{'path': path, 'line': 2, 'refusal': 'Model-reviewed control point.'}],
                    'callers': callers, 'rationale': 'The model identified the relevant control point.',
                }]}

    def register(self, payload):
        path = self.ws / 'boundary-recall.json'
        write_payload(path, payload)
        result = recall.apply_patterns(self.ws, self.state, path)
        self.reload()
        return result

    def test_comments_and_strings_cannot_overwrite_the_models_call_count(self):
        payload = self.pattern()
        # The fixture contains one model-confirmed call and two other textual matches.
        self.assertGreater(recall.count_callers(self.ws, self.state, ['launch_job'])['launch_job'], 1)
        self.register(payload)
        self.assertEqual(self.state['target_patterns'][0]['callers'], 1)

    def test_a_single_authorization_call_is_not_rejected_as_unimportant(self):
        payload = self.pattern('authorize_once', callers=1)
        self.assertNotIn('callers_note', payload['patterns'][0])
        result = self.register(payload)
        self.assertEqual(result['registered'], 1)
        self.assertEqual(self.state['target_patterns'][0]['callers'], 1)

    def test_same_named_methods_do_not_replace_model_confirmed_call_sites(self):
        payload = self.pattern('execute', callers=1)
        source = (self.target / 'call_shapes.py').read_text(encoding='utf-8').splitlines()
        driver_line = next(i for i, line in enumerate(source, 1) if line.startswith('driver.execute('))
        path = payload['patterns'][0]['defined_at']['path']
        call_sites = [{'path': path, 'line': driver_line}]
        payload['patterns'][0]['call_sites'] = call_sites
        self.assertGreater(recall.count_callers(self.ws, self.state, ['execute'])['execute'], 1)
        self.register(payload)
        row = self.state['target_patterns'][0]
        self.assertEqual(row['callers'], 1)
        self.assertEqual(row['call_sites'], call_sites)

    def test_a_word_shaped_pattern_is_not_reclassified_by_spelling(self):
        payload = self.pattern('execute', callers=1)
        payload['patterns'][0]['regex'] = 'execute'
        self.register(payload)
        self.assertEqual(self.state['target_patterns'][0]['kind'], 'sink')

    def test_recall_can_finish_with_zero_patterns(self):
        payload = {'target': 'fixture', 'baseline_id': self.state['framework']['baseline_id'],
                   'patterns': []}
        result = self.register(payload)
        self.assertEqual(result['registered'], 0)
        self.assertEqual(self.state['target_patterns'], [])

    def test_main_entry_text_is_searchable(self):
        matched = recall.search_call_sites(self.ws, self.state, ['main_entry'])['main_entry']
        source = (self.target / 'call_shapes.py').read_text(encoding='utf-8').splitlines()
        entry_lines = {i for i, line in enumerate(source, 1) if line.startswith('    main_entry(')}
        self.assertEqual(len(entry_lines), 2)
        self.assertTrue(entry_lines <= {row['line'] for row in matched['matches']}, matched)
        self.assertEqual(matched['method'], 'text_regex')

    def test_production_text_after_an_inline_test_module_is_searchable(self):
        shutil.copyfile(FIXTURES / 'module_shapes.rs', self.target / 'module_shapes.rs')
        audit.refresh(self.ws, self.state)
        self.reload()
        matched = recall.search_call_sites(self.ws, self.state, ['after_module'])['after_module']
        source = (self.target / 'module_shapes.rs').read_text(encoding='utf-8').splitlines()
        production_line = next(i for i, line in enumerate(source, 1)
                               if '    after_module(' in line)
        self.assertIn(production_line, {row['line'] for row in matched['matches']})

    def test_one_pattern_preserves_every_model_selected_object_tag(self):
        payload = self.pattern(callers=3)
        payload['patterns'][0]['object_ids'] = ['A2.5', 'A4.6']
        self.register(payload)
        self.plan()
        surface.build(self.ws, self.state)
        self.reload()
        hits = [hit for unit in self.state['units']
                for hit in surface.load_hits(self.ws, unit['id'])['hits']
                if 'launch_job' in hit.get('symbol', '')]
        self.assertTrue(hits, 'the registered target pattern must actually match')
        objects = {oid for hit in hits for oid in hit['object_ids']}
        self.assertTrue({'A2.5', 'A4.6'} <= objects, objects)

    def test_a_pattern_with_an_unknown_material_reference_is_still_refused(self):
        payload = self.pattern(callers=3)
        missing = 'missing/control.py'
        payload['patterns'][0]['defined_at']['path'] = missing
        self.assertNotIn(missing, {r['path'] for r in self.state['materials'].values()})
        before = (self.ws / 'audit.json').read_bytes()
        with self.assertRaises(ValueError) as caught:
            self.register(payload)
        self.assertIn(missing, str(caught.exception))
        self.assertEqual((self.ws / 'audit.json').read_bytes(), before)




class MigrationBoundaryTests(ProductBase):
    def test_migration_preserves_old_facts_and_marks_unverified_contract(self):
        import hashlib
        unit, path = self._product()
        payload = self._complete(path, unit)
        merge.merge_unit(self.ws, self.state, unit['id'])
        self.reload()
        # Simulate an unchanged original product produced under the older contract.
        payload['schema_version'] = '1.5'
        payload['return_line'] = '候选 2 (confirmed=0, fp=1, unclosed=1)'
        payload.pop('dismissed_candidates', None)
        write_payload(path, payload)
        owner = next(u for u in self.state['units'] if u['id'] == unit['id'])
        owner['partial_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.state['schema_version'] = '1.5'
        self.state.pop('dismissed_candidates', None)
        self.state['unknown_legacy_field'] = {'keep': ['uninterpreted fact']}
        self.state['target_patterns'] = [{'id':'legacy','callers':3,'callers_claimed':17}]
        before = deepcopy(self.state)
        audit.save(self.ws, self.state)
        audit.refresh(self.ws, self.state)
        self.assertEqual(self.state['schema_version'], '1.6')
        for key in ('checks','findings','evidence','unknown_legacy_field','target_patterns'):
            self.assertEqual(self.state[key], before[key], key)
        self.assertEqual(self.state['dismissed_candidates'], [])
        self.assertEqual(self.state['queue']['phase1_frozen'], before['queue']['phase1_frozen'])
        self.assertEqual(self.state['queue']['legacy_freeze_contract'], '1.5')
        owner = next(u for u in self.state['units'] if u['id'] == unit['id'])
        self.assertTrue(merge.legacy_product(self.ws, owner, payload))
        self.assertEqual(merge.validate_partial(self.state, owner, payload, legacy=True), [])
        # Merely writing an old schema or reusing a legacy unit cannot bypass new rules.
        payload['method_notes'] = ['changed after migration']
        payload['schema_version'] = audit.SCHEMA_VERSION
        write_payload(path, payload)
        self.assertFalse(merge.legacy_product(self.ws, owner, payload))
        self.assertTrue(any('dismissed_candidates' in e for e in
                            merge.validate_partial(self.state, owner, payload)))

    def test_candidate_association_is_counted_by_identity_and_merge_is_idempotent(self):
        unit, path = self._product()
        payload = self._complete(path, unit)
        check = deepcopy(payload['checks'][0])
        check['id'] = 'CHK-%s-0901' % unit['id'][2:]
        check['verdict'] = 'not_established'
        check['applicability'] = 'applicable'
        for row in check['prerequisites']: row.update(state='met',evidence_ids=check['evidence_ids'])
        for row in check['criteria']: row.update(state='not_met',evidence_ids=check['evidence_ids'])
        check['counterevidence_ids'] = list(check['evidence_ids'])
        payload['checks'].append(check)
        candidate_id = 'F-%s-0901' % unit['id'][2:]
        payload['dismissed_candidates'] = [{'id':candidate_id,'reason':'specific candidate refuted',
                                            'check_ids':[check['id']]}]
        payload['return_line'] = '候选 2 (confirmed=0, fp=1, unclosed=1)'
        write_payload(path,payload)
        self.assertEqual(review_prepare.prepare(self.ws,self.state,unit['id'])['mechanical'],'PASS')
        merge.merge_unit(self.ws,self.state,unit['id'])
        merge.merge_unit(self.ws,self.state,unit['id'])
        self.assertEqual([c['id'] for c in self.state['dismissed_candidates']],[candidate_id])


class ExplicitPlanningBoundaryTests(ScaleBase):
    target_subdir = 'tests/fixtures/surface'

    def test_directory_candidates_need_model_adoption(self):
        self.plan()
        self.resolve_all()
        self.state['queue']['partition_confirmed'] = False
        self.state['pending_decisions'] = units.pending_decisions(self.ws,self.state)
        with self.assertRaises(ValueError): units.freeze(self.ws,self.state,1)
        from decide import decide
        decide(self.ws,self.state,'partition:queue','accept','model checked dependencies and responsibilities')
        units.freeze(self.ws,self.state,1)

    def test_file_split_does_not_inherit_parent_semantic_decisions(self):
        self.plan()
        self.resolve_all()
        parent = next(u for u in self.state['units'] if u['file_count'] > 1)
        original = set(parent['material_ids'])
        result = units.split_unit(self.ws,self.state,parent['id'],by='file')
        children = [u for u in self.state['units'] if u['id'] in result['into']]
        self.assertEqual(len(children),len(original))
        self.assertEqual({m for u in children for m in u['material_ids']},original)
        for child in children:
            self.assertEqual(child['object_ids'],[])
            self.assertEqual(child['exposure'],'unknown')
            self.assertIsNone(child['depth'])

    def test_unmerged_product_prevents_replanning_away_its_boundary(self):
        self.plan()
        self.resolve_all()
        unit=self.state['units'][0]
        self.product(unit)
        with self.assertRaisesRegex(ValueError,'Existing work'):
            units.plan_census(self.ws,self.state,rebuild=True)
        payload=units.plan_template(self.state);payload['reason']='attempted replacement'
        payload['units'][0]['id']='U-SH999'
        before=deepcopy(self.state);disk=(self.ws/'audit.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'existing work'):
            units.apply_plan(self.ws,self.state,payload)
        self.assertEqual(self.state,before)
        self.assertEqual((self.ws/'audit.json').read_bytes(),disk)


if __name__ == '__main__':
    unittest.main()
