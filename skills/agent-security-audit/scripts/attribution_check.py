"""Behavioral checks for attribution state, concurrent proposals and report integration."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit
import attribution as a
import rootcause as rc
import rootcause_run as runs
from review import record_review, withdraw_review


def decision(state, fid, kind='defect', **fields):
    f = next(f for f in state['findings'] if f['id'] == fid)
    row = {'finding_id': fid, 'kind': kind, 'by': 'test-attribution', 'reason': '已比较具体控制实现与证据'}
    if kind == 'defect':
        row['comparison'] = {'by': 'test-attribution', 'scope': '引用材料中的控制位置及已知入口',
                             'reason': '夹具明确规定的同源或独立控制关系', 'conclusion': 'standalone',
                             'finding_ids': sorted({fid} | {other for c in rc.candidates(state) if fid in c['finding_ids'] for other in c['finding_ids']}), 'evidence_ids': f['evidence_ids']}
    row.update(fields)
    return row


def approve(workspace, state, rows=None, causes=None, **extra):
    rows = rows if rows is not None else [decision(state, f['id']) for f in state['findings'] if f['status'] == 'current']
    body = {'base_sha256': rc.digest(state), 'by': 'test-attribution',
            'finding_dispositions': rows, 'root_causes': causes or [], **extra}
    return rc.apply_adjudication(workspace, state, body), body


def proposal(run, task, attempt, kind='defect'):
    return {'run_id': run, 'task_id': task['id'], 'attempt': attempt['n'],
            'input_digest': task['input_digest'], 'reviewer': 'test-attribution',
            'assessments': [{'finding_id': fid, 'proposed_kind': kind, 'reason': '逐条核对的临时建议'}
                            for fid in task['finding_ids']],
            'group_proposals': [], 'comparisons': [], 'cross_file_leads': [],
            'fact_corrections': [], 'open_items': [], 'read_dependencies': [], 'resolutions': []}


class AttributionTests(unittest.TestCase):
    def setUp(self):
        from self_check import root_cause_fixture
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws, self.state = root_cause_fixture(self.tmp.name)
        self.ids = [f['id'] for f in self.state['findings']]

    def view(self): return a.build_vulnerability_view(self.state)

    def relate(self):
        f = self.state['findings'][0]
        f['related_findings'] = [{'finding_id': self.ids[1], 'relation': 'possible_same_defect',
                                  'reason': '夹具明确登记的待比较共享控制', 'evidence_ids': f['evidence_ids']}]
        from report_fixtures import _review
        _review(self.ws, self.state)

    def test_legacy_no_implicit_singletons(self):
        view = self.view()
        self.assertEqual(0, len(view['vulnerabilities']))
        self.assertEqual(set(self.ids), {r['finding_id'] for r in view['pending']})
        rows = [dict(decision(self.state, fid), comparison=None) for fid in self.ids]
        with self.assertRaises(ValueError): approve(self.ws, self.state, rows)
        self.assertFalse(self.state.get('finding_dispositions'))

    def test_singletons_need_comparison_and_preserve_fact_review(self):
        before = copy.deepcopy(self.state['reviews'])
        approve(self.ws, self.state)
        self.assertEqual(4, len(self.view()['vulnerabilities']))
        self.assertEqual(before, self.state['reviews'])
        self.assertFalse(self.view()['pending'])

    def test_group_counts_once_and_preserves_all_paths(self):
        from self_check import MERGE
        cause = dict(copy.deepcopy(MERGE), evidence_ids=self.state['findings'][0]['evidence_ids'])
        rows = [decision(self.state, fid) for fid in self.ids]
        for row in rows[:2]: row['comparison']['conclusion'] = 'grouped'
        approve(self.ws, self.state, rows, [cause])
        view = self.view()
        self.assertEqual(3, len(view['vulnerabilities']))
        group = next(v for v in view['vulnerabilities'] if v['id'] == 'RC-01')
        self.assertEqual(self.ids[:2], group['finding_ids'])
        self.assertEqual(2, len(self.state['root_causes'][0]['member_paths']))
        from records import validate
        self.assertEqual([], validate(self.ws, self.state))

    def test_new_fact_and_review_stale_attribution_only(self):
        # This independent local finding has no shared material, copy or FM signal.
        f4 = self.state['findings'][3]
        eid = f4['evidence_ids'][0]
        ev = next(e for e in self.state['evidence'] if e['id'] == eid)
        material = dict(self.state['materials'][ev['material_id']], id='independent', sha256='f' * 64, path='independent.ts')
        self.state['materials']['independent'] = material
        ev.update(material_id='independent', sha256=material['sha256'])
        record_review(self.ws,self.state,f4['id'],{'reviewer':'test-facts','decision':'retain','rationale':'独立材料','counterevidence_analysis':'无共享实现','evidence_ids':f4['evidence_ids'],'counterevidence_ids':[]})
        approve(self.ws, self.state)
        f = self.state['findings'][0]
        f['impact'] += ' 新的受影响资产'
        record_review(self.ws, self.state, f['id'], {'reviewer': 'test-facts', 'decision': 'retain',
                      'rationale': '已核对新事实', 'counterevidence_analysis': '保留具体前提',
                      'evidence_ids': f['evidence_ids'], 'counterevidence_ids': []})
        pending = {r['finding_id'] for r in self.view()['pending']}
        self.assertIn(f['id'], pending)
        self.assertNotIn(self.ids[3], pending)
        self.assertEqual('current', f['status'])

    def test_supplement_direct_target_and_target_withdrawal(self):
        rows = [decision(self.state, fid) for fid in self.ids]
        rows[0] = decision(self.state, self.ids[0], 'supplement', target_finding_id=self.ids[1])
        approve(self.ws, self.state, rows)
        self.assertEqual(3, len(self.view()['vulnerabilities']))
        self.assertEqual(self.view()['finding_map'][self.ids[1]]['vulnerability_id'],
                         self.view()['finding_map'][self.ids[0]]['vulnerability_id'])
        withdraw_review(self.ws, self.state, self.ids[1], '重新核对目标')
        self.assertIn(self.ids[0], {r['finding_id'] for r in self.view()['pending']})
        self.assertEqual('needs_review', self.state['findings'][1]['status'])

    def test_supplement_chain_is_rejected_atomically(self):
        rows = [decision(self.state, fid) for fid in self.ids]
        rows[0] = decision(self.state, self.ids[0], 'supplement', target_finding_id=self.ids[1])
        rows[1] = decision(self.state, self.ids[1], 'supplement', target_finding_id=self.ids[2])
        before = (self.ws/'audit.json').read_bytes()
        with self.assertRaises(ValueError): approve(self.ws, self.state, rows)
        self.assertEqual(before, (self.ws/'audit.json').read_bytes())

    def test_chain_and_summary_have_destinations_and_do_not_add_counts(self):
        self.state['chains'] = [{'id': 'CHAIN-AA01-01', 'title': '已有能力组合', 'entry_exposure': 'ADJ',
                                 'steps': [{'finding_id': self.ids[2]}]}]
        self.state['report_todos'] = [{'id': 'TODO-AA01', 'instruction': '呈现组合与治理边界', 'status': 'open'}]
        rows = [decision(self.state, fid) for fid in self.ids]
        rows[0] = decision(self.state, self.ids[0], 'chain', finding_ids=[self.ids[2]], chain_ids=['CHAIN-AA01-01'])
        rows[1] = decision(self.state, self.ids[1], 'summary', finding_ids=[self.ids[2]], todo_ids=['TODO-AA01'])
        approve(self.ws, self.state, rows)
        self.assertEqual(2, len(self.view()['vulnerabilities']))
        self.assertEqual(['CHAIN-AA01-01'], self.view()['finding_map'][self.ids[0]]['chain_ids'])
        self.assertNotIn('path', self.view()['finding_map'][self.ids[0]])
        self.assertTrue(self.view()['statistics']['attribution_complete'])
        # A finding also used in a chain remains an independent defect.
        self.assertEqual('defect', self.view()['finding_map'][self.ids[2]]['kind'])
        self.state['report_todos'][0]['status'] = 'applied'
        self.assertTrue(self.view()['statistics']['attribution_complete'])

    def test_bad_chain_missing_chain_record_fails(self):
        rows = [decision(self.state, fid) for fid in self.ids]
        rows[0] = decision(self.state, self.ids[0], 'chain', finding_ids=[self.ids[1]])
        with self.assertRaises(ValueError): approve(self.ws, self.state, rows)

    def test_superseded_never_resurrects(self):
        f = self.state['findings'][0]
        record_review(self.ws, self.state, f['id'], {'reviewer':'test-facts','decision':'reject',
                      'rationale':'由具体记录替代，不认定原事实全为误报','counterevidence_analysis':'保留替代目标',
                      'evidence_ids':f['evidence_ids'],'counterevidence_ids':[]})
        rows = [decision(self.state, fid) for fid in self.ids[1:]]
        rows.append(decision(self.state, self.ids[0], 'superseded', finding_ids=[self.ids[1]]))
        approve(self.ws, self.state, rows)
        withdraw_review(self.ws, self.state, self.ids[1], '需要重新核对')
        self.assertEqual('withdrawn', f['status'])
        self.assertTrue(self.view()['historical_issues'])
        self.assertEqual('withdrawn', f['status'])

    def test_chain_updates_bind_previous_source_and_keep_history(self):
        chain = {'id': 'CHAIN-AA01-UPDATE', 'title': '已有静态路径', 'entry_exposure': 'ADJ',
                 'steps': [{'finding_id': self.ids[0], 'description': '在已记录身份前提下进入读取器。'}]}
        approve(self.ws, self.state, chains=[chain])
        original = copy.deepcopy(next(c for c in self.state['chains'] if c['id'] == chain['id']))
        changed = dict(original, title='已收窄前提的静态路径')
        reviews = copy.deepcopy(self.state['reviews'])
        before = (self.ws / 'audit.json').read_bytes()
        invalid = {'base_sha256': rc.digest(self.state), 'by': 'chain-reviewer',
                   'chain_updates': [{'previous_sha256': '0' * 64, 'chain': changed}]}
        with self.assertRaisesRegex(ValueError, '链订正来源'):
            rc.apply_adjudication(self.ws, self.state, invalid)
        self.assertEqual(before, (self.ws / 'audit.json').read_bytes())
        invalid['chain_updates'][0]['previous_sha256'] = a.fingerprint(original)
        invalid['chain_updates'][0]['chain'] = dict(changed, steps=[None])
        with self.assertRaisesRegex(ValueError, '每跳必须为对象'):
            rc.apply_adjudication(self.ws, self.state, invalid)
        self.assertEqual(before, (self.ws / 'audit.json').read_bytes())
        payload = {'base_sha256': rc.digest(self.state), 'by': 'chain-reviewer',
                   'chain_updates': [{'previous_sha256': a.fingerprint(original), 'chain': changed}]}
        result = rc.apply_adjudication(self.ws, self.state, payload)
        self.assertEqual(1, result['updated_chains'])
        self.assertEqual(reviews, self.state['reviews'])
        self.assertEqual(1, sum(c['id'] == chain['id'] for c in self.state['chains']))
        self.assertTrue(any(h.get('record') == original for h in self.state['attribution_history']))
        self.assertTrue(rc.apply_adjudication(self.ws, self.state, payload)['replayed'])

    def test_pending_does_not_hide_high_findings(self):
        from reporting import export_package, high_findings
        rows = [decision(self.state, fid, 'pending') for fid in self.ids]
        approve(self.ws, self.state, rows)
        index = export_package(self.ws, self.state)
        self.assertEqual([], index['tasks'])
        self.assertEqual([f['id'] for f in high_findings(self.state)], [f['id'] for f in index['high_findings']])
        self.assertEqual(set(self.ids), set(index['finding_map']))
        self.assertEqual(4, index['statistics']['attribution']['pending_findings'])

    def test_empty_groups_and_member_removal_are_not_singletons(self):
        from self_check import MERGE
        rows = [decision(self.state, fid) for fid in self.ids]
        for row in rows[:2]: row['comparison']['conclusion']='grouped'
        approve(self.ws, self.state, rows, [dict(copy.deepcopy(MERGE), evidence_ids=self.state['findings'][0]['evidence_ids'])])
        withdraw_review(self.ws, self.state, self.ids[0], '成员需复核')
        self.assertNotIn('RC-01', {v['id'] for v in self.view()['vulnerabilities']})
        self.assertIn(self.ids[1], {r['finding_id'] for r in self.view()['pending']})

    def test_idempotency_and_failed_write(self):
        before = copy.deepcopy(self.state)
        with patch('audit.write_json', side_effect=OSError('write fault')):
            with self.assertRaises(OSError): approve(self.ws, self.state)
        self.assertEqual(before, self.state)
        result, payload = approve(self.ws, self.state)
        disk = (self.ws/'audit.json').read_bytes()
        self.assertTrue(rc.apply_adjudication(self.ws, self.state, payload)['replayed'])
        self.assertEqual(disk, (self.ws/'audit.json').read_bytes())
        self.state['findings'][0]['impact'] += '变化'
        with self.assertRaises(ValueError): rc.apply_adjudication(self.ws, self.state, payload)

    def test_file_groups_and_complete_id_recall(self):
        self.state['findings'][0]['mechanism'] += '补充 F-CC01-02。'
        groups = rc.file_groups(self.state)
        self.assertEqual(set(self.ids), {fid for g in groups for fid in g['finding_ids']})
        leads = rc.file_candidates(self.state)
        self.assertTrue(any(r['key'].startswith('link:') and self.ids[0] in r['finding_ids'] and self.ids[3] in r['finding_ids'] for r in leads))
        self.assertEqual(0, len(self.view()['vulnerabilities']))

    def test_new_fact_fields_and_review_fingerprint(self):
        from review import subject_digest
        f = self.state['findings'][0]
        old = subject_digest(self.state, f)
        f['failure_points'] = [{'evidence_ids':f['evidence_ids'][:1], 'expected_control':'绑定身份', 'observed_failure':'采信自报身份'}]
        self.assertNotEqual(old, subject_digest(self.state, f))
        self.assertEqual([], a.finding_extension_errors(self.state))
        f['related_findings'] = [{'finding_id':'F-UNKNOWN-01','relation':'overlaps','reason':'待核对','evidence_ids':f['evidence_ids']}]
        self.assertTrue(a.finding_extension_errors(self.state))

    def launch(self, run, tid):
        return runs.dispatch(self.ws, self.state, run, tid, {'limit':8,'active_agent_ids':[]})

    def finish(self, run, tid, change=None):
        root,m,_=runs.load(self.ws,run);t=m['tasks'][tid];attempt=t['attempts'][-1]
        data=proposal(run,t,attempt)
        if change: change(data)
        audit.write_json(root/attempt['result_path'], data)
        return runs.collect(self.ws,self.state,run,[{'task_id':tid,'attempt':attempt['n'],'event':'completed','result_path':str(root/attempt['result_path'])}])

    def test_parallel_overlapping_jobs_and_capacity(self):
        self.relate()
        plan={'tasks':[{'finding_ids':self.ids[:3],'reason':'共享入口'}, {'finding_ids':self.ids[2:],'reason':'同文件不同控制'}]}
        before=(self.ws/'audit.json').read_bytes()
        run=runs.prepare(self.ws,self.state,task_plan=plan)['run_id']
        with self.assertRaises(ValueError):
            runs.dispatch(self.ws,self.state,run,'T0001',{'limit':1,'active_agent_ids':['other-role']})
        one=self.launch(run,'T0001'); two=self.launch(run,'T0002')
        self.assertNotEqual(one['result_path'],two['result_path'])
        self.assertEqual('dispatched',one['state'])
        self.assertIn('rootcause_reviewer.md',one['prompt'])
        self.assertNotIn('/roles/reviewer.md',one['prompt'])
        with self.assertRaises(ValueError): self.launch(run,'T0001')
        self.finish(run,'T0002');summary=self.finish(run,'T0001')
        self.assertFalse(summary['missing_analysis_tasks'])
        self.assertEqual(before,(self.ws/'audit.json').read_bytes())
        self.assertTrue(any(i['kind']=='candidate_comparison' for i in summary['issues']))

    def test_started_failure_and_retry_files(self):
        run=runs.prepare(self.ws,self.state)['run_id']; self.launch(run,'T0001')
        runs.collect(self.ws,self.state,run,[{'task_id':'T0001','attempt':1,'event':'started','agent_id':'AGENT-01'}])
        with self.assertRaises(ValueError):
            runs.collect(self.ws,self.state,run,[{'task_id':'T0001','attempt':1,'event':'failed','reason':'异常'}])
        runs.collect(self.ws,self.state,run,[{'task_id':'T0001','attempt':1,'event':'failed','reason':'已停止','stopped':True}])
        second=self.launch(run,'T0001')
        self.assertEqual(2,second['attempt'])
        self.assertTrue(second['result_path'].endswith('result-2.json'))

    def test_conflicting_group_proposals_do_not_union(self):
        plan={'tasks':[{'finding_ids':self.ids[:2],'reason':'比较一'}, {'finding_ids':self.ids[1:],'reason':'比较二'}]}
        run=runs.prepare(self.ws,self.state,task_plan=plan)['run_id']
        for tid,ids in [('T0001',self.ids[:2]),('T0002',self.ids[1:3])]:
            self.launch(run,tid)
            summary=self.finish(run,tid,lambda data,ids=ids:data['group_proposals'].append({'finding_ids':ids,'reason':'需进一步核对的共同失效'}))
        self.assertTrue(any(i['kind']=='overlapping_groups' for i in summary['issues']))
        self.assertEqual([], self.state['root_causes'])
        self.assertEqual(0,len(self.view()['vulnerabilities']))

    def test_read_only_status_and_stale_inputs(self):
        run=runs.prepare(self.ws,self.state)['run_id']; self.launch(run,'T0001');self.finish(run,'T0001')
        root,m,_=runs.load(self.ws,run);before=(root/'manifest.json').read_bytes()
        self.state['findings'][0]['title'] += '改变'
        result=runs.status(self.ws,self.state,run)
        self.assertTrue(any(t['effective_state']=='stale' for t in result['tasks']))
        self.assertEqual(before,(root/'manifest.json').read_bytes())

    def test_bad_result_cannot_be_collected(self):
        run=runs.prepare(self.ws,self.state)['run_id'];self.launch(run,'T0001')
        root,m,_=runs.load(self.ws,run);t=m['tasks']['T0001'];attempt=t['attempts'][-1]
        data=proposal(run,t,attempt);data['assessments'].pop()
        audit.write_json(root/attempt['result_path'],data)
        before=(root/'manifest.json').read_bytes()
        with self.assertRaises(ValueError):runs.collect(self.ws,self.state,run,[{'task_id':'T0001','attempt':1,'event':'completed'}])
        self.assertEqual(before,(root/'manifest.json').read_bytes())

    def test_identical_input_reuses_original_result(self):
        run=runs.prepare(self.ws,self.state)['run_id'];self.launch(run,'T0001');self.finish(run,'T0001')
        other=runs.prepare(self.ws,self.state)['run_id']
        root,m,_=runs.load(self.ws,other)
        task=m['tasks']['T0001']
        self.assertEqual('returned',task['state'])
        result=json.loads((root/task['attempts'][0]['result_path']).read_text())
        self.assertEqual(run,result['run_id'])
        runs.validate_result(self.state,task,result,task['attempts'][0],other)

    def test_sarif_removed_and_old_snapshot_preserved(self):
        self.assertNotIn('sarif',audit.build_parser()._actions[1].choices)
        self.assertFalse((Path(audit.__file__).parent/'sarif.py').exists())
        historical=self.ws/'report.sarif.json';historical.write_text('{"historical":true}\n')
        before=historical.read_bytes()
        snap=audit.archive(self.ws,self.state,'test')
        self.assertEqual(before,historical.read_bytes())
        self.assertEqual(before,(snap/'workspace/report.sarif.json').read_bytes())
        historical.unlink()
        other=audit.archive(self.ws,self.state,'test-empty')
        self.assertFalse((other/'workspace/report.sarif.json').exists())

    def test_full_run_submission_and_receipt_recovery(self):
        run=runs.prepare(self.ws,self.state)['run_id']; self.launch(run,'T0001')
        summary=self.finish(run,'T0001',lambda r:r['comparisons'].append({'finding_ids':self.ids,'conclusion':'distinct','reason':'分别核对的控制实现'}))
        self.assertEqual([],summary['issues'])
        rows=[decision(self.state,fid) for fid in self.ids]
        result,payload=approve(self.ws,self.state,rows,run_id=run,run_digest=a.fingerprint(summary),resolutions=[])
        runs.record_receipt(self.ws,run,result)
        root,_,_=runs.load(self.ws,run);(root/'receipt.json').unlink()
        again=rc.apply_adjudication(self.ws,self.state,payload)
        runs.record_receipt(self.ws,run,again)
        self.assertTrue(again['replayed']);self.assertTrue((root/'receipt.json').is_file())

    def test_real_projected_fixtures_are_closed_and_recallable(self):
        raw=json.loads((Path(__file__).parent/'fixtures/attribution.json').read_text())
        records=raw['records']; known={name:{r['id'] for r in records[name]} for name in ('findings','checks','evidence')}
        mats=records['materials']
        if isinstance(mats,list): mids={r['id'] for r in mats}
        else: mids=set(mats)
        self.assertGreaterEqual(len(raw['cases']),8)
        for f in records['findings']:
            self.assertTrue(set(f['check_ids'])<=known['checks'])
            self.assertTrue(set(f['evidence_ids'])<=known['evidence'])
            self.assertNotIn('failure_points',f)
        for e in records['evidence']:
            if e.get('material_id'):self.assertIn(e['material_id'],mids)
        projected=dict(self.state,findings=records['findings'],evidence=records['evidence'],
                       materials=({r['id']:r for r in mats} if isinstance(mats,list) else mats))
        groups=rc.file_groups(projected)
        self.assertEqual({f['id'] for f in projected['findings'] if f['status']=='current'},
                         {fid for g in groups for fid in g['finding_ids']})
        identity=next(c for c in raw['cases'] if c['id']=='same_identity_branch')
        self.assertTrue(any(set(identity['input']['finding_ids'])<=set(g['finding_ids']) for g in groups))


    def _collect_dependency_jobs(self):
        """复用现有四发现夹具；T0001 只主认领首项，显式补读末项。"""
        plan = {'tasks': [
            {'finding_ids': self.ids[:1], 'reason': '第一项的独立分析'},
            {'finding_ids': self.ids[1:], 'reason': '其余项的独立分析'},
        ]}
        run = runs.prepare(self.ws, self.state, task_plan=plan)['run_id']
        self.launch(run, 'T0001')
        root, manifest, _ = runs.load(self.ws, run)
        task = manifest['tasks']['T0001']
        attempt = task['attempts'][-1]
        dependency = {'category': 'findings', 'id': self.ids[-1]}
        dependency['sha256'] = a.fingerprint(a.dependency_value(self.state, dependency))
        data = proposal(run, task, attempt)
        data['read_dependencies'] = [dependency]
        result_path = root / attempt['result_path']
        audit.write_json(result_path, data)
        packet = runs.task_input(root, task)
        self.assertNotIn(dependency['id'], packet['finding_ids'])
        self.assertEqual([], runs.stale_reasons(self.state, packet))
        self.assertEqual([], a.dependency_errors(self.state, [dependency]))
        return run, root, result_path, dependency

    def _change_collect_dependency(self, finding_id):
        """走真实复核账本改变来源；不改冻结 source 或任何已提交结果。"""
        withdraw_review(self.ws, self.state, finding_id, '夹具：源事实订正')
        row = next(f for f in self.state['findings'] if f['id'] == finding_id)
        before = row['impact']
        row['impact'] = before + '；经事实复核收窄的影响'
        self.assertNotEqual(before, row['impact'])
        record_review(self.ws, self.state, finding_id, {
            'reviewer': '同一模型回源复核（回归夹具）；非独立动态验证',
            'decision': 'retain', 'rationale': '夹具源事实已订正',
            'counterevidence_analysis': '用于确认依赖漂移，不修改目标源码',
            'evidence_ids': row['evidence_ids'][:1], 'counterevidence_ids': [],
        })
        self.assertEqual([], a.fact_errors(self.state, row))

    def test_collect_stopped_receipt_survives_stale_returned_read_dependency(self):
        run, root, first_path, dependency = self._collect_dependency_jobs()
        runs.collect(self.ws, self.state, run, [
            {'task_id': 'T0001', 'attempt': 1, 'event': 'completed'},
        ])
        self.launch(run, 'T0002')
        runs.collect(self.ws, self.state, run, [
            {'task_id': 'T0002', 'attempt': 1, 'event': 'started',
             'agent_id': 'fixture-running-agent'},
        ])
        accepted_before = first_path.read_bytes()
        source_before = (root / 'source.json').read_bytes()
        _, before_manifest, _ = runs.load(self.ws, run)
        first_attempt_before = copy.deepcopy(before_manifest['tasks']['T0001']['attempts'][0])

        self._change_collect_dependency(dependency['id'])
        first_packet = runs.task_input(root, before_manifest['tasks']['T0001'])
        # 必须先证明只改变补读来源，不能让普通输入过期掩盖回归靶点。
        self.assertEqual([], runs.stale_reasons(self.state, first_packet))
        self.assertNotEqual(dependency['sha256'],
                            a.fingerprint(a.dependency_value(self.state, dependency)))
        self.assertTrue(a.dependency_errors(self.state, [dependency]))
        audit_before = (self.ws / 'audit.json').read_bytes()

        summary = runs.collect(self.ws, self.state, run, [
            {'task_id': 'T0002', 'attempt': 1, 'event': 'failed',
             'reason': '执行者已停止，来源已改变', 'stopped': True},
        ])
        _, manifest, _ = runs.load(self.ws, run)
        second = manifest['tasks']['T0002']
        self.assertEqual('planned', second['state'])
        self.assertEqual('failed', second['attempts'][0]['state'])
        self.assertEqual('执行者已停止，来源已改变', second['attempts'][0]['reason'])
        self.assertIsNone(second['selected_attempt'])
        self.assertNotIn('result_sha256', second['attempts'][0])
        self.assertIn('T0001', summary['stale_tasks'])
        self.assertNotIn('T0001', summary['result_refs'])
        self.assertIn('T0001', summary['missing_analysis_tasks'])
        self.assertEqual(first_attempt_before, manifest['tasks']['T0001']['attempts'][0])
        self.assertEqual('returned', manifest['tasks']['T0001']['state'])
        state_view = runs.status(self.ws, self.state, run)
        self.assertEqual(0, state_view['in_flight'])
        first_view = next(t for t in state_view['tasks'] if t['task_id'] == 'T0001')
        self.assertEqual('stale', first_view['effective_state'])
        self.assertTrue(first_view['stale_reasons'])
        self.assertEqual(accepted_before, first_path.read_bytes())
        self.assertEqual(source_before, (root / 'source.json').read_bytes())
        self.assertEqual(audit_before, (self.ws / 'audit.json').read_bytes())
        persisted = json.loads((root / 'reconciliation/worklist.json').read_text())
        self.assertEqual(summary, persisted)

    def test_collect_changed_read_dependency_rejects_new_completion(self):
        run, root, result_path, dependency = self._collect_dependency_jobs()
        runs.collect(self.ws, self.state, run, [
            {'task_id': 'T0001', 'attempt': 1, 'event': 'started',
             'agent_id': 'fixture-new-result-agent'},
        ])
        self._change_collect_dependency(dependency['id'])
        _, manifest, _ = runs.load(self.ws, run)
        packet = runs.task_input(root, manifest['tasks']['T0001'])
        self.assertEqual([], runs.stale_reasons(self.state, packet))
        self.assertTrue(a.dependency_errors(self.state, [dependency]))
        files = [root / 'manifest.json', root / 'source.json', result_path,
                 root / 'reconciliation/worklist.json', self.ws / 'audit.json']
        before = {p: p.read_bytes() for p in files}
        # 新成功产物必须拒收；生命周期修复不能把依赖错误吞掉。
        with self.assertRaisesRegex(ValueError, '依赖已变或不存在'):
            runs.collect(self.ws, self.state, run, [
                {'task_id': 'T0001', 'attempt': 1, 'event': 'completed'},
            ])
        self.assertEqual(before, {p: p.read_bytes() for p in files})
        _, after, _ = runs.load(self.ws, run)
        self.assertEqual('running', after['tasks']['T0001']['state'])
        self.assertIsNone(after['tasks']['T0001']['selected_attempt'])

    def test_collect_changed_packet_rejects_new_completion(self):
        run, root, result_path, _ = self._collect_dependency_jobs()
        self._change_collect_dependency(self.ids[0])
        _, manifest, _ = runs.load(self.ws, run)
        packet = runs.task_input(root, manifest['tasks']['T0001'])
        self.assertTrue(runs.stale_reasons(self.state, packet))
        before = (root / 'manifest.json').read_bytes()
        result_before = result_path.read_bytes()
        source_before = (root / 'source.json').read_bytes()
        with self.assertRaisesRegex(ValueError, '任务输入已经过期'):
            runs.collect(self.ws, self.state, run, [
                {'task_id': 'T0001', 'attempt': 1, 'event': 'completed'},
            ])
        self.assertEqual(before, (root / 'manifest.json').read_bytes())
        self.assertEqual(result_before, result_path.read_bytes())
        self.assertEqual(source_before, (root / 'source.json').read_bytes())

    def test_collect_unchanged_dependencies_accept_completion(self):
        run, root, result_path, dependency = self._collect_dependency_jobs()
        result_before = result_path.read_bytes()
        source_before = (root / 'source.json').read_bytes()
        audit_before = (self.ws / 'audit.json').read_bytes()
        summary = runs.collect(self.ws, self.state, run, [
            {'task_id': 'T0001', 'attempt': 1, 'event': 'completed'},
        ])
        self.assertEqual([], summary['stale_tasks'])
        self.assertIn('T0001', summary['result_refs'])
        _, manifest, _ = runs.load(self.ws, run)
        self.assertEqual('returned', manifest['tasks']['T0001']['state'])
        self.assertEqual(1, manifest['tasks']['T0001']['selected_attempt'])
        self.assertEqual([], a.dependency_errors(self.state, [dependency]))
        self.assertEqual(result_before, result_path.read_bytes())
        self.assertEqual(source_before, (root / 'source.json').read_bytes())
        self.assertEqual(audit_before, (self.ws / 'audit.json').read_bytes())

    def test_cli_prepare_dispatch_collect_status_and_report(self):
        import subprocess
        def command(*args):
            result = subprocess.run([sys.executable, str(Path(audit.__file__)), *args,
                                     '--workspace', str(self.ws)], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            return json.loads(result.stdout)
        prepared = command('rootcause', '--prepare')
        run = prepared['run_id']
        capacity = self.ws/'capacity.json'
        audit.write_json(capacity, {'limit': 2, 'active_agent_ids': []})
        launch = command('rootcause', '--dispatch', '--run', run, '--task', 'T0001', '--capacity-file', str(capacity))
        root, manifest, _ = runs.load(self.ws, run)
        task = manifest['tasks']['T0001']
        audit.write_json(Path(launch['result_path']), proposal(run, task, task['attempts'][-1]))
        events = self.ws/'returns.json'
        audit.write_json(events, {'events':[{'task_id':'T0001','attempt':1,'event':'completed','result_path':launch['result_path']}]})
        command('rootcause', '--collect', '--run', run, '--returns-file', str(events))
        status = command('rootcause', '--status', '--run', run)
        self.assertEqual('returned', next(t for t in status['tasks'] if t['task_id']=='T0001')['state'])
        report = command('report')
        self.assertEqual(0, report['writing_tasks'])
        self.assertFalse((self.ws/'report.sarif.json').exists())

    def test_g9_precedes_prose_and_g10_checks_actual_mapping(self):
        from gate import evaluate
        import reporting
        from reporting_check import author_fixture
        self.state['chains'] = [{'id':'CHAIN-AA01-01','title':'组合路径','entry_exposure':'ADJ',
                                 'steps':[{'unit_id':'U-CC01','primitive':'READ','finding_id':self.ids[2],
                                           'check_id':'CHK-CC01-0001','note':'静态关系'}]}]
        rows = [decision(self.state,fid) for fid in self.ids]
        rows[0] = decision(self.state,self.ids[0],'chain',finding_ids=[self.ids[2]],chain_ids=['CHAIN-AA01-01'])
        approve(self.ws,self.state,rows)
        gates = {r['id']:r for r in evaluate(self.ws,self.state,prepare_report=True)}
        self.assertEqual('pass',gates['G9']['status'])
        self.assertEqual('skip',gates['G10']['status'])
        self.assertEqual('fail',next(r for r in evaluate(self.ws,self.state) if r['id']=='G10')['status'])
        from report_fixtures import confirm_fixture_plan
        confirm_fixture_plan(self.state, scenarios=[{'id': 'SCENE-ACCESS', 'title': '有条件的访问路径',
            'chain_ids': ['CHAIN-AA01-01'], 'vulnerability_ids': [self.ids[2]], 'grouping_reason': '保留已有能力的组合关系'}])
        index = reporting.export_package(self.ws,self.state)
        author_fixture(self.ws,self.state,index)
        self.assertEqual([],reporting.validate_package(self.ws,self.state))
        summary = self.ws/'report/summary.md'
        body=summary.read_text();broken=body.replace('<a id="SCENE-ACCESS"></a>','')
        self.assertNotEqual(body,broken);summary.write_text(broken)
        self.assertTrue(any('场景落点' in e for e in reporting.validate_package(self.ws,self.state)))

    def test_received_result_cannot_be_replaced_by_completion_event(self):
        run=runs.prepare(self.ws,self.state)['run_id'];self.launch(run,'T0001');self.finish(run,'T0001')
        root,m,_=runs.load(self.ws,run);attempt=m['tasks']['T0001']['attempts'][-1]
        p=root/attempt['result_path'];data=json.loads(p.read_text());data['reviewer']='different-result'
        audit.write_json(p,data)
        with self.assertRaises(ValueError):runs.collect(self.ws,self.state,run,[{'task_id':'T0001','attempt':1,'event':'completed'}])

    def test_old_authored_reports_are_archived_without_rewriting(self):
        import reporting
        from reporting_check import author_fixture
        approve(self.ws,self.state)
        from report_fixtures import confirm_fixture_plan
        confirm_fixture_plan(self.state)
        index=reporting.export_package(self.ws,self.state);author_fixture(self.ws,self.state,index)
        before={p.name:p.read_bytes() for p in (self.ws/'report/vulnerabilities').glob('*.md')}
        withdraw_review(self.ws,self.state,self.ids[0],'新证据需要核对')
        with self.assertRaises(ValueError): reporting.export_package(self.ws,self.state)
        self.assertEqual(before, {p.name:p.read_bytes() for p in (self.ws/'report/vulnerabilities').glob('*.md')})
        approve(self.ws,self.state)
        confirm_fixture_plan(self.state)
        index=reporting.export_package(self.ws,self.state)
        surviving={p.name:p.read_bytes() for p in (self.ws/'report/vulnerabilities').glob('*.md')}
        archived=[p.read_bytes() for p in (self.ws/'report/legacy/vulnerabilities').glob('*.md')]
        for name,body in before.items():self.assertTrue(surviving.get(name)==body or body in archived)

    def test_known_candidates_cannot_be_closed_with_self_only_comparison(self):
        self.relate()
        rows=[decision(self.state,fid) for fid in self.ids]
        for row in rows:row['comparison']['finding_ids']=[row['finding_id']]
        with self.assertRaises(ValueError):approve(self.ws,self.state,rows)

    def test_explicit_retirement_and_replacement_preserve_history(self):
        from self_check import MERGE
        rows=[decision(self.state,fid) for fid in self.ids]
        for row in rows[:2]:row['comparison']['conclusion']='grouped'
        approve(self.ws,self.state,rows,[dict(copy.deepcopy(MERGE),evidence_ids=self.state['findings'][0]['evidence_ids'])])
        reviews=copy.deepcopy(self.state['reviews'])
        approve(self.ws,self.state,retire_root_cause_ids=['RC-01'])
        self.assertEqual(4,len(self.view()['vulnerabilities']))
        self.assertTrue(self.state['attribution_history'])
        self.assertEqual(reviews,self.state['reviews'])
        self.assertEqual('retired',self.state['root_causes'][0]['status'])


    def test_task_todos_are_routed_without_prefix_collisions(self):
        self.state['report_todos']=[{'id':'TODO-A','instruction':'核对'+self.ids[0]+'的影响','status':'open'},
                                   {'id':'TODO-B','instruction':'只涉及 '+self.ids[0]+'2','status':'open'},
                                   {'id':'TODO-G','instruction':'全局呈现要求。'*30000,'status':'open'}]
        data=runs.packet(self.state,[self.ids[0]])
        self.assertEqual(['TODO-A'],[t['id'] for t in data['report_todos']])
        self.assertEqual(self.state['report_todos'][0],data['report_todos'][0])
        run=runs.prepare(self.ws,self.state)['run_id']
        _,manifest,source=runs.load(self.ws,run)
        self.assertIn('TODO-G',manifest['global_report_todo_ids'])
        self.assertEqual(self.state['report_todos'],source['report_todos'])


    def test_composition_cycles_do_not_close(self):
        self.state['report_todos']=[{'id':'TODO-AA01','instruction':'呈现关系','status':'open'}]
        rows=[decision(self.state,fid) for fid in self.ids]
        for i in range(3):rows[i]=decision(self.state,self.ids[i],'summary',finding_ids=[self.ids[(i+1)%3]],todo_ids=['TODO-AA01'])
        before=(self.ws/'audit.json').read_bytes()
        with self.assertRaises(ValueError):approve(self.ws,self.state,rows)
        self.assertEqual(before,(self.ws/'audit.json').read_bytes())

    def test_reconciliation_new_leads_reach_final_worklist(self):
        self.relate()
        run=runs.prepare(self.ws,self.state)['run_id'];self.launch(run,'T0001');self.finish(run,'T0001')
        root,m,_=runs.load(self.ws,run)
        tid=next(tid for tid,t in m['tasks'].items() if t['kind']=='reconciliation')
        self.launch(run,tid)
        summary=self.finish(run,tid,lambda data:data['open_items'].append({'finding_ids':[data['assessments'][0]['finding_id']],
                                                                         'reason':'跨文件核查新增缺口'}))
        self.assertTrue(any(i['kind']=='open_items' and any(b['item']['reason']=='跨文件核查新增缺口' for b in i['basis']) for i in summary['issues']))
        self.assertIn(tid,summary['result_refs'])
        count=len(runs.load(self.ws,run)[1]['tasks'])
        runs.collect(self.ws,self.state,run)
        self.assertEqual(count,len(runs.load(self.ws,run)[1]['tasks']))


    def test_actual_source_drift_blocks_dispatch(self):
        run=runs.prepare(self.ws,self.state)['run_id']
        material=next(iter(self.state['materials'].values()))
        path=audit.material_path(self.state,material)
        path.write_text('changed after prepare\n')
        with self.assertRaises(ValueError):self.launch(run,'T0001')

    def test_report_fixture_cli_executes_after_helper_definition(self):
        import subprocess
        result=subprocess.run([sys.executable,str(Path(__file__).parent/'report_fixtures.py'),
                               '--case','small','--skill',str(Path(__file__).parent.parent),'--verify-fixture'],
                              capture_output=True,text=True)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        self.assertEqual([],json.loads(result.stdout)['record_validation_errors'])


    def test_replacement_keeps_historical_ids_after_review_withdrawal(self):
        from merge import retract_unit
        withdraw_review(self.ws,self.state,self.ids[0],'拆分复合机制')
        before=copy.deepcopy(self.state)
        with self.assertRaises(ValueError):retract_unit(self.ws,self.state,'U-AA01',[],commit=False)
        self.assertEqual(before,self.state)

    def test_backlinks_recover_without_changing_factual_review(self):
        from self_check import MERGE
        rows=[decision(self.state,fid) for fid in self.ids]
        for row in rows[:2]:row['comparison']['conclusion']='grouped'
        approve(self.ws,self.state,rows,[dict(copy.deepcopy(MERGE),evidence_ids=self.state['findings'][0]['evidence_ids'])])
        old=copy.deepcopy(self.state['reviews'])
        self.state['findings'][0].pop('root_cause_id')
        a.sync_root_cause_links(self.state)
        self.assertEqual('RC-01',self.state['findings'][0]['root_cause_id'])
        self.assertEqual(old,self.state['reviews'])
        self.assertEqual([],self.view()['pending'])


    def test_real_merge_reconstructs_attribution_backlinks(self):
        from self_check import MERGE
        from merge import merge_unit, COLLECTIONS
        from units import id_owner
        rows=[decision(self.state,fid) for fid in self.ids]
        for row in rows[:2]:row['comparison']['conclusion']='grouped'
        approve(self.ws,self.state,rows,[dict(copy.deepcopy(MERGE),evidence_ids=self.state['findings'][0]['evidence_ids'])])
        unit=next(u for u in self.state['units'] if u['id']=='U-AA01')
        product={'unit_id':unit['id'],'schema_version':audit.SCHEMA_VERSION,
                 'progress':{'files_done':len(unit['material_ids'])},
                 'dimensions':{key:{'state':'done','reason':'已完成夹具核对'} for key in unit['dimensions']}}
        for name in COLLECTIONS:
            product[name]=[copy.deepcopy(r) for r in self.state.get(name,[]) if id_owner(r.get('id'))=='AA01']
        for f in product['findings']:
            f['status']='needs_review';f.pop('root_cause_id',None)
        partial=self.ws/'replacement.json';audit.write_json(partial,product)
        old_reviews=copy.deepcopy(self.state['reviews'])
        merge_unit(self.ws,self.state,'U-AA01',partial,replace=True)
        first=next(f for f in self.state['findings'] if f['id']==self.ids[0])
        self.assertEqual('RC-01',first['root_cause_id'])
        self.assertEqual('current',first['status'])
        self.assertEqual(old_reviews,self.state['reviews'])
        self.assertEqual([],self.view()['pending'])


    def test_replacement_preserves_shared_review_order_and_still_rejects_content_changes(self):
        from merge import merge_unit, COLLECTIONS
        from units import id_owner
        from review import subject_digest
        shared = self.state['findings'][2]
        shared['check_ids'] = ['CHK-CC01-0001', 'CHK-AA01-0001', 'CHK-BB01-0001']
        shared['evidence_ids'] = ['E-CC01-001', 'E-AA01-001', 'E-BB01-001']
        unit = next(u for u in self.state['units'] if u['id'] == 'U-AA01')
        partial = self.ws / 'stable-replacement.json'
        for verdict in ('retain', 'reject'):
            record_review(self.ws, self.state, shared['id'], {
                'reviewer': 'shared-source-reviewer', 'decision': verdict,
                'rationale': '夹具分别验证保留与拒绝账本的顺序稳定性。',
                'counterevidence_analysis': '主张本身没有随单元替换变化。',
                'evidence_ids': shared['evidence_ids'], 'counterevidence_ids': []})
            product = {'unit_id': unit['id'], 'schema_version': audit.SCHEMA_VERSION,
                       'progress': {'files_done': len(unit['material_ids'])},
                       'dimensions': {key: {'state': 'done', 'reason': '已核对'} for key in unit['dimensions']}}
            for name in COLLECTIONS:
                product[name] = [copy.deepcopy(r) for r in self.state.get(name, []) if id_owner(r.get('id')) == 'AA01']
            for finding in product['findings']:
                finding['status'] = 'needs_review'
            if not any(e['id'] == 'E-AA01-004' for e in product['evidence']):
                product['evidence'].append(dict(copy.deepcopy(product['evidence'][0]), id='E-AA01-004', observation='新旁证不改变既有主张。'))
            old_order = {key: [r['id'] for r in self.state[key]] for key in ('checks', 'evidence')}
            old_reviews = copy.deepcopy(self.state['reviews'])
            before_digest = subject_digest(self.state, shared)
            audit.write_json(partial, product)
            try:
                merge_unit(self.ws, self.state, unit['id'], partial, replace=True)
            except ValueError as exc:
                self.fail('unchanged shared review was refused: ' + str(exc))
            shared = next(f for f in self.state['findings'] if f['id'] == shared['id'])
            self.assertEqual(before_digest, subject_digest(self.state, shared))
            self.assertEqual(old_reviews, self.state['reviews'])
            self.assertEqual('current' if verdict == 'retain' else 'withdrawn', shared['status'])
            for key, ids in old_order.items():
                self.assertEqual(ids, [r['id'] for r in self.state[key] if r['id'] in ids])
            self.assertEqual('E-AA01-004', self.state['evidence'][-1]['id'])
        original = copy.deepcopy(self.state)
        original_bytes = (self.ws / 'audit.json').read_bytes()
        changed = next(e for e in product['evidence'] if e['id'] == 'E-AA01-001')
        changed['observation'] += ' 实际事实内容变化。'
        audit.write_json(partial, product)
        with self.assertRaisesRegex(ValueError, 'Reviewed subject changed'):
            merge_unit(self.ws, self.state, unit['id'], partial, replace=True)
        self.assertEqual(original, self.state)
        self.assertEqual(original_bytes, (self.ws / 'audit.json').read_bytes())

    def test_large_material_line_locators_use_bounded_reads_and_physical_lines(self):
        from pathlib import Path
        from materials import physical_line_count, decode, MAX_BYTES
        from records import validate
        from report_fixtures import _review
        material = self.state['materials'][self.state['evidence'][0]['material_id']]
        path = audit.material_path(self.state, material)
        text = 'value = 1\n' * 500000
        self.assertGreater(len(text.encode()), MAX_BYTES)
        path.write_text(text)
        material.update(sha256=audit.digest(path), size=path.stat().st_size, visibility='oversized')
        for evidence in self.state['evidence']:
            if evidence['material_id'] == material['id']:
                evidence['sha256'] = material['sha256']
        self.state['evidence'][0]['locator'] = {'lines': [500000, 500000]}
        _review(self.ws, self.state)
        original_open = Path.open
        reads = []
        class Bounded:
            def __init__(self, handle): self.handle = handle
            def __enter__(self): return self
            def __exit__(self, *args): return self.handle.__exit__(*args)
            def __getattr__(self, name): return getattr(self.handle, name)
            def read(self, size=-1):
                if size < 0 or size > MAX_BYTES + 1:
                    raise AssertionError('material read must remain bounded')
                reads.append(size)
                return self.handle.read(size)
        def opened(which, *args, **kwargs):
            handle = original_open(which, *args, **kwargs)
            return Bounded(handle) if which == path else handle
        with patch.object(Path, 'open', opened):
            self.assertEqual([], validate(self.ws, self.state))
        self.assertTrue(reads)
        with self.assertRaisesRegex(ValueError, 'bounded decoding size'):
            decode(text.encode())
        self.state['evidence'][0]['locator']['lines'] = [500001, 500001]
        _review(self.ws, self.state)
        self.assertTrue(any('line beyond end of material' in e for e in validate(self.ws, self.state)))
        probe = self.ws / 'line-probe.txt'
        for value, encoding, expected in [('alpha\u2028beta\nlast', 'utf-8', 2),
                                           ('a\r\nb\rc\n', 'utf-8', 3),
                                           ('甲\n乙', 'utf-16', 2), ('', 'utf-8', 0)]:
            probe.write_bytes(value.encode(encoding))
            self.assertEqual(expected, physical_line_count(probe))
        probe.write_bytes(b'abc\x00def')
        with self.assertRaisesRegex(ValueError, 'Binary control'):
            physical_line_count(probe)

    def test_query_separates_candidate_coverage_from_effective_attribution(self):
        value=rc.survey(self.state)
        self.assertIn('candidate_coverage',value)
        self.assertNotIn('closure',value)
        self.assertEqual(4,value['attribution']['statistics']['pending_findings'])
        self.assertFalse(value['attribution']['statistics']['attribution_complete'])


def run_checks():
    stream=io.StringIO()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(AttributionTests)
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    return [] if result.wasSuccessful() else [stream.getvalue()]


if __name__=='__main__':
    unittest.main()
