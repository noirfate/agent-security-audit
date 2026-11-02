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
        self.assertEqual('summary.md#' + self.ids[0], self.view()['finding_map'][self.ids[0]]['path'])
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
        index = reporting.export_package(self.ws,self.state)
        author_fixture(self.ws,self.state,index)
        self.assertEqual([],reporting.validate_package(self.ws,self.state))
        summary = self.ws/'report/summary.md'
        body=summary.read_text();broken=body.replace('<a id="'+self.ids[0]+'"></a>','')
        self.assertNotEqual(body,broken);summary.write_text(broken)
        self.assertTrue(any('anchor' in e for e in reporting.validate_package(self.ws,self.state)))

    def test_received_result_cannot_be_replaced_by_completion_event(self):
        run=runs.prepare(self.ws,self.state)['run_id'];self.launch(run,'T0001');self.finish(run,'T0001')
        root,m,_=runs.load(self.ws,run);attempt=m['tasks']['T0001']['attempts'][-1]
        p=root/attempt['result_path'];data=json.loads(p.read_text());data['reviewer']='different-result'
        audit.write_json(p,data)
        with self.assertRaises(ValueError):runs.collect(self.ws,self.state,run,[{'task_id':'T0001','attempt':1,'event':'completed'}])

    def test_migration_keeps_facts_and_does_not_infer_dispositions(self):
        original=copy.deepcopy(self.state['findings'])
        self.state['schema_version']=audit.MIGRATABLE[-1]
        for key in ('finding_dispositions','attribution_history','attribution_commits'):self.state.pop(key,None)
        audit.save(self.ws,self.state)
        migrated=audit.refresh(self.ws,self.state)
        self.assertTrue(migrated['schema_migrated'])
        self.assertEqual(audit.SCHEMA_VERSION,self.state['schema_version'])
        self.assertEqual(original,self.state['findings'])
        self.assertEqual([],self.state['finding_dispositions'])
        self.assertEqual(4,self.view()['statistics']['pending_findings'])

    def test_old_authored_reports_are_archived_without_rewriting(self):
        import reporting
        from reporting_check import author_fixture
        approve(self.ws,self.state)
        index=reporting.export_package(self.ws,self.state);author_fixture(self.ws,self.state,index)
        before={p.name:p.read_bytes() for p in (self.ws/'report/vulnerabilities').glob('*.md')}
        withdraw_review(self.ws,self.state,self.ids[0],'新证据需要核对')
        index=reporting.export_package(self.ws,self.state)
        surviving={p.name:p.read_bytes() for p in (self.ws/'report/vulnerabilities').glob('*.md')}
        archived=[p.read_bytes() for p in (self.ws/'report/legacy/vulnerabilities').glob('*.md')]
        for name,body in before.items():self.assertTrue(surviving.get(name)==body or body in archived)

    def test_known_candidates_cannot_be_closed_with_self_only_comparison(self):
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

    def test_legacy_three_file_snapshot_still_loads(self):
        folder=Path(self.tmp.name)/'legacy';folder.mkdir()
        for name,body in [('audit.json','{}'),('report.md','# historical'),('report.sarif.json','{}')]:
            (folder/name).write_text(body)
        audit.write_json(folder/'manifest.json',{'files':{p.name:audit.digest(p) for p in folder.iterdir()},
                                                'baseline_ids':[self.state['framework']['baseline_id']]})
        self.assertEqual({'audit.json','report.md','report.sarif.json'},set(audit.snapshot_manifest(folder)['files']))

    def test_reconciliation_new_leads_reach_final_worklist(self):
        run=runs.prepare(self.ws,self.state)['run_id'];self.launch(run,'T0001');self.finish(run,'T0001')
        root,m,_=runs.load(self.ws,run)
        tid=next(tid for tid,t in m['tasks'].items() if t['kind']=='reconciliation')
        self.launch(run,tid)
        summary=self.finish(run,tid,lambda data:data['open_items'].append({'finding_ids':[data['assessments'][0]['finding_id']],
                                                                         'reason':'跨文件核查新增缺口'}))
        self.assertTrue(any(i['kind']=='open_items' and i['basis']['item']['reason']=='跨文件核查新增缺口' for i in summary['issues']))
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
