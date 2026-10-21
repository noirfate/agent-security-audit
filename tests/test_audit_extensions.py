"""Behavior and counterexample tests for the audit skill's evidence boundaries.

Run from the repository with:
  AUDIT_SKILL_TEST_DIR=/path/to/staged/skill python3 /path/to/this_file.py -v

The existing audit fixtures are copied as data. Dynamic tests bind only a local
HTTPServer and never contact an external service or import target modules.
"""
import copy
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import marshal
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
_roots = [Path(os.environ.get('AUDIT_REPO_TEST_DIR', Path(__file__).resolve().parents[1])), Path.cwd(), Path.cwd() / 'agent-security-audit']
ROOT = next(p for p in _roots if (p / 'tests/fixtures/audit').is_dir())
SKILL = Path(os.environ.get('AUDIT_SKILL_TEST_DIR', str(ROOT / 'skills/agent-security-audit'))).resolve()
sys.path.insert(0, str(SKILL / 'scripts'))
import audit
import dynamic
import knowledge
import materials
import records
import review
import sarif


@contextmanager
def local_http(responder):
    """Observe actual requests; responder returns (status, body, headers)."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self):
            size = int(self.headers.get('Content-Length', '0'))
            body = json.loads(self.rfile.read(size)) if size else None
            request = {'path': self.path, 'method': self.command, 'body': body, 'headers': dict(self.headers)}
            self.server.requests.append(request)
            status, response, headers = responder(request)
            raw = response if isinstance(response, bytes) else json.dumps(response).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)

        do_POST = respond
        do_GET = respond

    server = HTTPServer(('127.0.0.1', 0), Handler)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    try:
        yield server, 'http://127.0.0.1:' + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.target = self.base / 'target'
        shutil.copytree(ROOT / 'tests/fixtures/audit', self.target)
        self.ws = self.base / 'workspace'
        audit.initialize(self.ws, 'extension-fixture', ['app=' + str(self.target)], [])
        self.state = knowledge.read(self.ws / 'audit.json')

    def material(self, path):
        return next(m for m in self.state['materials'].values() if m['path'] == path)

    def add_material(self, name, raw):
        path = self.target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        audit.refresh(self.ws, self.state)
        return self.material(name)

    def valid(self):
        self.assertEqual(records.validate(self.ws, self.state), [])

    def prepared(self, protected=False):
        """Start with actual initialize/seed records, then annotate fixture facts."""
        mat = self.material('business/service.py' if protected else 'framework/memory.py')
        self.state['instances'].append({
            'id': 'I-1', 'name': 'Shared memory fixture', 'framework_object_ids': ['A5.2'],
            'material_ids': [mat['id']], 'evidence_ids': ['E-1'],
            'responsibility': 'Look up the caller-supplied memory namespace',
        })
        self.state['evidence'].append({
            'id': 'E-1', 'material_id': mat['id'], 'sha256': mat['sha256'], 'kind': 'code',
            'locator': {'lines': [3, 4 if protected else 5]}, 'status': 'current',
            'observation': ('recall indexes by authenticated_user.tenant_id and authenticated_user.id.' if protected
                            else 'recall reads request[namespace] without consulting authenticated_user.'),
        })
        audit.seed(self.ws, self.state)
        check = next(c for c in self.state['checks'] if c['failure_mode_id'] == 'FM-A5.2-03')
        check.update(status='complete', applicability='applicable',
                     verdict='not_established' if protected else 'confirmed',
                     scope=['code'], evidence_ids=['E-1'],
                     explanation=('The memory lookup binds both namespace dimensions to the authenticated caller.' if protected
                                  else 'The supplied shared-memory path does not bind the namespace to the caller.'))
        for row in check['prerequisites'] + check['criteria']:
            row.update(state='met', evidence_ids=['E-1'])
        if protected:
            check['counterevidence_ids'] = ['E-1']
        self.valid()
        return check

    def finding(self, check, fid='F-1'):
        finding = {
            'id': fid, 'check_ids': [check['id']], 'evidence_ids': ['E-1'],
            'title': 'Caller selects the shared memory namespace',
            'mechanism': 'The supplied namespace is used without an authenticated-subject binding.',
            'impact': 'Other namespaces may be accessible through this fixture path.',
            'severity': 'medium', 'severity_reason': 'Shared-memory access crosses the caller boundary.',
            'remediation': 'Bind the namespace to the authenticated subject.',
            'responsibility': 'Memory service owner', 'validation': 'Static fixture walkthrough.',
            'residual_risk': 'Host integration has not been supplied.', 'status': 'needs_review',
        }
        self.state['findings'].append(finding)
        return finding

    def adjudicate(self, finding, **updates):
        payload = {
            'reviewer': 'fixture-reviewer', 'decision': 'retain',
            'rationale': 'The evidence supports the scoped fixture mechanism.',
            'counterevidence_analysis': 'The fixture accepts an authenticated user but does not use it.',
            'evidence_ids': ['E-1'], 'counterevidence_ids': [],
        }
        payload.update(updates)
        return review.record_review(self.ws, self.state, finding['id'], payload)

    def configuration(self, url, **updates):
        config = {
            'name': 'Loopback fixture', 'authorization': 'Local test server owned by this test',
            'allowed_actions': 'POST a synthetic prompt to the exact local endpoint',
            'target_version': 'fixture-v1', 'url': url, 'adapter': 'http_json',
            'request': {'body': {'prompt': '{{prompt}}'}}, 'response_pointer': '/reply',
            'max_requests': 3, 'timeout_seconds': 2, 'max_response_bytes': 4096,
        }
        config.update(updates)
        return config

    def runtime_evidence(self, observation):
        return {
            'id': 'E-1', 'kind': 'runtime', 'status': 'current',
            'observation_id': observation['id'], 'sha256': observation['sha256'],
            'locator': {'json_pointer': '/response/selected'},
            'observation': 'A local HTTP response was captured at this pointer.',
        }

    def test_cache_and_executable_artifacts_are_inventory_data_only(self):
        marker = self.base / 'TARGET_EXECUTED'
        fixture_source = (self.target / 'framework/memory.py').read_text()
        fixture_source += '\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n'
        # Compile synthetic source into a genuine importable pyc; never execute it.
        code = compile(fixture_source, 'fixture.py', 'exec')
        bytecode = importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, 0, 0) + marshal.dumps(code)
        payloads = {
            '__pycache__/fixture.pyc': bytecode,
            'build/fixture.pyo': bytecode,
            'dist/loader.py': fixture_source.encode(),
            'node_modules/fixture/index.js': b'throw new Error("must remain data");\n',
            '.venv/lib/fixture.py': fixture_source.encode(),
        }
        for name, raw in payloads.items():
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        before = {p.relative_to(self.target): knowledge.digest(p) for p in self.target.rglob('*') if p.is_file()}
        audit.refresh(self.ws, self.state)
        for name in payloads:
            with self.subTest(material=name):
                mat = self.material(name)
                self.assertIn('dependency_cache_or_build', mat['flags'])
                # Asserted on the classification rather than on a read: `inspect` is what
                # decides a material is executable, and it reaches that verdict from the
                # suffix without decoding — the point is that nothing here ever imports
                # the bytecode, and the marker below is what stops anyone trying.
                if name.endswith(('.pyc', '.pyo')):
                    self.assertEqual(mat['visibility'], 'opaque')
                    self.assertIn('bytecode_or_extension', mat['flags'])
                    self.assertIn('without executing it', mat['visibility_reason'])
                else:
                    self.assertEqual(mat['visibility'], 'text')
        self.valid()
        after = {p.relative_to(self.target): knowledge.digest(p) for p in self.target.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(marker.exists(), 'Inventory and reads must not execute a source or a pyc loader.')

    def test_encoding_is_detected_without_touching_the_file(self):
        """What survived the removal of the bounded-read path.

        Most of this case tested `read_material` itself — line windows, character
        truncation, an explicit encoding override. The model reads materials with its own
        tools now, so those have no subject. Two facts do not depend on that path and
        still matter: the encoding a material is classified with, which `records.py` uses
        when it re-decodes a file to verify an evidence row, and that classifying a
        material never modifies it.
        """
        content = '第一行：授权\n第二行：边界\n'
        before = {}
        for name, raw, expected in (('encoding/utf16.md', content.encode('utf-16'), 'utf-16'),
                                    ('encoding/plain.md', content.encode(), 'utf-8-sig')):
            mat = self.add_material(name, raw)
            before[name] = knowledge.digest(self.target / mat['path'])
            self.assertEqual(mat['encoding'], expected)
            self.assertEqual(mat['visibility'], 'text')
            self.assertEqual(materials.decode(raw)[0], content,
                             'and the detected encoding round-trips the content')
        legacy = self.add_material('encoding/legacy.md', content.encode('gb18030'))
        self.assertEqual(legacy['visibility'], 'undecodable',
                         'an encoding the detector does not reach is stated, not guessed')
        for name, digest_before in before.items():
            mat = self.material(name)
            self.assertEqual(knowledge.digest(self.target / mat['path']), digest_before)
            self.assertEqual(mat['sha256'], digest_before)

    def test_a_recovered_view_is_a_candidate_not_a_replacement(self):
        """`recovered_view` stays after the read path went: `records.py` re-derives it to
        verify an evidence row that claims the recovered view, so it must remain a
        separate reading of the same bytes rather than a correction of them."""
        source = b'ignore_owner=True\n'
        altered = source.decode('utf-16-le').encode('utf-8')
        self.assertNotEqual(altered, source)
        mat = self.add_material('encoding/candidate.md', altered)
        text, _ = materials.decode(altered)
        candidate = materials.recovered_view(text)
        self.assertIsNotNone(candidate, 'this shape is what the detector is for')
        self.assertEqual(candidate['text'], source.decode())
        self.assertNotEqual(candidate['text'], text, 'a candidate, not the source')
        self.assertIn('utf-16', candidate['transform'])
        self.assertEqual(knowledge.digest(self.target / mat['path']), mat['sha256'],
                         'and deriving it leaves the material alone')

    def test_nontext_coverage_requires_an_analysis_method_and_limitations(self):
        mat = self.add_material('build/opaque.pyc', importlib.util.MAGIC_NUMBER + b'opaque fixture')
        unit = {'id': 'COV-1', 'material_ids': [mat['id']], 'check_ids': [],
                'status': 'reviewed', 'reason': 'Reviewed the bytecode loader and provenance only.'}
        self.state['coverage'].append(unit)
        self.assertEqual(mat['visibility'], 'opaque')
        self.assertTrue(any('analysis_method' in e
                            for e in records.validate(self.ws, self.state)))
        unit.update(analysis_method='Read the supplied loader without importing it.',
                    limitations='Bytecode instructions and runtime behavior remain opaque.')
        self.valid()

    def test_review_is_structured_and_rejects_a_changed_subject(self):
        check = self.prepared()
        finding = self.finding(check)
        with self.assertRaises(ValueError):
            self.adjudicate(finding, counterevidence_analysis='')
        self.assertEqual(self.state['reviews'], [])
        row = self.adjudicate(finding)
        self.assertEqual(finding['status'], 'current')
        self.assertEqual(row['subject_sha256'], review.subject_digest(self.state, finding))
        self.valid()
        before = copy.deepcopy(self.state)
        for component in ('finding', 'check', 'evidence'):
            with self.subTest(component=component):
                self.state = copy.deepcopy(before)
                if component == 'finding':
                    self.state['findings'][0]['impact'] += ' Additional unsupplied impact.'
                elif component == 'check':
                    next(c for c in self.state['checks'] if c['id'] == check['id'])['explanation'] += ' Different reachability claim.'
                else:
                    self.state['evidence'][0]['observation'] += ' Different target fact.'
                self.assertNotEqual(self.state, before, 'The counterexample must actually change the subject.')
                self.assertNotEqual(row['subject_sha256'], review.subject_digest(self.state, self.state['findings'][0]))
                self.assertTrue(any('review is stale' in e for e in records.validate(self.ws, self.state)))

    def test_review_binds_counterevidence_even_when_outside_the_finding_and_check(self):
        check = self.prepared()
        finding = self.finding(check)
        mat = self.material('business/service.py')
        counter = {
            'id': 'E-COUNTER', 'material_id': mat['id'], 'sha256': mat['sha256'],
            'kind': 'code', 'locator': {'lines': [3, 4]}, 'status': 'current',
            'observation': 'A separate memory implementation binds both tenant and user identities.',
        }
        self.state['evidence'].append(counter)
        self.assertNotIn(counter['id'], audit.check_evidence_ids(check))
        self.assertNotIn(counter['id'], finding['evidence_ids'])
        self.adjudicate(finding, counterevidence_ids=[counter['id']],
                        counterevidence_analysis='The protected implementation does not guard the independent vulnerable path.')
        self.valid()
        before = copy.deepcopy(counter)
        counter['observation'] = 'The protected implementation guards every call to the reported path.'
        self.assertNotEqual(counter, before)
        self.assertEqual(counter['sha256'], before['sha256'], 'This mutates the evidence interpretation, not its file.')
        self.assertTrue(records.validate(self.ws, self.state),
                        'A retained review must expire when its independent counterevidence changes.')
        self.adjudicate(finding, decision='needs_evidence', counterevidence_ids=[counter['id']],
                        counterevidence_analysis='The new interpretation needs a call-graph trace before retaining the finding.')
        self.assertEqual(finding['status'], 'needs_review')
        self.assertEqual(len(self.state['reviews']), 2)
        self.valid()

    def test_current_finding_without_review_cannot_be_exported_by_cli(self):
        finding = self.finding(self.prepared())
        finding['status'] = 'current'
        self.assertEqual(self.state['reviews'], [])
        audit.save(self.ws, self.state)
        proc = subprocess.run([sys.executable, str(SKILL / 'scripts/audit.py'), 'sarif', '--workspace', str(self.ws)],
                              cwd=self.base, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(proc.stdout)
        self.assertFalse(result['valid'])
        self.assertTrue(any('recorded review' in e for e in result['errors']))
        self.assertFalse((self.ws / 'report.sarif.json').exists())

    def test_effective_control_needs_matching_counterevidence(self):
        check = self.prepared(protected=True)
        self.assertEqual(check['prerequisites'], [])
        self.assertEqual(check['criteria'], [])
        control = {
            'id': 'CTRL-1', 'description': 'Subject binding at the memory boundary',
            'instance_ids': ['I-1'], 'effectiveness': 'effective',
            'scope': 'The supplied memory read path', 'limitations': 'Other call paths unexamined',
            'rationale': 'The selected criterion has a recorded counterexample.',
            'retest': 'Repeat the namespace-boundary check after changes.',
            'check_ids': [check['id']], 'evidence_ids': ['E-1'],
        }
        self.state['controls'].append(control)
        other = copy.deepcopy(self.state['evidence'][0])
        other.update(id='E-OTHER', observation='Independent evidence, not the selected counterexample.')
        self.state['evidence'].append(other)
        self.valid()
        control['evidence_ids'] = ['E-OTHER']
        self.assertNotIn('E-1', control['evidence_ids'])
        self.assertTrue(any('matching counterevidence' in e for e in records.validate(self.ws, self.state)))
        control['evidence_ids'] = ['E-1']
        check['status'] = 'needs_review'
        self.assertTrue(any('stale or incomplete checks' in e for e in records.validate(self.ws, self.state)))

    def test_sarif_exports_current_findings_and_marks_unfinished_coverage(self):
        finding = self.finding(self.prepared())
        self.adjudicate(finding)
        for fid, status in [('F-STALE', 'needs_review'), ('F-WITHDRAWN', 'withdrawn')]:
            old = copy.deepcopy(finding)
            old.update(id=fid, status=status)
            self.state['findings'].append(old)
        self.valid()
        exported = sarif.export_sarif(self.state, self.ws)
        self.assertEqual(exported['version'], '2.1.0')
        run = exported['runs'][0]
        self.assertEqual([r['properties']['findingId'] for r in run['results']], ['F-1'])
        result = run['results'][0]
        self.assertEqual(result['level'], 'warning')
        self.assertEqual(result['locations'][0]['physicalLocation']['region'], {'startLine': 3, 'endLine': 5})
        self.assertEqual(result['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'app/framework/memory.py')
        self.assertEqual(result['partialFingerprints'], sarif.export_sarif(self.state, self.ws)['runs'][0]['results'][0]['partialFingerprints'])
        self.assertEqual({f['id'] for f in run['properties']['omittedFindings']}, {'F-STALE', 'F-WITHDRAWN'})
        self.assertFalse(run['properties']['coverage']['scope_review_complete'])
        self.assertFalse(run['invocations'][0]['executionSuccessful'])
        self.assertEqual(run['invocations'][0]['toolExecutionNotifications'][0]['level'], 'warning')

    def test_zero_findings_in_sarif_do_not_claim_complete_scope(self):
        self.valid()
        run = sarif.export_sarif(self.state, self.ws)['runs'][0]
        self.assertEqual(run['results'], [])
        self.assertFalse(run['invocations'][0]['executionSuccessful'])
        self.assertGreater(run['properties']['coverage']['materials_without_completed_coverage'], 0)

    def test_live_http_is_observed_but_never_auto_promoted_to_a_finding(self):
        with local_http(lambda request: (200, {'reply': request['body']['prompt']}, {})) as (server, url):
            session = dynamic.prepare(self.ws, self.state, self.configuration(url + '/audit'))
            row = dynamic.run(self.ws, self.state, session['id'], 'Echo {{canary}}')
            self.assertEqual(len(server.requests), 1)
            self.assertIn(session['canary'], server.requests[0]['body']['prompt'])
        document = knowledge.read(self.ws / row['path'])
        self.assertEqual(row['observation_mode'], 'live_http')
        self.assertEqual(row['outcome'], 'captured')
        self.assertTrue(document['canary_hit'])
        self.assertIn(session['canary'], document['response']['selected'])
        self.assertEqual(self.state['findings'], [])
        self.state['evidence'].append(self.runtime_evidence(row))
        self.valid()

    def test_simulation_import_cannot_masquerade_as_runtime_evidence(self):
        source = {
            'source': 'synthetic fixture transcript', 'target_version': 'fixture-v1',
            'captured_at': '2026-01-01T00:00:00Z', 'observation_mode': 'simulation',
            'request': {'prompt': 'Return a namespace'},
            'response': {'selected': 'a simulated result'},
        }
        observation = dynamic.import_observation(self.ws, self.state, source)
        self.assertEqual(observation['observation_mode'], 'simulation')
        self.valid()
        self.state['evidence'].append(self.runtime_evidence(observation))
        self.assertTrue(any('simulated or unsuccessful' in e for e in records.validate(self.ws, self.state)))
        claimed_live = {**source, 'observation_mode': 'live_http'}
        self.assertNotEqual(claimed_live, source)
        with self.assertRaises(ValueError):
            dynamic.import_observation(self.ws, self.state, claimed_live)

    def test_failed_attempt_consumes_budget_even_after_reload(self):
        with local_http(lambda request: (200, b'not-json', {})) as (server, url):
            session = dynamic.prepare(self.ws, self.state, self.configuration(url + '/audit', max_requests=1))
            row = dynamic.run(self.ws, self.state, session['id'], 'Synthetic request')
            self.assertEqual(row['outcome'], 'error')
            persisted = knowledge.read(self.ws / 'audit.json')
            self.assertEqual(persisted['observations'][0]['id'], row['id'])
            with self.assertRaises(ValueError):
                dynamic.run(self.ws, persisted, session['id'], 'Do not send this second request')
            self.assertEqual(len(server.requests), 1)
        self.state['evidence'].append(self.runtime_evidence(row))
        self.assertTrue(records.validate(self.ws, self.state))

    def test_redirect_is_not_followed_and_oversized_response_is_inconclusive(self):
        def respond(request):
            if request['path'] == '/redirect':
                # A default urllib opener follows POST/302 as GET. Count both
                # methods so a missing redirect guard cannot silently pass.
                return 302, {'reply': 'redirect'}, {'Location': '/unexpected-destination'}
            return 200, {'reply': 'x' * 200}, {}
        with local_http(respond) as (server, url):
            session = dynamic.prepare(self.ws, self.state, self.configuration(url + '/redirect'))
            redirected = dynamic.run(self.ws, self.state, session['id'], 'Follow no redirect')
            self.assertEqual(redirected['outcome'], 'error')
            self.assertEqual([r['path'] for r in server.requests], ['/redirect'])
            session = dynamic.prepare(self.ws, self.state, self.configuration(url + '/large', max_response_bytes=32))
            large = dynamic.run(self.ws, self.state, session['id'], 'Bound the response')
            self.assertEqual(large['outcome'], 'truncated')
            document = knowledge.read(self.ws / large['path'])
            self.assertNotIn('selected', document['response'])
        self.state['evidence'].append(self.runtime_evidence(large))
        self.assertTrue(records.validate(self.ws, self.state))

    def test_runtime_empty_selected_response_cannot_support_a_finding(self):
        self.prepared()
        baseline = copy.deepcopy(self.state)
        for empty in (None, '', ' \n\t', {}, []):
            with self.subTest(selected=empty):
                self.state = copy.deepcopy(baseline)
                with local_http(lambda request: (200, {'reply': empty}, {})) as (server, url):
                    session = dynamic.prepare(self.ws, self.state, self.configuration(url + '/empty'))
                    row = dynamic.run(self.ws, self.state, session['id'], 'Synthetic input')
                    self.assertEqual(len(server.requests), 1)
                document = knowledge.read(self.ws / row['path'])
                # Establish the invalid fixture: the cited runtime response is empty.
                self.assertEqual(document['response'].get('selected'), empty)
                self.state['evidence'] = [self.runtime_evidence(row)]
                check = next(c for c in self.state['checks'] if c['status'] == 'complete')
                check['scope'] = ['runtime']
                finding = self.finding(check)
                self.adjudicate(finding)
                self.assertTrue(records.validate(self.ws, self.state),
                                'An empty captured response cannot support a confirmed runtime finding.')

    def test_false_and_zero_are_observed_values_not_empty_responses(self):
        baseline = copy.deepcopy(self.state)
        for value in (False, 0):
            with self.subTest(selected=value):
                self.state = copy.deepcopy(baseline)
                with local_http(lambda request: (200, {'reply': value}, {})) as (server, url):
                    session = dynamic.prepare(self.ws, self.state, self.configuration(url + '/signal'))
                    row = dynamic.run(self.ws, self.state, session['id'], 'Synthetic input')
                    self.assertEqual(len(server.requests), 1)
                self.assertEqual(row['outcome'], 'captured')
                selected = knowledge.read(self.ws / row['path'])['response']['selected']
                self.assertEqual(selected, value)
                self.assertIs(type(selected), type(value))
                self.state['evidence'].append(self.runtime_evidence(row))
                self.valid()

    def test_live_credentials_are_sent_only_to_local_server_and_redacted_on_disk(self):
        secret = 'fixture-sensitive-credential-7391'
        def respond(request):
            return 200, {'reply': secret + ' ' + request['body']['prompt'],
                         'authorization': request['headers']['Authorization']}, {}
        with local_http(respond) as (server, url):
            config = self.configuration(url + '/audit')
            config['request']['headers_env'] = {'Authorization': 'AUDIT_EXTENSION_TOKEN'}
            session = dynamic.prepare(self.ws, self.state, config)
            with patch.dict(os.environ, {'AUDIT_EXTENSION_TOKEN': 'Bearer ' + secret}):
                row = dynamic.run(self.ws, self.state, session['id'], secret + ' {{canary}}')
            self.assertEqual(server.requests[0]['headers']['Authorization'], 'Bearer ' + secret)
            self.assertEqual(row['outcome'], 'captured')
            bad = copy.deepcopy(config)
            bad['request']['headers'] = {'Authorization': 'Bearer ' + secret}
            with self.assertRaises(ValueError):
                dynamic.prepare(self.ws, self.state, bad)
        for path in self.ws.rglob('*.json'):
            self.assertNotIn(secret, path.read_text(), str(path.relative_to(self.ws)))
        self.assertIn('[REDACTED]', (self.ws / row['path']).read_text())

    def test_imported_http_credentials_are_redacted_in_every_persisted_record(self):
        secret = 'fixture-import-secret-9467'
        source = {
            'source': 'local-http-capture.json', 'target_version': 'fixture-v1',
            'captured_at': '2026-01-01T00:00:00Z', 'observation_mode': 'recorded_runtime',
            'request': {'headers': {'X-API-Key': secret}, 'body': {'prompt': 'Synthetic request'}},
            'response': {'selected': 'Nonempty captured response'},
        }
        self.assertEqual(source['request']['headers']['X-API-Key'], secret)
        row = dynamic.import_observation(self.ws, self.state, source)
        self.assertEqual(row['observation_mode'], 'recorded_runtime')
        for path in self.ws.rglob('*.json'):
            self.assertNotIn(secret, path.read_text(), str(path.relative_to(self.ws)))

    def test_procedure_catalog_routes_only_known_objects_to_readable_methods(self):
        data, _, _ = knowledge.load_bundle()
        procedures = knowledge.procedures()
        self.assertEqual(len(procedures), 8)
        self.assertEqual(len({p['id'] for p in procedures}), len(procedures))
        for entry in procedures:
            self.assertTrue(entry['targets'] and entry['materials'])
            self.assertLessEqual(set(entry['object_ids']), set(knowledge.objects(data)))
            self.assertTrue(knowledge.procedures(entry['id'], full=True)['content'].strip())
        methods = knowledge.query(data, 'object', 'A2.5')['procedures']
        self.assertIn('skill-integrity', {m['id'] for m in methods})
        with self.assertRaises(ValueError):
            knowledge.procedures('missing-procedure', full=True)

    def test_old_workspace_migrates_without_rewriting_the_old_snapshot(self):
        finding = self.finding(self.prepared())
        self.adjudicate(finding)
        # Derive a 1.0 record by removing precisely the collections added since.
        self.state['schema_version'] = '1.0'
        for key in ('reviews', 'observations', 'dynamic_sessions') + audit.SCHEDULING_COLLECTIONS:
            del self.state[key]
        del self.state['queue']
        audit.save(self.ws, self.state)
        original = copy.deepcopy(self.state)
        result = audit.refresh(self.ws, self.state)
        self.assertTrue(result['schema_migrated'])
        snapshots = list((self.ws / 'snapshots').glob('*before-schema-migration*'))
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(knowledge.read(snapshots[0] / 'workspace' / 'audit.json'), original)
        old_hash = knowledge.digest(snapshots[0] / 'workspace' / 'audit.json')
        self.assertEqual(self.state['schema_version'], audit.SCHEMA_VERSION)
        self.assertEqual(finding['status'], 'needs_review')
        self.assertEqual(self.state['reviews'], [])
        self.valid()
        self.assertFalse(audit.refresh(self.ws, self.state)['schema_migrated'])
        self.assertEqual(knowledge.digest(snapshots[0] / 'workspace' / 'audit.json'), old_hash)

    def test_a_one_one_record_gains_the_scheduling_collections_and_keeps_its_findings(self):
        finding = self.finding(self.prepared())
        self.adjudicate(finding)
        # 1.2 only adds the scheduling layer, so a 1.1 conclusion is not invalidated by
        # the migration itself; only changed material or a changed skill does that.
        self.state['schema_version'] = '1.1'
        for key in audit.SCHEDULING_COLLECTIONS:
            del self.state[key]
        del self.state['queue']
        audit.save(self.ws, self.state)
        result = audit.refresh(self.ws, self.state)
        self.assertTrue(result['schema_migrated'])
        self.assertEqual(self.state['schema_version'], audit.SCHEMA_VERSION)
        for key in audit.SCHEDULING_COLLECTIONS:
            self.assertEqual(self.state[key], [])
        self.assertEqual({k:self.state['queue'][k] for k in audit.EMPTY_QUEUE}, audit.EMPTY_QUEUE)
        self.assertEqual(self.state['queue']['legacy_freeze_contract'], '1.1')
        self.assertEqual(finding['status'], 'current')
        self.valid()

    def test_material_refresh_invalidates_effective_controls(self):
        check = self.prepared(protected=True)
        self.state['controls'].append({
            'id': 'CTRL-1', 'description': 'Authenticated namespace', 'instance_ids': ['I-1'],
            'effectiveness': 'effective', 'scope': 'Supplied memory read', 'limitations': 'Other paths unknown',
            'rationale': 'The key uses tenant and subject', 'retest': 'Re-read changed key construction',
            'check_ids': [check['id']], 'evidence_ids': ['E-1']})
        self.valid()
        path = self.target / 'business/service.py'
        path.write_text(path.read_text() + '\n# revised deployment assumption\n')
        audit.refresh(self.ws, self.state)
        self.assertEqual(self.state['controls'][0]['effectiveness'], 'needs_review')
        self.assertEqual(check['status'], 'needs_review')
        self.valid()

    def test_extended_cli_works_detached_without_writing_the_skill_or_target(self):
        finding = self.finding(self.prepared())
        audit.save(self.ws, self.state)
        detached = self.base / 'installed'
        shutil.copytree(SKILL, detached, ignore=shutil.ignore_patterns('__pycache__'))
        def hashes(directory):
            return {p.relative_to(directory).as_posix(): knowledge.digest(p) for p in directory.rglob('*') if p.is_file()}
        before = hashes(detached), hashes(self.target)
        def run(script, *args):
            proc = subprocess.run([sys.executable, str(detached / 'scripts' / script), *args],
                                  cwd=self.base, capture_output=True, text=True, timeout=20)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            return json.loads(proc.stdout)
        self.assertIn('content', run('knowledge.py', 'procedure', 'mcp-boundaries'))
        # `read` was the detached-run probe until the bounded-read path went; `validate`
        # exercises the same thing — a script run from outside the skill directory, with
        # neither the skill nor the target written to.
        report = run('audit.py', 'validate', '--workspace', str(self.ws))
        self.assertTrue(report['valid'], report.get('errors'))
        payload = self.base / 'review.json'
        audit.write_json(payload, {'reviewer': 'CLI fixture reviewer', 'decision': 'retain',
                                  'rationale': 'Re-read supplied path', 'counterevidence_analysis': 'Checked supplied caller binding',
                                  'evidence_ids': ['E-1'], 'counterevidence_ids': []})
        run('audit.py', 'review', '--workspace', str(self.ws), '--finding', finding['id'], '--review-file', str(payload))
        config = self.base / 'config.json'
        audit.write_json(config, self.configuration('http://127.0.0.1:9/not-contacted'))
        run('dynamic.py', 'prepare', '--workspace', str(self.ws), '--config', str(config))
        source = self.base / 'observation.json'
        audit.write_json(source, {'source': 'synthetic transcript', 'target_version': 'fixture-v1',
                                 'captured_at': '2026-01-01T00:00:00Z', 'observation_mode': 'simulation',
                                 'request': {'prompt': 'synthetic'}, 'response': {'selected': 'synthetic'}})
        imported = run('dynamic.py', 'import', '--workspace', str(self.ws), '--input', str(source))
        result = run('audit.py', 'snapshot', '--workspace', str(self.ws))
        snapshot = Path(result['snapshot']) / 'workspace'
        self.assertTrue((snapshot / 'report.sarif.json').is_file())
        self.assertIn('](' + imported['path'] + ')', (snapshot / 'report.md').read_text())
        self.assertEqual(knowledge.read(snapshot / 'report.sarif.json')['runs'][0]['results'][0]['properties']['findingId'], finding['id'])
        self.assertEqual(before, (hashes(detached), hashes(self.target)))


if __name__ == '__main__':
    unittest.main()
