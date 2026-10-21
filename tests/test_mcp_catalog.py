"""Exercise MCP source provenance, graph navigation and standalone audit delivery."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(os.environ.get('AUDIT_REPO_TEST_DIR', Path(__file__).resolve().parents[1]))
SKILL = Path(os.environ.get('AUDIT_SKILL_TEST_DIR', ROOT / 'skills/agent-security-audit'))
sys.path.insert(0, str(SKILL / 'scripts'))
import audit
import knowledge
sys.path.insert(0, str(ROOT / 'scripts'))
import agent_audit_versioning as versioning


class MCPCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.manifest, cls.fingerprint = knowledge.load_bundle()
        cls.ids = {f'MCP{i:02d}' for i in range(1, 11)}

    def test_pinned_sources_preserve_the_2025_edition_and_source_disagreements(self):
        data = self.data
        risks = {rid: r for rid, r in data['risks'].items() if r['family'] == 'MCP'}
        self.assertEqual(set(risks), self.ids)
        provenance = data['meta']['mcp_top10_source']
        commit = provenance['commit']
        self.assertEqual(commit, '165fe0f78ef104459237b4a8e0f6e78db9b02391')
        self.assertEqual(provenance['edition'], '2025')
        self.assertEqual(provenance['status'], 'beta / v0.1')
        for rid, risk in risks.items():
            with self.subTest(risk=rid):
                self.assertEqual(risk['version'], '2025')
                source = risk['source_refs'][0]
                self.assertIn('/blob/' + commit + '/', source['url'])
                path = ROOT / source['local_path']
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                                 data['meta']['source_hashes'][source['local_path']])
                self.assertIn(rid + ':2025', path.read_text())
                self.assertIn(risk['name_en'], path.read_text())
        self.assertEqual(risks['MCP06']['name_en'], 'Intent Flow Subversion')
        original = ROOT / 'sources/owasp/mcp-top10-2025'
        self.assertIn('Prompt Injection via Contextual Payloads', (original / 'README.md').read_text())
        self.assertIn('creativecommons.org/licenses/by-sa/4.0', (original / 'LICENSE.md').read_text())
        self.assertIn('creativecommons.org/licenses/by-nc-sa/4.0', (original / 'index.md').read_text())
        self.assertIn('CC BY-SA 4.0', provenance['license_note'])
        self.assertIn('CC BY-NC-SA 4.0', provenance['license_note'])

    def test_risk_object_mode_case_and_defense_navigation_are_consistent(self):
        data = self.data
        objects = knowledge.objects(data)
        for rid in self.ids:
            with self.subTest(risk=rid):
                result = knowledge.query(data, 'risk', rid)
                self.assertTrue(result['links'])
                self.assertEqual(set(result['risk']['case_ids']),
                                 {cid for cid, c in data['cases'].items() if rid in c['risk_ids']})
                for row in result['links']:
                    mode = data['failure_modes'][row['failure_mode_id']]
                    self.assertEqual(mode['object_id'], row['object_id'])
                    self.assertIn(rid, mode['risk_ids'])
                    self.assertIn(rid, objects[row['object_id']]['risk_ids'])
                defense = data['defense']['risk_mappings'][rid]
                self.assertTrue(defense['cis_ids'])
                self.assertTrue(set(defense['cis_ids']) <= set(data['defense']['safeguards']))
                self.assertTrue(set(defense['mcp_ids']) <= set(data['defense']['mcp']['recommendations']))
        self.assertIn('PUB-047', data['risks']['MCP05']['case_ids'])
        self.assertIn('PUB-028', data['risks']['MCP06']['case_ids'])
        self.assertNotIn('PUB-028', data['risks']['MCP03']['case_ids'])
        # Neither a generic disclosure nor the Render Skill incident proves an MCP case.
        self.assertFalse(self.ids.intersection(data['cases']['PUB-046']['risk_ids']))

    def test_identity_and_runtime_change_preserve_existing_propositions(self):
        data = self.data
        expected = {
            ('MCP03', 'A4.1'): {'FM-A4.1-01', 'FM-A4.1-05'},
            ('ASI04', 'A4.1'): {'FM-A4.1-01', 'FM-A4.1-05'},
            ('MCP03', 'A4.3'): {'FM-A4.3-02', 'FM-A4.3-04'},
        }
        for (rid, oid), fids in expected.items():
            with self.subTest(risk=rid, object=oid):
                result = knowledge.query(data, 'risk', rid)
                self.assertEqual({r['failure_mode_id'] for r in result['links']
                                  if r['object_id'] == oid}, fids)
                self.assertEqual(data['risks'][rid]['object_ids'].count(oid), 1)
                self.assertEqual(data['objects'][oid]['risk_ids'].count(rid), 1)
                for fid in fids:
                    mode = knowledge.query(data, 'mode', fid)['mode']
                    self.assertIn(rid, mode['risk_ids'])
        triples = [(r['risk_id'], r['object_id'], r['failure_mode_id']) for r in data['links']]
        self.assertEqual(len(triples), len(set(triples)))
        # Existing cases retain their distinct mechanism, rather than moving to the new FM.
        for cid, oid, fid in [('INC-136', 'A4.3', 'FM-A4.3-02'),
                             ('INC-111', 'A4.1', 'FM-A4.1-01')]:
            mapping = next(m for m in data['cases'][cid]['object_mappings'] if m['object_id'] == oid)
            self.assertEqual(mapping['fm_id'], fid)

    def test_distinct_propositions_compile_but_exact_duplicate_links_fail(self):
        links = json.loads((ROOT / 'data/risk-object-links.json').read_text())
        selected = [r for r in links if r['risk_id'] == 'MCP03' and r['object_id'] == 'A4.1']
        self.assertEqual({r['fm_id'] for r in selected}, {'FM-A4.1-01', 'FM-A4.1-05'})
        resolved = versioning.resolve_failure_modes(ROOT, selected)
        self.assertEqual(len(resolved), 2)
        with self.assertRaisesRegex(AssertionError, 'Duplicate risk/object/proposition mapping'):
            versioning.resolve_failure_modes(ROOT, selected + [selected[0]])

    def test_supplement_sources_are_pinned_and_remain_distinct_from_owasp(self):
        data = self.data
        provenance = data['meta']['mcp_supplement_source']
        commit = provenance['commit']
        self.assertEqual(commit, 'c11a8527312b9468aadb76ad0df3572f6da40c47')
        self.assertEqual(set(provenance['classification_names']),
                         {'Name Confusion', 'Rug Pull Attack', 'Tool Shadowing Attack'})
        self.assertEqual({rid for rid, r in data['risks'].items() if r['family'] == 'MCP'}, self.ids)
        for ref in provenance['source_refs']:
            with self.subTest(source=ref['local_path']):
                self.assertIn('/blob/' + commit + '/', ref['url'])
                self.assertEqual(hashlib.sha256((ROOT / ref['local_path']).read_bytes()).hexdigest(),
                                 data['meta']['source_hashes'][ref['local_path']])
                self.assertIn(ref, data['risks']['MCP03']['source_refs'])
        self.assertIn(provenance['source_refs'][0], data['risks']['ASI04']['source_refs'])

    def test_an_installed_skill_can_query_every_mcp_risk_without_the_source_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            isolated = Path(tmp) / 'skill'
            shutil.copytree(SKILL, isolated, ignore=shutil.ignore_patterns('__pycache__'))
            for rid in sorted(self.ids):
                with self.subTest(risk=rid):
                    result = subprocess.run(
                        [sys.executable, '-I', '-B', str(isolated / 'scripts/knowledge.py'), 'risk', rid],
                        cwd=tmp, capture_output=True, text=True,
                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, check=True)
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload['risk']['id'], rid)
                    self.assertTrue(payload['links'])
                    self.assertTrue(payload['risk']['source_refs'][0]['url'].startswith('https://github.com/'))

    def test_new_propositions_reach_audit_checks_and_optional_risk_lookups(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / 'target'
            shutil.copytree(ROOT / 'tests/fixtures/audit', target)
            workspace = base / 'audit'
            audit.initialize(workspace, 'MCP catalogue integration', ['target=' + str(target)], [])
            state = knowledge.read(workspace / 'audit.json')
            for oid in ['A4.1', 'A6.1', 'A7.5']:
                state['instances'].append({
                    'id': 'I-' + oid, 'name': 'Fixture component',
                    'framework_object_ids': [oid], 'material_ids': [], 'evidence_ids': [],
                    'responsibility': 'Fixture routing only; no target security claim.',
                })
            audit.seed(workspace, state)
            for fid, rid in [('FM-A4.1-05', 'MCP03'), ('FM-A4.1-05', 'ASI04'),
                             ('FM-A6.1-05', 'MCP08'), ('FM-A7.5-07', 'MCP09')]:
                checks = [c for c in state['checks'] if c['failure_mode_id'] == fid]
                self.assertEqual(len(checks), 1, fid)
                mode = self.data['failure_modes'][fid]
                brief = knowledge.brief(workspace, state, {'object_ids': [mode['object_id']]})
                self.assertIn(mode['statement'], brief)
                self.assertIn(f'[{rid} · ', brief)
                self.assertIn('risk-catalogue', brief)
            pinned = knowledge.baseline_dir(workspace, state['framework']['baseline_id'])
            frozen, _, _ = knowledge.load_bundle(pinned)
            self.assertEqual(set(r for r in frozen['risks'] if r.startswith('MCP')), self.ids)


if __name__ == '__main__':
    unittest.main()
