#!/usr/bin/env python3
"""Shared, versioned JSON sources for the offline explorer and audit skill."""
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML_NAME = 'AI-Agent安全审计图谱.html'
DATA_FILES = ('metadata', 'architecture', 'risks', 'cases', 'risk-object-links',
              'defense', 'safeai', 'source-techniques', 'reference-catalogs', 'presentation')


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def version_dir(version=None):
    """This repository is the data package itself; paths resolve against it."""
    return ROOT


def ordered(ids, preferred):
    available = set(ids)
    return list(dict.fromkeys([x for x in preferred if x in available] + list(ids)))


def resolve_failure_modes(package, links):
    """A proposition states the object-side failure once; catalog rows reference it."""
    path = package / 'data/failure-modes.json'
    if not path.exists():
        return links
    modes = read(path)

    def expand(row):
        mode = modes[row['fm_id']]
        assert mode['object_id'] == row['object_id'], ('Proposition belongs to another object', row['fm_id'])
        return {'risk_id': row['risk_id'], 'object_id': row['object_id'],
                'role': mode['role'], 'reason': mode['statement'],
                'applicability_conditions': mode['applicability_conditions'],
                'failure_criteria': mode['failure_criteria'],
                'evidence_requirements': mode['evidence_requirements'],
                'mapping_status': mode['mapping_status'], 'origin': mode['origin'],
                'review_id': mode['review_id'],
                'basis_refs': {**mode['basis_refs'], **row['basis_refs']},
                'source_refs': row['source_refs'], 'failure_mode_id': row['fm_id'],
                **({'revised_by': mode['revised_by']} if mode.get('revised_by') else {})}

    resolved, seen = [], set()
    for row in links:
        key = (row['risk_id'], row['object_id'], row['fm_id'])
        assert key not in seen, ('Duplicate risk/object/proposition mapping', key)
        seen.add(key)
        link = expand(row)
        if row.get('contexts'):
            link['contexts'] = row['contexts']
        if row.get('view_reviews'):
            link['view_reviews'] = {vid: expand(view) for vid, view in row['view_reviews'].items()}
        resolved.append(link)
    return resolved


def review_revisions(package):
    """Deliberate, recorded changes on top of a frozen responsibility review."""
    path = package / 'data/review-revisions.json'
    if not path.exists():
        return {}, {}, set()
    doc = read(path)
    relabels, additions, removals = {}, {}, set()
    for revision in doc['revisions']:
        # Case-to-object revisions are a separate channel; the risk map does not read them.
        if revision.get('channel', 'risk_object') != 'risk_object':
            continue
        for entry in revision['entries']:
            assert entry.get('reason'), ('Revision entry needs a reason', revision['id'])
            if revision['kind'] == 'relabel':
                relabels.setdefault(entry['fm_id'], {})[entry['field']] = (entry['from'], entry['to'])
            elif revision['kind'] == 'add_mapping':
                for rid in entry['risk_ids']:
                    key = (entry['object_id'], rid)
                    assert key not in additions, ('Duplicate declared addition', key)
                    additions[key] = entry['fm_id']
            elif revision['kind'] == 'remove_mapping':
                removals |= {(entry['object_id'], rid) for rid in entry['risk_ids']}
            else:
                raise AssertionError(('Unknown revision kind', revision['kind']))
    return relabels, additions, removals


def mapping_review(package, links, views):
    """Keep reviewed decisions and the active map consistent, including scoped views."""
    path = package / 'data/risk-mapping-review.json'
    if not path.exists():
        return None
    review = read(path)
    retired_objects = set(review.get('retired_object_ids', []))
    accepted = {}
    for row in review['decisions']:
        if row['decision'] == 'exclude_from_risk_tags' or row['object_id'] in retired_objects:
            continue
        link = row['reviewed_link']
        key = (link['object_id'], link['risk_id'])
        assert key not in accepted, ('Duplicate review decision', key)
        assert link['review_id'] == review['review_id']
        assert link['applicability_conditions'] and link['failure_criteria']
        assert link['evidence_requirements'] and link['basis_refs']
        accepted[key] = link
    active = {}
    for link in links:
        key = (link['object_id'], link['risk_id'])
        assert key not in active, ('Duplicate active mapping', key)
        active[key] = {k: v for k, v in link.items() if k not in {'contexts', 'view_reviews'}}
        for vid, projected in link.get('view_reviews', {}).items():
            assert views[vid]['canonical_id'] == link['object_id']
            assert projected['object_id'] == vid and projected['risk_id'] == link['risk_id']
            key = (vid, link['risk_id'])
            assert key not in active, ('Duplicate reviewed view', key)
            active[key] = dict(projected)
    relabels, additions, removals = review_revisions(package)
    for key, row in active.items():
        link = {k: v for k, v in row.items() if k not in {'failure_mode_id', 'revised_by'}}
        if key not in accepted:
            assert key in additions, ('Active mapping without a review decision', key)
            assert row.get('failure_mode_id') == additions[key], ('Addition cites another proposition', key)
            continue
        revised = relabels.get(row.get('failure_mode_id'), {})
        for field, value in accepted[key].items():
            if link[field] == value:
                continue
            assert field in revised, ('Active mapping differs from its review', key, field)
            assert revised[field] == (value, link[field]), ('Revision does not match the change', key, field)
        assert set(link) == set(accepted[key]), ('Active mapping changed its fields', key)
    missing = set(accepted) - set(active) - removals
    assert not missing, ('Reviewed mapping dropped without a removal record', sorted(missing)[:5])
    expected = review['summary']['active_rendered_links'] + len(additions) - len(removals)
    assert len(active) == expected, (len(active), expected)
    return review


def compile_data(version=None):
    package = version_dir(version)
    p = {name: read(package / 'data' / (name + '.json')) for name in DATA_FILES}
    a, order = p['architecture'], p['presentation']
    objects, security = a['objects'], a['security_objects']
    # Older readers use this field; its content is derived from the canonical definition.
    for obj in objects.values():
        if 'definition' in obj:
            obj['member_and_boundary'] = obj['definition']
    # A package either maintains one canonical definition per object, or it predates that rule.
    canonical_definitions = all('definition' in obj for obj in objects.values())
    views, aliases = a.get('security_views', {}), a.get('aliases', {})
    risks, cases = p['risks'], p['cases']
    # A case reaches an object through a stated mapping; the id list is only its index.
    for case in cases.values():
        case['object_ids'] = [m['object_id'] for m in case['object_mappings']] \
            if 'object_mappings' in case else case.get('object_ids', [])
    failure_modes = copy.deepcopy(read(package / 'data/failure-modes.json')) \
        if (package / 'data/failure-modes.json').exists() else {}
    for fid, mode in failure_modes.items():
        assert mode['id'] == fid, ('Mismatched proposition id', fid)
        assert mode['object_id'] in {**objects, **security, **views}, ('Unknown object', fid)
        assert 'conditions' not in mode and 'applicability' not in mode, ('Legacy mixed conditions', fid)
        for field in ('applicability_conditions', 'failure_criteria', 'evidence_requirements'):
            values = mode.get(field)
            assert isinstance(values, list) and values and all(isinstance(s, str) and s.strip() for s in values), (fid, field)
    links = resolve_failure_modes(package, p['risk-object-links'])
    review = mapping_review(package, links, views)
    for link in links:
        if review:
            # Imported descriptions remain in the archive; they do not override this review.
            continue
        descriptions = list(dict.fromkeys(c['role_description'] for c in link.get('contexts', [])
                                          if c.get('role_description')))
        if descriptions:
            link['role_description'] = '；'.join(descriptions)
    # A contextual view projects canonical relationships; it never owns a second rule.
    projected = []
    for vid, view in views.items():
        target = security[view['canonical_id']]
        obj = {**copy.deepcopy(target), **copy.deepcopy(view), 'id': vid, 'kind': 'security',
               'definition': view.get('definition') or target['definition'] + ' ' + view['scope'],
               'is_view': True}
        views[vid] = obj
        for link in links:
            if link['object_id'] != view['canonical_id']:
                continue
            contexts = [c for c in link.get('contexts', []) if c.get('view_id') == vid]
            # The projection comes from the canonical link's own view_reviews, not from the review archive.
            selected = link.get('view_reviews', {}).get(vid)
            if selected:
                projected.append({**copy.deepcopy(selected), 'canonical_object_id': view['canonical_id'],
                                  'contexts': contexts, 'projection': True})
            elif contexts:
                projected.append({**copy.deepcopy(link), 'object_id': vid,
                                  'canonical_object_id': view['canonical_id'],
                                  'role': contexts[0]['role'],
                                  'reason': '；'.join(dict.fromkeys(c['reason'] for c in contexts)),
                                  'contexts': contexts, 'projection': True})
    links = links + projected
    all_objects = {**objects, **security, **views}
    for oid, obj in all_objects.items():
        ids = [l['risk_id'] for l in links if l['object_id'] == oid]
        obj['risk_ids'] = ordered(ids, order['object_risks'].get(oid, []))
    for rid, risk in risks.items():
        ids = [l['object_id'] for l in links if l['risk_id'] == rid and l['object_id'] in objects]
        risk['object_ids'] = ordered(ids, order['risk_objects'].get(rid, []))
        if review:
            risk['object_roles'] = {l['object_id']: l['role'] for l in links
                                    if l['risk_id'] == rid and l['object_id'] in objects}
        risk['security_object_ids'] = [s for s in security if any(l['risk_id'] == rid and l['object_id'] == s for l in links)]
        cids = [cid for cid, case in cases.items() if rid in case['risk_ids']]
        risk['case_ids'] = ordered(cids, order['risk_cases'].get(rid, []))
    for layer in a['layers']:
        layer['object_ids'] = [oid for oid, obj in objects.items() if obj['layer_id'] == layer['id']]
    for domain in a['domains']:
        ids = [oid for oid, obj in {**security, **views}.items() if obj['domain_id'] == domain['id']]
        domain['object_ids'] = ordered(ids, order['domain_objects'].get(domain['id'], []))
    defense = p['defense']
    for oid, profile in defense['object_mappings'].items():
        if canonical_definitions:
            profile['object_scope'] = all_objects[oid]['definition']
        requirement_sets = [defense['technical_requirements'][tid]
                            for tid in profile.get('technical_requirement_ids', [])]
        if requirement_sets:
            profile['requirements'] = [x for t in requirement_sets for x in t['requirements']]
            profile['checks'] = [x for t in requirement_sets for x in t['checks']]
            profile['evidence'] = list(dict.fromkeys(x for t in requirement_sets for x in t['evidence']))
            profile['location'] = '；'.join(dict.fromkeys(t['location'] for t in requirement_sets))
    for vid, view in views.items():
        profile = copy.deepcopy(defense['object_mappings'][view['canonical_id']])
        context = defense.get('view_contexts', {}).get(vid, {})
        profile.update(context)
        if canonical_definitions:
            profile['object_scope'] = view['definition']
        profile['canonical_object_id'] = view['canonical_id']
        defense['object_mappings'][vid] = profile
    for mode in failure_modes.values():
        mode['risk_ids'] = [l['risk_id'] for l in links if l.get('failure_mode_id') == mode['id']]
        assert mode['risk_ids'], ('Proposition without any catalog entry', mode['id'])
    if failure_modes:
        for oid, obj in all_objects.items():
            obj['failure_mode_ids'] = [m['id'] for m in failure_modes.values() if m['object_id'] == oid]
    extra = {'failure_modes': failure_modes} if failure_modes else {}
    review_path = package / 'data/case-object-review.json'
    if review_path.exists():
        extra['case_review'] = read(review_path)
    # The case count is a fact about cases.json, so it is derived, never maintained by hand.
    p['metadata']['case_count'] = len(cases)
    return dict(meta=p['metadata'], layers=a['layers'], objects=objects, **extra,
                domains=a['domains'], security_objects=security, security_views=views,
                aliases=aliases, risks=risks, cases=cases, links=links,
                controls=p['reference-catalogs']['controls'],
                methods=p['reference-catalogs']['methods'], defense=defense,
                safeai=p['safeai']['report'], cross_object_controls=p['safeai']['joint_controls'],
                source_techniques=p['source-techniques'])


def build(version=None, publish_current=False):
    package = version_dir(version)
    data = compile_data()
    export_text = json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    (package / 'explorer-data.json').write_text(export_text)
    css = (package / 'ui/app.css').read_text()
    js = (package / 'ui/app.js').read_text()
    template = (package / 'ui/app.html').read_text()
    payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('&', '\\u0026')
    base = template.replace('/*__APP_CSS__*/', css).replace('/*__APP_JS__*/', js).replace('__EXPLORER_DATA__', payload)
    targets = [package / HTML_NAME]
    if publish_current:
        targets.append(ROOT / HTML_NAME)
    for target in targets:
        def href_to(base_dir):
            rel = os.path.relpath(base_dir, target.parent).replace(os.sep, '/')
            return '' if rel == '.' else rel + '/'
        # Two bases: the repository root for older versions, the package itself for a self-contained one.
        marker = '<meta name="agent-project-root" content="' + href_to(ROOT) + '">' \
                 '\n  <meta name="agent-package-root" content="' + href_to(package) + '">'
        rendered = base.replace('<meta charset="utf-8">', '<meta charset="utf-8">\n  ' + marker, 1)
        target.write_text(rendered)
    return data, targets
