#!/usr/bin/env python3
"""Check this skill against itself. Ships with the skill, so an installed copy is verifiable.

Each check below exists because something actually went wrong once, and each one is
mechanical: it answers "is it there, do the two sides agree, does the number hold",
never "is this a good audit". A crash is reported as a FAIL rather than raised, so a
broken check cannot read as a pass.

    python3 self_check.py            run every check
    python3 self_check.py --list     name them without running

Exit codes: 0 all passed / 1 at least one failed / 2 the checker could not run.
"""
# Importable under `python3 -I`, which clears the script directory from sys.path:
# the session rule is to read untrusted data with -I, and these scripts import
# their siblings, so without this they fail before doing anything.
import sys as _sys
from pathlib import Path as _Path
if str(_Path(__file__).resolve().parent) not in _sys.path:
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
import argparse
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / 'scripts'
DOCS = [SKILL / 'SKILL.md'] + sorted((SKILL / 'references').rglob('*.md'))
BRIEF_BUDGET = 30 * 1024

CHECKS = []


def check(name):
    def wrap(function):
        CHECKS.append((name, function))
        return function
    return wrap


def read_text(path):
    return Path(path).read_text(encoding='utf-8')


def docs_text():
    return '\n'.join(read_text(p) for p in DOCS if p.is_file())


def root_cause_fixture(tmp):
    """A fresh record with a known root-cause shape, for the checks that need findings.

    Three units, one proposition shared by all three (a strong `fm:` candidate), and two
    of them citing the same three evidence locations (a strong `set:` candidate). The
    generator, the gate row and the renderer are each driven over this instead of over a
    re-implementation of what they are supposed to do.
    """
    import audit
    from units import new_unit
    workspace, target = Path(tmp) / 'ws', Path(tmp) / 'target'
    target.mkdir()
    for name in ('a.ts', 'b.ts', 'c.ts'):
        (target / name).write_text('x = 1\n' * 8, encoding='utf-8')
    audit.initialize(workspace, 'rc-probe', ['repo=' + str(target)], [])
    state = audit.read(workspace / 'audit.json')
    mats = sorted(state['materials'])
    state['units'] = [new_unit('U-AA01', 'repo_shard', 'a', mapping_note='n'),
                      new_unit('U-BB01', 'repo_shard', 'b', mapping_note='n'),
                      new_unit('U-CC01', 'repo_shard', 'c', mapping_note='n')]
    for unit, mid in zip(state['units'], mats):
        # Counted, so the record passes `validate`: a fixture that cannot validate also
        # cannot be rendered through the command line, and that is one of the paths
        # these checks have to drive.
        row = state['materials'][mid]
        unit.update(material_ids=[mid], file_count=1, byte_count=row['size'] or 0,
                    text_count=1, opaque_count=0,
                    target_ids=[row['target_id']], exposure='INT', exposure_reason='r')
    state['queue'].update(partition_confirmed=True, partition_reason='r',
                          census={'enumerated': len(mats), 'in_units': len(mats),
                                  'unit_file_count_sum': len(mats)})

    def evidence(eid, mid, first):
        return {'id': eid, 'material_id': mid, 'sha256': state['materials'][mid]['sha256'],
                'kind': 'code', 'locator': {'lines': [first, first + 2]},
                'observation': 'o', 'status': 'current'}
    state['evidence'] = ([evidence('E-AA01-00%d' % i, mats[0], i) for i in (1, 2, 3)]
                         + [evidence('E-BB01-00%d' % i, mats[0], i) for i in (1, 2, 3)]
                         + [evidence('E-CC01-001', mats[2], 2),
                            evidence('E-CC01-002', mats[2], 5)])

    def check_row(cid, mode, evidence_ids):
        return {'id': cid, 'failure_mode_id': mode, 'instance_ids': [],
                'baseline_id': state['framework']['baseline_id'], 'status': 'complete',
                'verdict': 'confirmed', 'applicability': 'applicable', 'scope': ['code'],
                'local_definition': None, 'prerequisites': [], 'criteria': [],
                'evidence_ids': evidence_ids, 'counterevidence_ids': [],
                'explanation': 'e', 'missing_evidence': []}
    state['checks'] = [check_row('CHK-AA01-0001', 'FM-A1.1-01', ['E-AA01-001']),
                       check_row('CHK-BB01-0001', 'FM-A1.1-01', ['E-BB01-001']),
                       check_row('CHK-CC01-0001', 'FM-A1.1-01', ['E-CC01-001']),
                       check_row('CHK-CC01-0002', None, ['E-CC01-002'])]

    def finding(fid, check_ids, evidence_ids, severity='high'):
        return {'id': fid, 'check_ids': check_ids, 'title': 't ' + fid, 'mechanism': 'm',
                'evidence_ids': evidence_ids, 'impact': 'i', 'severity': severity,
                'severity_reason': 'sr', 'remediation': 'rem', 'responsibility': 'resp',
                'validation': 'v', 'residual_risk': 'rr', 'exposure': 'EXT',
                'status': 'current'}
    state['findings'] = [
        finding('F-AA01-01', ['CHK-AA01-0001'], ['E-AA01-001', 'E-AA01-002', 'E-AA01-003']),
        finding('F-BB01-01', ['CHK-BB01-0001'], ['E-BB01-001', 'E-BB01-002', 'E-BB01-003']),
        finding('F-CC01-01', ['CHK-CC01-0001'], ['E-CC01-001']),
        finding('F-CC01-02', ['CHK-CC01-0002'], ['E-CC01-002'], 'low')]
    # One instance per unit, carrying the object the proposition belongs to, and a local
    # definition for the check that has no proposition: without them the record does not
    # validate, and a record the product would refuse is the wrong thing to assert on —
    # `report` stops at `validate` and never renders, so the command-line path could not
    # be driven at all.
    state['instances'] = [{'id': 'INST-' + unit['id'][2:], 'name': 'n ' + unit['id'][2:],
                           'unit_id': unit['id'], 'framework_object_ids': ['A1.1'],
                           'material_ids': list(unit['material_ids']),
                           'evidence_ids': [], 'responsibility': 'r'}
                          for unit in state['units']]
    for row in state['checks']:
        row['instance_ids'] = ['INST-' + row['id'].split('-')[1]]
        if row['failure_mode_id'] is None:
            row['local_definition'] = {'statement': '本地命题', 'requirement': '本地要求'}
    state['queue'].pop('legacy_freeze_contract', None)
    audit.save(workspace, state)
    # Through the real ledger, so the digest binds the finding as it actually is: these
    # checks then also show that grouping a reviewed finding does not stale its review.
    from review import record_review
    for row in list(state['findings']):
        record_review(workspace, state, row['id'],
                      {'reviewer': '同一模型回源复核（自检夹具）；非独立实现验证',
                       'decision': 'retain', 'rationale': 'r',
                       'counterevidence_analysis': 'c',
                       'evidence_ids': row['evidence_ids'][:1],
                       'counterevidence_ids': []})
    return workspace, state


def linked(state, rows):
    """Adjudications plus the back-links, written the way `rootcause --apply` writes them."""
    state['root_causes'] = rows
    owner = {fid: row['id'] for row in rows if row.get('verdict') == 'merge'
             for fid in row.get('finding_ids') or []}
    for finding in state['findings']:
        finding['root_cause_id'] = owner.get(finding['id'])
    return state


MERGE = {'id': 'RC-01', 'verdict': 'merge', 'statement': '共享加载器缺来源约束',
         'fix_point': 'a.ts 的 load()', 'by': 'segment reviewer', 'reason': '同一处调用点',
         'finding_ids': ['F-AA01-01', 'F-BB01-01'], 'candidates': ['fm:FM-A1.1-01'],
         'member_paths': [{'finding_id': 'F-AA01-01', 'location': 'a.ts:1-3',
                           'difference': '入口在网关'},
                          {'finding_id': 'F-BB01-01', 'location': 'a.ts:2-4',
                           'difference': '入口在通道'}]}


@check('role-contracts')
def role_contracts():
    """Each role contract fixes its own return line, and somebody dispatches it.

    The roles are enumerated from the directory rather than from a list in here: a
    hard-coded list makes the missing-file direction visible and the other one invisible,
    so a contract nobody ever dispatches would pass unnoticed — the same shape as the
    verdict that had no landing place.

    Kept through the pruning that removed the prose-anchored checks: this one reconciles
    two independently changing facts — what sits in `roles/` against what the protocol
    dispatches — and the survey found three contracts (merger, queue_critic,
    report_writer) that no run has ever dispatched. It was misclassified as prose-only
    once, by a script that matched on the Chinese strings without reading the body.
    """
    directory = SKILL / 'references' / 'roles'
    contracts = sorted(p for p in directory.glob('*.md'))
    problems = []
    if not contracts:
        return ['no role contracts found at ' + str(directory)]
    elsewhere = {p: read_text(p) for p in sorted(SKILL.rglob('*.md')) if p.parent != directory}
    sibling = {p: read_text(p) for p in contracts}
    for path in contracts:
        role = path.stem
        text = sibling[path]
        if '## return 行' not in text:
            problems.append(role + ': no return line is fixed')
        if '证据' not in text and 'evidence' not in text:
            problems.append(role + ': does not state what counts as evidence')
        routed = (any(role in t for t in elsewhere.values())
                  or any(role in t for p, t in sibling.items() if p != path))
        if not routed:
            problems.append(role + ': nothing dispatches this contract')
    return problems


@check('schema-literal')
def schema_literal():
    """The target schema version is pinned in one place.

    dynamic.py once compared `state['schema_version']` to a literal of its own, so a
    bumped schema left that one script refusing every workspace while every other
    script accepted it.
    """
    # Only the target record's field counts: the framework bundle has a field of the
    # same name whose literal is legitimately written out in knowledge.py.
    owner = re.compile(r"""state(?:\.get\(['"]|\[['"])schema_version""")
    literal = re.compile(r"'[0-9]+\.[0-9]+'")
    bad = []
    for path in sorted(SCRIPTS.glob('*.py')):
        if path.name == 'audit.py':
            continue
        for number, line in enumerate(read_text(path).splitlines(), 1):
            if owner.search(line) and literal.search(line):
                bad.append('%s:%d %s' % (path.name, number, line.strip()))
    return bad and ['compares the target schema against a literal instead of '
                    'audit.SCHEMA_VERSION: ' + '; '.join(bad)]


@check('id-prefix-table')
def id_prefix_table():
    """Every mergeable collection has an id prefix, and every prefix has a collection."""
    from merge import COLLECTIONS
    from units import PREFIXES
    missing = sorted(set(COLLECTIONS) - set(PREFIXES))
    extra = sorted(set(PREFIXES) - set(COLLECTIONS))
    problems = []
    if missing:
        problems.append('mergeable collections without an id prefix: ' + ', '.join(missing))
    if extra:
        problems.append('id prefixes for collections a unit cannot contribute: ' + ', '.join(extra))
    other = {k: v for k, v in PREFIXES.items() if k != 'dismissed_candidates'}
    if len(set(other.values())) != len(other) or PREFIXES.get('dismissed_candidates') != PREFIXES.get('findings'):
        problems.append('unexpected shared id prefix; only findings/dismissed_candidates share candidate identity')
    return problems


@check('surface-patterns')
def surface_patterns():
    """Pattern families must compile and must point at objects that exist in the bundle."""
    from knowledge import load_bundle, objects
    from surface import load_patterns
    data, _, _ = load_bundle()
    known = objects(data)
    families = load_patterns()['families']
    problems = []
    if len({f['id'] for f in families}) != len(families):
        problems.append('duplicate family ids')
    for family in families:
        if not family.get('sink'):
            problems.append('%s: a family with no sink pattern yields nothing to dispose of'
                            % family['id'])
        for kind in ('sink', 'topic'):
            for expression in family.get(kind) or []:
                try:
                    re.compile(expression)
                except re.error as exc:
                    problems.append('%s %s: regex does not compile (%s): %s'
                                    % (family['id'], kind, exc, expression))
        for oid in family['object_ids']:
            if oid not in known:
                problems.append('%s: routes to an object that is not in the framework: %s'
                                % (family['id'], oid))
    hint = load_patterns().get('cross_domain_hint') or {}
    ids = {f['id'] for f in families}
    for domain, listed in hint.items():
        for fid in listed:
            if fid not in ids:
                problems.append('cross_domain_hint %s names an unknown family: %s' % (domain, fid))
    return problems


@check('brief-budget')
def brief_budget():
    """A per-object unit brief stays inside the budget the orchestration doc states.

    This is the knowledge wall the scheduling layer exists to avoid: a full object
    query is 19-24 KB, so a worker that queries them itself spends its window before
    reading code.
    """
    from knowledge import brief, load_bundle, objects
    data, _, _ = load_bundle()
    oversized = []
    for oid in objects(data):
        unit = {'id': 'U-SH01', 'kind': 'repo_shard', 'object_ids': [oid], 'mapping_note': ''}
        size = len(brief(None, {'route_excluded': []}, unit, data).encode('utf-8'))
        if size > BRIEF_BUDGET:
            oversized.append('%s %d bytes' % (oid, size))
    return oversized and ['single-object briefs over the %d byte budget: %s'
                          % (BRIEF_BUDGET, ', '.join(oversized))]


@check('vocabulary-documented')
def vocabulary_documented():
    """The enumerations the records accept are the ones the documents teach."""
    # PRIMITIVES is left to `primitive-table`, which requires each one inside the
    # definition table in method.md rather than anywhere in the docs.
    from units import CROSS_TYPES, DEPTHS, DIMENSIONS, EXPOSURES
    text = docs_text()
    problems = []
    for label, values in (('exposure', EXPOSURES),
                          ('depth', DEPTHS), ('cross type', CROSS_TYPES),
                          ('analysis dimension', DIMENSIONS)):
        # Whole-token match, not containment: renaming INJECT to INJECTX leaves the
        # substring in place, so a containment check stays green through exactly the
        # drift it exists to catch.
        missing = [v for v in values if v != 'unknown'
                   and not re.search(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % re.escape(v), text)]
        if missing:
            problems.append('%s values no document mentions: %s' % (label, ', '.join(missing)))
    return problems


@check('attack-entry-routing')
def attack_entry_routing():
    """Entry-type definitions reach every classifier and the generated unit brief.

    Check the enum/table and link targets, not the meaning of the prose. The latter
    remains the reviewer's job. Exercise both generated consumers so checking the
    static role files cannot hide a stale decision prompt or a lost rationale.
    """
    import tempfile
    from units import EXPOSURES, pending_decisions, write_brief

    problems = []
    definition = SKILL / 'references' / 'method.md'
    fragment = 'attack-entry-types'
    source = read_text(definition)
    anchor = '<a id="%s"></a>' % fragment
    if source.count(anchor) != 1:
        return ['entry-type definition needs one unambiguous anchor: ' + fragment]
    section = re.split(r'^## ', source.split(anchor, 1)[1], flags=re.M)
    body = section[1] if len(section) > 1 else ''
    values = re.findall(r'^\|\s*`([A-Za-z_]+)`\s*\|', body, re.M)
    expected = [v for v in EXPOSURES if v != 'unknown']
    if sorted(values) != sorted(expected):
        problems.append('entry-type table differs from the classified values: ' + repr(values))

    def has_definition_link(text, base):
        for destination in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', text):
            path, _, anchor_id = destination.strip('<>').partition('#')
            if anchor_id == fragment and (base / path).resolve() == definition.resolve():
                return True
        return False

    for rel in ('SKILL.md', 'references/orchestration.md', 'references/records.md',
                'references/report-format.md', 'references/roles/worker.md',
                'references/roles/reviewer.md', 'references/roles/queue_critic.md',
                'references/roles/report_writer.md'):
        path = SKILL / rel
        if not has_definition_link(read_text(path), path.parent):
            problems.append(rel + ': no working link to the common entry-type definition')

    with tempfile.TemporaryDirectory(prefix='audit-entry-routing-') as tmp:
        workspace, state = root_cause_fixture(tmp)
        unit = state['units'][0]
        unit['exposure'] = 'unknown'
        questions = [d for d in pending_decisions(workspace, state)
                     if d['kind'] == 'exposure' and d['subject'] == unit['id']]
        if len(questions) != 1 or not has_definition_link(questions[0]['question'], SKILL):
            problems.append('generated exposure question does not reach the definition')
        unit['exposure'] = 'ADJ'
        unit['exposure_reason'] = '需要位于专用网络；本条为该单元的分类依据。'
        before = json.dumps(state, ensure_ascii=False, sort_keys=True)
        result = write_brief(workspace, state, unit, '', None)
        brief = read_text(result['brief'])
        if not has_definition_link(brief, Path(result['brief']).parent):
            problems.append('generated unit brief does not reach the definition')
        if unit['exposure_reason'] not in brief:
            problems.append('generated unit brief lost the recorded classification basis')
        if json.dumps(state, ensure_ascii=False, sort_keys=True) != before:
            problems.append('writing the unit brief changed the audit record')
    return problems


@check('primitive-table')
def primitive_table():
    """Each attack primitive has its own row in the definition table.

    A value mentioned somewhere is not enough: the primitives are also quoted twice
    in the chain-candidate text, so a containment check stays green when the table row
    itself is renamed. The row is the definition; anchor on it, not on a restatement.
    """
    from units import PRIMITIVES
    lines = [line for line in read_text(SKILL / 'references' / 'method.md').splitlines()
             if line.startswith('|')]
    missing = [value for value in PRIMITIVES
               if not any('`%s`' % value in line for line in lines)]
    return missing and ['attack primitives without a row in the definition table of '
                        'references/method.md: ' + ', '.join(missing)]


@check('command-surface-routed')
def command_surface_routed():
    """Every subcommand and option is named somewhere a reader is told to use it.

    The general form of the verdict that had no landing place: a capability nobody routes
    is dead weight, and nobody notices because nothing fails. Enumerated from the parser
    object rather than from the source text, so adding an option cannot slip past by
    being written in a shape a regex did not expect.

    What this does NOT claim: that each one is explained in prose. A mention inside a
    command example counts, and twelve options are documented only that way — several of
    them are self-evident from the line they appear in. The failure guarded against is a
    capability with no landing place at all, which is what the verdict with no route was.
    Requiring prose for every flag is a different rule with much weaker returns.
    """
    sys.path.insert(0, str(SKILL / 'scripts'))
    import audit
    parser = audit.build_parser()
    commands = list([a for a in parser._actions if a.dest == 'command'][0].choices)
    options = sorted({o for a in parser._actions for o in a.option_strings
                      if o.startswith('--')})
    prose = '\n'.join(p.read_text(encoding='utf-8') for p in sorted(SKILL.rglob('*.md')))
    problems = []
    orphan_commands = [c for c in commands if not re.search(r'\b%s\b' % re.escape(c), prose)]
    orphan_options = [o for o in options if o not in prose]
    if orphan_commands:
        problems.append('subcommands no document ever mentions: ' + ', '.join(orphan_commands))
    if orphan_options:
        problems.append('options no document ever mentions: ' + ', '.join(orphan_options))
    return problems


@check('documented-cli-commands')
def documented_cli_commands():
    """Shell examples name commands from the actual parser; no shell is executed."""
    import shlex
    from audit import build_parser
    commands = next(a.choices for a in build_parser()._actions if a.dest == 'command')
    problems = []
    for path in DOCS:
        for block in re.findall(r'```(?:bash|sh|shell)\s*\n(.*?)```', read_text(path), re.S):
            for line in block.replace('\\\n', ' ').splitlines():
                try:
                    words = shlex.split(line, comments=True)
                except ValueError as exc:
                    problems.append('%s: malformed shell example: %s' % (path.name, exc))
                    continue
                for index, word in enumerate(words[:-1]):
                    if (word == 'audit.py' or word.endswith('/audit.py')) and words[index + 1] not in commands:
                        problems.append('%s: unknown audit.py command %s'
                                        % (path.name, words[index + 1]))
    return problems


@check('local-check-example')
def local_check_example():
    """The worker's local-check example has the same fields as an actual seed."""
    from audit import new_check
    from records import STATUSES, VERDICTS, SCOPES
    text = read_text(SKILL / 'references' / 'roles' / 'worker.md')
    examples = []
    problems = []
    for block in re.findall(r'```json\s*\n(.*?)```', text, re.S):
        try:
            row = json.loads(block)
        except ValueError as exc:
            problems.append('worker.md: malformed JSON example: ' + str(exc))
            continue
        if isinstance(row, dict) and 'local_definition' in row:
            examples.append(row)
    if not examples:
        return problems + ['worker.md: no complete local-check example']
    for row in examples:
        definition = row.get('local_definition') or {}
        if not all(definition.get(k) for k in ('statement', 'requirement')):
            problems.append('worker.md: incomplete local definition')
            continue
        expected = new_check('CHK-example', 'INST-example', dict(definition, id=None), 'baseline')
        missing = sorted(set(expected) - set(row))
        if missing:
            problems.append('worker.md: local check is missing fields: ' + ', '.join(missing))
        for field, key in (('prerequisites', 'condition'), ('criteria', 'criterion')):
            conditions = row.get(field, [])
            if not isinstance(conditions, list):
                problems.append('worker.md: %s must be an array' % field)
                continue
            for condition in conditions:
                if (not isinstance(condition, dict)
                        or set(condition) != {key, 'state', 'evidence_ids'}
                        or not isinstance(condition.get(key), str) or not condition[key].strip()
                        or condition.get('state') not in {'unknown', 'met', 'not_met'}
                        or not isinstance(condition.get('evidence_ids'), list)):
                    problems.append('worker.md: invalid %s row shape/state' % field)
        if (row.get('status') not in STATUSES
                or row.get('verdict') not in VERDICTS | {None}
                or row.get('applicability') not in {'unknown', 'applicable', 'not_applicable'}
                or not isinstance(row.get('scope'), list)
                or set(row.get('scope') or []) - SCOPES):
            problems.append('worker.md: invalid local-check enum or scope')
    return problems


@check('errors-go-to-stderr')
def errors_go_to_stderr():
    """Results on stdout, errors on stderr — in every script, not just most of them.

    `audit.py` has always done this; three scripts added later printed their errors on
    stdout instead, so the same class of failure arrived on a different stream depending
    on which guard caught it. An orchestrator that parses stdout then reads an error as a
    result, and one that reads stderr misses it. Found by a test of mine tripping on it.
    """
    problems = []
    for path in sorted((SKILL / 'scripts').glob('*.py')):
        source = read_text(path)
        for match in re.finditer(r"print\(json\.dumps\(\{'error'", source):
            line_no = source[:match.start()].count('\n') + 1
            # The call may wrap, so look at the statement rather than the one line.
            tail = source[match.start():match.start() + 400].split('\n\n')[0]
            statement = tail.split(')\n')[0]
            if 'sys.stderr' not in statement:
                problems.append('%s:%d prints an error on stdout' % (path.name, line_no))
    return problems


@check('collections-documented')
def collections_documented():
    """Every collection in the record is described where the record format is documented.

    Six were added in one stretch and none of them reached `records.md`, which is the
    only place a worker or a reviewer can learn what a field means. An undocumented
    collection gets filled by guesswork or left empty, and an empty one reads exactly
    like a rule that did not apply.
    """
    import audit
    from merge import COLLECTIONS
    doc = read_text(SKILL / 'references' / 'records.md')
    known = list(dict.fromkeys(list(COLLECTIONS) + list(audit.SCHEDULING_COLLECTIONS)
                               + ['reviews', 'withdrawn_reviews', 'reconciliations',
                                  'object_scope', 'materials', 'coverage', 'queue',
                                  'root_causes']))
    # Defined by a section instead of a named row: `## 检查及判定` carries `checks`, the
    # 证据记录示例 block carries `evidence`, and the legacy note inside the `clusters`
    # row carries `artifacts`. They are named here as exceptions so the strict path stays
    # the default — a collection added later needs a definition of its own.
    prose_defined = {'checks', 'evidence', 'artifacts'}
    problems = []
    missing, buried = [], []
    for name in known:
        token = '`%s`' % name
        if token not in doc:
            missing.append(name)
        elif name in prose_defined:
            continue
        # Containment alone is too weak: a cross-reference elsewhere on the page keeps the
        # name present after its definition is deleted. Measured — dropping the
        # `root_causes` row left two mentions behind (the 1.7 migration note and the
        # finding field list) and this check stayed green through exactly the loss it
        # exists to catch. A definition sits at a cell or line boundary; a
        # cross-reference, being mid-sentence, does not.
        elif not (re.search(r'^\|[^|\n]*%s[^|\n]*\|' % re.escape(token), doc, re.M)
                  or re.search(r'^%s' % re.escape(token), doc, re.M)):
            buried.append(name)
    if missing:
        problems.append('records.md does not describe: ' + ', '.join(missing))
    if buried:
        problems.append('records.md only cross-references, never defines: ' + ', '.join(buried))
    # The record version is stated in two places. It was documented as 1.2 while the
    # code had moved to 1.4, which is the kind of drift that makes a reader mistrust
    # everything else on the page.
    # Anchored on the sentence that states it, not on the version string: the migration
    # notes on the same page mention each version too, so a bare search stays green while
    # the stated version goes stale.
    stated = re.search(r'目标记录版本为`([0-9.]+)`', doc)
    if not stated:
        problems.append('records.md does not state the record version at all')
    elif stated.group(1) != audit.SCHEMA_VERSION:
        problems.append('records.md states record version %s, the code is at %s'
                        % (stated.group(1), audit.SCHEMA_VERSION))
    return problems


@check('schema-version-ladder')
def schema_version_ladder():
    """Every record version the documents still name is one this release can open.

    `MIGRATABLE` is what `refresh` accepts, and the guard rejects anything outside it
    plus `SCHEMA_VERSION` before the migration path gets a chance to run. So bumping the
    version without extending the ladder turns every existing workspace into an
    unrecognized record — refused even by the one command that exists to migrate it.
    Nothing was watching that pair.
    """
    import audit
    doc = read_text(SKILL / 'references' / 'records.md')
    openable = set(audit.MIGRATABLE) | {audit.SCHEMA_VERSION}
    problems = []
    if audit.SCHEMA_VERSION in audit.MIGRATABLE:
        problems.append('the current version is also listed as migratable from: '
                        + audit.SCHEMA_VERSION)
    ordered = sorted(audit.MIGRATABLE, key=lambda v: [int(part) for part in v.split('.')])
    if list(audit.MIGRATABLE) != ordered:
        problems.append('MIGRATABLE is not in ascending order: ' + ', '.join(audit.MIGRATABLE))
    # Only the versions the page itself still names. The other direction is not a defect:
    # a version no document mentions may stay openable.
    stranded = sorted(set(re.findall(r'`([0-9]+\.[0-9]+)`', doc)) - openable)
    if stranded:
        problems.append('records.md names versions refresh would refuse: ' + ', '.join(stranded))
    major, minor = (int(part) for part in audit.SCHEMA_VERSION.split('.'))
    if minor and ('%d.%d' % (major, minor - 1)) not in openable:
        problems.append('the version right below %s cannot be opened, so every existing '
                        'record would be unrecognized' % audit.SCHEMA_VERSION)
    # A version named in any other document always means 「the contract in force」, and
    # the next bump makes that sentence false while it still reads as if it were true.
    # Measured: report_writer.md said 「不宣称已按 1.6 验证」, which after the bump told the
    # writer not to claim the one contract a migrated record legitimately carries. The
    # lookbehind also excludes letters, so framework object ids like `A1.2` are not
    # versions. records.md is the single place that states it.
    for path in [SKILL / 'SKILL.md'] + sorted((SKILL / 'references').rglob('*.md')):
        if path.name == 'records.md':
            continue
        text = read_text(path)
        named = sorted(version for version in openable
                       if re.search(r'(?<![0-9A-Za-z.])%s(?![0-9])' % re.escape(version), text))
        if named:
            problems.append('%s writes the record contract version (%s) into prose; only '
                            'records.md states it, everything else says 「当前记录契约」'
                            % (path.name, ', '.join(named)))
    return problems


@check('dimension-glossary')
def dimension_glossary():
    """Each analysis dimension names the one method.md section that defines it.

    `vocabulary-documented` only asks whether the name appears somewhere, so a gloss can
    drift while staying green. Measured: worker.md taught `lateral` as lateral movement
    while method.md's section of that name is the sibling-operation sweep — and the sweep
    is where 「按共同根因归并发现」 lives. The executor reads worker.md and nothing else
    of the protocol, so that instruction had no carrier, and 48 of 48 units reported the
    dimension done. Three copies have to agree: the section titles in method.md, the
    glosses in orchestration.md, and the method column of worker.md's table.
    """
    from units import DIMENSIONS
    sections = re.findall(r'^### (.+)$', read_text(SKILL / 'references' / 'method.md'), re.M)
    protocol = read_text(SKILL / 'references' / 'orchestration.md')
    worker = read_text(SKILL / 'references' / 'roles' / 'worker.md')
    problems = []
    glossed = {}
    for name in DIMENSIONS:
        gloss = re.search('`%s`（([^）]+)）' % re.escape(name), protocol)
        if not gloss:
            problems.append('orchestration.md does not say which method %s is' % name)
            continue
        title = gloss.group(1)
        glossed[name] = title
        if title not in sections:
            problems.append('%s is glossed 「%s」, which is no section in method.md'
                            % (name, title))
        row = re.search(r'^\| `%s` \|([^\n]*)$' % re.escape(name), worker, re.M)
        if not row:
            problems.append("worker.md's dimension table gives no method for " + name)
            continue
        stated = row.group(1).split('|')[0].strip()
        if stated != title:
            problems.append('%s: worker.md says 「%s」, orchestration.md says 「%s」'
                            % (name, stated, title))
        # A second method name in the same row makes two readings available, which is the
        # drift this check exists to stop, one cell further in.
        for other in sections:
            if other != title and other in row.group(1):
                problems.append('%s names two methods: 「%s」 and 「%s」'
                                % (name, title, other))
    if len(set(glossed.values())) != len(glossed):
        problems.append('two dimensions are glossed as the same method: '
                        + ', '.join('%s=%s' % pair for pair in sorted(glossed.items())))
    return problems


@check('review-subject-ignores-grouping')
def review_subject_ignores_grouping():
    """Filing a finding under its root cause does not stale the review bound to it.

    The digest a review is bound to covers the finding record, so a field added after the
    review invalidates it. Measured: setting `root_cause_id` on one finding of a real
    227-finding record turned `validate` into 「review is stale or does not retain
    finding」. Grouping is not part of what a reviewer judged, and 227 withdrawals to
    record a pointer buys nothing. Asserted by calling the digest rather than by reading
    its exclusion set — the set is only one of the ways to get this wrong — and in both
    directions, so widening the set until everything is excluded fails too.
    """
    from review import subject_digest
    finding = {'id': 'F-X-01', 'check_ids': [], 'evidence_ids': [], 'status': 'current',
               'title': 't', 'mechanism': 'm', 'severity': 'low'}
    state = {'checks': [], 'evidence': []}
    plain = subject_digest(state, finding)
    problems = []
    if plain != subject_digest(state, dict(finding, root_cause_id='RC-01')):
        problems.append('a root cause annotation moves the review subject digest, so '
                        'grouping would stale every review it touches')
    for key, value in (('mechanism', 'something else'), ('severity', 'high')):
        if plain == subject_digest(state, dict(finding, **{key: value})):
            problems.append('the review subject digest ignores %s, which is exactly what '
                            'it exists to bind' % key)
    return problems


@check('record-shape-rules')
def record_shape_rules():
    """Each 1.7 field rule fires on a record that violates just that rule.

    `validate` is where a record's shape gets judged, and nothing was judging `validate`:
    deleting any one of its `require` lines left every check in here green. So these
    cases drive the real validator over a throwaway workspace. A freshly initialized
    record must pass, and each violation must produce its own named message — a rule
    cannot be deleted, nor widened until it never fires, without this going red. Other
    errors from the same run are ignored on purpose: the assertion is that the named rule
    fires, not that the fixture is complete in every other respect.
    """
    import copy
    import tempfile
    from pathlib import Path
    import audit
    import records
    from units import new_unit
    cause = {'id': 'RC-01', 'verdict': 'merge', 'statement': 's', 'fix_point': 'f',
             'by': 'b', 'reason': 'r', 'finding_ids': ['F-AA01-01', 'F-AA01-02'],
             'member_paths': [{'finding_id': 'F-AA01-01', 'location': 'l', 'difference': 'd'},
                              {'finding_id': 'F-AA01-02', 'location': 'l', 'difference': 'd'}]}
    member = {'check_ids': [], 'evidence_ids': [], 'status': 'needs_review',
              'severity': 'low'}
    reviewed = {'status': 'reviewed', 'reason': 'r', 'analysis_method': 'm',
                'limitations': 'l', 'check_ids': []}
    cases = [
        ('a reserve that swallows the whole limit',
         lambda s: s['queue'].update(dispatch_capacity={'limit': 4, 'reserve': 4, 'source': 'x'}),
         'reserves every slot'),
        ('a limit that is not a whole number',
         lambda s: s['queue'].update(dispatch_capacity={'limit': '4', 'reserve': 0, 'source': 'x'}),
         'dispatch_capacity.limit'),
        ('a capacity with no provenance',
         lambda s: s['queue'].update(dispatch_capacity={'limit': 4, 'reserve': 0}),
         'needs its source'),
        ('a clustering decision that is neither needed nor not_needed',
         lambda s: s['queue'].update(cluster_scope={'decision': 'maybe', 'reason': 'r'}),
         'needed or not_needed'),
        ('a clustering decision with no reason',
         lambda s: s['queue'].update(cluster_scope={'decision': 'needed', 'reason': '  '}),
         'cluster_scope needs its reason'),
        ('a root cause that groups a single finding',
         lambda s: s.update(root_causes=[dict(cause, finding_ids=['F-AA01-01'])]),
         'at least two findings'),
        ('finding_ids written as a scalar',
         lambda s: s.update(root_causes=[dict(cause, finding_ids='F-AA01-01')]),
         'finding_ids is a list'),
        ('a dispatch wave numbered zero',
         lambda s: s['units'].append(new_unit('U-AA01', 'repo_shard', 't', wave=0,
                                              mapping_note='n')),
         'dispatch wave is a positive integer'),
        ('a no_check_reason that is not prose',
         lambda s: s['coverage'].append({'id': 'COV-AA01-01', 'status': 'not_started',
                                         'material_ids': [], 'no_check_reason': 7}),
         'no_check_reason is prose'),
        ('a root_cause_id pointing at nothing',
         lambda s: s['findings'].append({'id': 'F-AA01-01', 'check_ids': [], 'evidence_ids': [],
                                         'status': 'needs_review', 'severity': 'low',
                                         'root_cause_id': 'RC-99'}),
         'points at no recorded root cause'),
        ('reviewed coverage with neither checks nor a reason for having none',
         lambda s: s['coverage'].append(dict(reviewed, id='COV-AA01-01',
                                             material_ids=list(s['materials'])[:1])),
         'proposition destination'),
        ('a root cause with no verdict',
         lambda s: s.update(root_causes=[{k: v for k, v in cause.items() if k != 'verdict'}]),
         'verdict is merge or distinct'),
        ('a merged cluster of two carrying one affected path',
         lambda s: s.update(root_causes=[dict(cause, member_paths=cause['member_paths'][:1])]),
         'one affected path per member'),
        ('an affected path that does not say how that member differs',
         lambda s: s.update(root_causes=[dict(cause, member_paths=[
             cause['member_paths'][0], dict(cause['member_paths'][1], difference='  ')])]),
         'affected path needs difference'),
        ('a merge whose member never links back',
         lambda s: (s.update(root_causes=[dict(cause)]),
                    s['findings'].extend([dict(member, id='F-AA01-01', root_cause_id='RC-01'),
                                          dict(member, id='F-AA01-02', root_cause_id=None)])),
         'does not link back'),
        ('a distinct adjudication dressed as a root cause',
         lambda s: s.update(root_causes=[dict(cause, verdict='distinct', member_paths=[])]),
         'carries no statement'),
    ]
    # Shapes the validator must stay silent on. A rule that fires on the legitimate shape
    # is the same defect as one that never fires, and grandfathering is only real if
    # something breaks when it is taken away.
    tolerated = [
        ('reviewed coverage that says why it produced no check',
         lambda s: s['coverage'].append(dict(reviewed, id='COV-AA01-02',
                                             material_ids=list(s['materials'])[:1],
                                             no_check_reason='纯二进制资源，不产生命题结论')),
         'proposition destination'),
        ('coverage a unit wrote before the rule existed',
         lambda s: (s['units'].append(new_unit('U-AA01', 'repo_shard', 't', mapping_note='n',
                                               legacy_schema_version='1.6')),
                    s['coverage'].append(dict(reviewed, id='COV-AA01-03',
                                              material_ids=list(s['materials'])[:1]))),
         'proposition destination'),
        ('a complete merge whose members link back',
         lambda s: (s.update(root_causes=[dict(cause)]),
                    s['findings'].extend([dict(member, id='F-AA01-01', root_cause_id='RC-01'),
                                          dict(member, id='F-AA01-02', root_cause_id='RC-01')])),
         'RC-01'),
        ('a distinct adjudication carrying nothing but its reason',
         lambda s: s.update(root_causes=[{'id': 'RC-02', 'verdict': 'distinct', 'by': 'b',
                                          'reason': '同名命题，两个模块各自缺一次',
                                          'finding_ids': ['F-AA01-01', 'F-AA01-02']}]),
         'carries no'),
    ]
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        workspace, target = Path(tmp) / 'ws', Path(tmp) / 'target'
        target.mkdir()
        (target / 'a.md').write_text('x', encoding='utf-8')
        audit.initialize(workspace, 'shape-probe', ['repo=' + str(target)], [])
        clean = audit.read(workspace / 'audit.json')
        stray = records.validate(workspace, clean)
        if stray:
            problems.append('a freshly initialized record does not validate: '
                            + '; '.join(stray[:2]))
        for desc, break_it, expected in cases:
            state = copy.deepcopy(clean)
            break_it(state)
            if not any(expected in error for error in records.validate(workspace, state)):
                problems.append('validate stays silent on %s (expected 「%s」)'
                                % (desc, expected))
        for desc, arrange, forbidden in tolerated:
            state = copy.deepcopy(clean)
            arrange(state)
            objected = [error for error in records.validate(workspace, state)
                        if forbidden in error]
            if objected:
                problems.append('validate objects to %s: %s' % (desc, objected[0]))
    return problems


@check('dispatch-capacity-budget')
def dispatch_capacity_budget():
    """The dispatch ceiling resolves from the right place and the wave arithmetic holds.

    The ceiling is the host's, not this skill's: read from the environment when it is set,
    and from the documented default when it is not. A wave is counted against the units
    still out rather than against itself, because the ceiling is on what runs at once.
    Both directions are asserted — a budget that never refuses is the same as no budget —
    and the default is pinned to the number records.md states, because a reader who
    cannot find it will assume a different one.
    """
    import os
    import audit
    problems = []
    doc = read_text(SKILL / 'references' / 'records.md')
    if not re.search(r'默认\s*%d(?![0-9])' % audit.HOST_SUBAGENT_LIMIT, doc):
        problems.append('records.md does not state the host default (%d) with the field'
                        % audit.HOST_SUBAGENT_LIMIT)
    if audit.HOST_SUBAGENT_LIMIT_ENV not in doc:
        problems.append('records.md does not name the environment variable that overrides it')
    saved = os.environ.get(audit.HOST_SUBAGENT_LIMIT_ENV)
    try:
        os.environ.pop(audit.HOST_SUBAGENT_LIMIT_ENV, None)
        unset = audit.dispatch_capacity({})
        os.environ[audit.HOST_SUBAGENT_LIMIT_ENV] = '8'
        configured = audit.dispatch_capacity({})
    finally:
        os.environ.pop(audit.HOST_SUBAGENT_LIMIT_ENV, None)
        if saved is not None:
            os.environ[audit.HOST_SUBAGENT_LIMIT_ENV] = saved
    if (unset['limit'], unset['source']) != (audit.HOST_SUBAGENT_LIMIT, 'host_default'):
        problems.append('an unset environment does not fall back to the host default: %r'
                        % unset)
    if (configured['limit'], configured['source']) != (8, 'env'):
        problems.append('a ceiling set in the environment is not read from it: %r' % configured)
    recorded = {'queue': {'dispatch_capacity': {'limit': 10, 'reserve': 2, 'source': 'user'}}}
    if audit.dispatch_capacity(recorded)['limit'] != 10:
        problems.append('a capacity already on the record does not win over the default')
    # Filled to one short of the budget: a wave of three fits, and one more unit in flight
    # makes the same wave overflow.
    budget = audit.HOST_SUBAGENT_LIMIT - audit.DEFAULT_DISPATCH_RESERVE
    flight = [{'id': 'U-X%03d' % n, 'status': 'dispatched'} for n in range(budget - 3)]
    wave = ['U-A01', 'U-A02', 'U-A03']
    if audit.wave_overflow({'units': flight}, wave) is not None:
        problems.append('a wave that fits the budget is refused')
    if audit.wave_overflow({'units': flight + [{'id': 'U-X999', 'status': 'dispatched'}]},
                           wave) is None:
        problems.append('a wave over the budget is admitted, so the ceiling never bites')
    # Re-dispatching a unit that is already out must not count it twice.
    if audit.wave_overflow({'units': flight + [{'id': 'U-A01', 'status': 'dispatched'}]},
                           wave) is not None:
        problems.append('a unit being re-dispatched is counted twice against the budget')
    return problems


@check('dispatch-status-accounting')
def dispatch_status_accounting():
    """The reconciliation attributes each unit to the round it is in now, exactly once.

    A re-dispatched unit stays in the old round's `unit_ids`, so attributing its current
    status to every round that ever dispatched it shows one unit as outstanding twice —
    measured on a real record — and charges its slot twice against the ceiling. The whole
    value of this view is 「这一波派了几个、回了几个、还差谁」, which a double count
    destroys. Rolled-back units have to read as deferred, not as still running, or a
    refused launch keeps looking like work in progress.
    """
    import audit
    state = {'queue': {'dispatch_capacity': {'limit': 10, 'reserve': 2, 'source': 'user'}},
             'units': [{'id': 'U-AA01', 'status': 'merged', 'round': 1, 'wave': 1},
                       {'id': 'U-BB01', 'status': 'dispatched', 'round': 2, 'wave': 1},
                       {'id': 'U-CC01', 'status': 'planned', 'round': 2, 'wave': None}],
             'rounds': [{'n': 1, 'unit_ids': ['U-AA01', 'U-BB01'], 'returns': []},
                        {'n': 2, 'unit_ids': ['U-BB01', 'U-CC01'], 'returns': []}]}
    status = audit.dispatch_status(state)
    rows = {row['round']: row for row in status['rounds']}
    problems = []
    def bucket(round_number, name):
        return sorted(uid for wave in rows[round_number]['waves'] for uid in wave[name])
    if bucket(1, 'outstanding'):
        problems.append('a unit re-dispatched into a later round still counts as '
                         'outstanding in the earlier one: ' + ', '.join(bucket(1, 'outstanding')))
    if rows[1]['redispatched_later'] != ['U-BB01'] or rows[1]['dispatched'] != 1:
        problems.append('the earlier round does not report the unit as moved on: %r' % rows[1])
    if bucket(2, 'outstanding') != ['U-BB01']:
        problems.append('the round a unit is in now does not count it as outstanding')
    if bucket(2, 'deferred') != ['U-CC01']:
        problems.append('a unit rolled back to planned does not read as deferred')
    if status['in_flight'] != 1 or status['in_flight_units'] != ['U-BB01']:
        problems.append('in flight is not one slot per unit: %r' % status['in_flight_units'])
    if status['dispatchable_now'] != 10 - 2 - 1:
        problems.append('what is dispatchable now does not follow limit - reserve - in flight')
    return problems


@check('evidence-semantics')
def evidence_semantics():
    """The sampling lexicon loads, compiles, and answers both ways on sample observations.

    This file decides which evidence gets asked「它是否还支持别的失效机制」, so one broken
    regex or one empty group silently empties the list and the question stops being asked
    with nothing turning red. Sampled in both directions, and on the co-occurrence itself:
    the observation that was actually missed has to be picked up, an observation that says
    the input was escaped must not be, and one group alone must not be enough.
    """
    from knowledge import read as read_json
    spec = read_json(SKILL / 'references' / 'evidence_semantics.json')
    problems = []
    groups = {}
    for name in ('construction', 'boundary'):
        patterns = spec.get(name) or []
        if not patterns:
            problems.append('%s is empty, so nothing can ever co-occur' % name)
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.I))
            except re.error as exc:
                problems.append('%s: %s does not compile (%s)' % (name, pattern, exc))
        groups[name] = compiled
    if problems:
        # The shipped file is broken; the real sampler compiles the same patterns and
        # would raise on the same line, which reads as 「the check itself could not run」
        # instead of naming the pattern.
        return problems

    # Driven through the real sampler, not through a copy of its rule written in here:
    # a second implementation agrees with itself no matter what the shipped one does, so
    # changing `made and crossed` to `made or crossed` would leave this green.
    from review_prepare import evidence_leads

    def sampled(text):
        product = {'evidence': [{'id': 'E-AA01-001', 'kind': 'code', 'observation': text}],
                   'checks': [{'id': 'CHK-AA01-0001', 'evidence_ids': ['E-AA01-001']}]}
        return bool(evidence_leads({'checks': [], 'evidence': []}, product))

    missed = ('buildDockerExecArgs 把每个 env 条目作为 argv 里的 -e KEY=VALUE 传入 docker exec，'
              '并把 env.PATH 未转义地拼进 export PATH="...:$PATH"; 后接模型 command，'
              '由容器内 sh -lc 解释。')
    escaped = '该函数读取配置后调用 exec 工具，参数在上游已按白名单校验并逐项转义。'
    one_group = '配置项被原样写入 JSON 快照文件。'
    if not sampled(missed):
        problems.append('the observation this exists for is not sampled: an unescaped splice '
                        'into a shell is the case that reached no proposition')
    if sampled(escaped):
        problems.append('an observation stating the input was escaped is sampled anyway, so '
                        'the list fills with items nobody needs to answer')
    if sampled(one_group):
        problems.append('one group alone is enough, so co-occurrence is not being required')
    return problems


@check('evidence-lead-closure')
def evidence_lead_closure():
    """A lead is raised once and closes the three ways the record already provides.

    Without a closure the question becomes a line of prose nobody can show they answered;
    with the wrong one it reopens every run. All three answers are already recorded
    elsewhere, so none of them needs a collection of its own: a second check citing the
    same evidence drops it from the sample, and naming the evidence id in `method_notes`
    or in a `crosslead` marks it answered.
    """
    from review_prepare import evidence_leads
    observation = ('env.PATH 未转义地拼进 export PATH 后接模型 command，由容器内 sh -lc 解释。')

    def product(**extra):
        return {'evidence': [{'id': 'E-AA01-012', 'kind': 'code', 'observation': observation}],
                'checks': [{'id': 'CHK-AA01-0010', 'evidence_ids': ['E-AA01-012']}], **extra}

    state = {'checks': [], 'evidence': []}
    problems = []
    leads = evidence_leads(state, product())
    if [lead['evidence_id'] for lead in leads] != ['E-AA01-012'] or not leads[0]['open']:
        problems.append('evidence cited by exactly one check is not raised as an open lead: %r'
                        % leads)
    twice = product()
    twice['checks'].append({'id': 'CHK-AA01-0901', 'evidence_ids': ['E-AA01-012']})
    if evidence_leads(state, twice):
        problems.append('a second check citing the same evidence leaves it on the list')
    for key, value in (('method_notes',
                        ['E-AA01-012 的 PATH 插值由上游白名单限定，不另立检查']),
                       ('crossleads',
                        [{'note': 'E-AA01-012 的另一端在 U-BB01', 'to_unit': 'U-BB01'}])):
        answered = evidence_leads(state, product(**{key: value}))
        if not answered or answered[0]['open']:
            problems.append('naming the evidence in %s does not close the lead' % key)
    design = product()
    design['evidence'][0]['kind'] = 'design'
    if evidence_leads(state, design):
        problems.append('a design-level observation is sampled, though the sample is code')
    return problems


@check('rootcause-candidates')
def rootcause_candidates():
    """The two signals produce the leads they claim, and the strong slice stays tight.

    Measured on a 227-finding audit: 63 proposition families hold at least two findings
    and 375 pairs share an identical evidence location, while only 47 member sets are
    strong. The strong slice is G9's denominator, so both thresholds are asserted in both
    directions, from one notch below each — widen either and the gate starts demanding
    232 adjudications instead of 47.
    """
    import copy
    import tempfile
    from rootcause import candidates, no_proposition
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        _, state = root_cause_fixture(tmp)
        rows = {row['key']: row for row in candidates(state)}
        family, pair = rows.get('fm:FM-A1.1-01'), rows.get('set:F-AA01-01+F-BB01-01')
        if family is None:
            problems.append('a proposition shared by three findings produced no candidate')
        elif family['finding_ids'] != ['F-AA01-01', 'F-BB01-01', 'F-CC01-01']:
            problems.append('the proposition family has the wrong members: '
                            + ', '.join(family['finding_ids']))
        elif not family['strong']:
            problems.append('three findings across three units is not reported as strong')
        if pair is None:
            problems.append('two findings citing three identical locations produced no candidate')
        elif not pair['strong']:
            problems.append('a member set sharing three identical locations is not strong')
        elif not any('3 处完全相同的证据位置' in basis for basis in pair['basis']):
            problems.append('the location candidate does not say what it found: '
                            + '; '.join(pair['basis']))
        local = no_proposition(state, list(rows.values()))
        if local['finding_ids'] != ['F-CC01-02'] or local['unpaired'] != ['F-CC01-02']:
            problems.append('the findings no proposition can see are reported wrong: %s'
                            % local)
        # The other direction, and it sits one notch below each threshold on purpose:
        # two units, two shared locations. Widening either one by a single step makes
        # this strong, which is how the first version of this check let a lowered
        # threshold through — it was two notches away and nothing moved.
        narrowed = copy.deepcopy(state)
        for check in narrowed['checks']:
            if check['id'] == 'CHK-CC01-0001':
                check['failure_mode_id'] = None
        for finding in narrowed['findings']:
            if finding['id'] == 'F-BB01-01':
                finding['evidence_ids'] = ['E-BB01-001', 'E-BB01-002']
        weak = [row for row in candidates(narrowed) if row['strong']]
        if weak:
            problems.append('a family spanning two units and sharing two locations is '
                            'reported strong: ' + ', '.join(row['key'] for row in weak))
        if len([row for row in candidates(narrowed) if row['key'].startswith('fm:')]) != 1:
            problems.append('a proposition only one finding refers to produced a candidate')
    return problems


@check('rootcause-closure')
def rootcause_closure():
    """G9 counts adjudications over the strong slice, and nothing else.

    Drives the real gate. An unanswered strong candidate fails; an adjudication that
    names the candidate but leaves one of its members unaccounted for fails (that is the
    「归并不丢路径」 half, and it is the shape the report todos actually took — a merge
    requirement answered for some of the findings it named); answering both closes it.

    The grandfathering is asserted at the unit, not the workspace: a cold-start reviewer
    ran this on a migrated 48-unit workspace, left 39 strong candidates unanswered, and
    the gate passed — because the first version skipped the whole row on
    `queue.legacy_freeze_contract`, which a migration sets for good. So the
    workspace-level marker alone must NOT exempt anything, a candidate all of whose
    members sit in old-contract units must skip and say it checked nothing, and one
    member in a unit merged since must bring the row back.
    """
    import copy
    import tempfile
    from gate import evaluate

    def g9(workspace, state):
        return next(row for row in evaluate(workspace, state) if row['id'] == 'G9')
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        workspace, clean = root_cause_fixture(tmp)
        unanswered = g9(workspace, clean)
        if unanswered['status'] != 'fail' or '强候选' not in unanswered['detail']:
            problems.append('an unadjudicated strong candidate does not fail G9: %s'
                            % unanswered)
        dropped = g9(workspace, linked(copy.deepcopy(clean), [copy.deepcopy(MERGE)]))
        if dropped['status'] != 'fail' or '漏下成员' not in dropped['detail']:
            problems.append('a merge that drops a member of the candidate it answers '
                            'passes G9: %s' % dropped)
        settled = linked(copy.deepcopy(clean), [
            dict(copy.deepcopy(MERGE),
                 candidates=['fm:FM-A1.1-01', 'set:F-AA01-01+F-BB01-01']),
            {'id': 'RC-02', 'verdict': 'distinct', 'by': 'segment reviewer',
             'reason': '同名命题，CC01 是另一个模块各自缺一次授权',
             'finding_ids': ['F-CC01-01', 'F-AA01-01'], 'candidates': ['fm:FM-A1.1-01']}])
        closed = g9(workspace, settled)
        if closed['status'] != 'pass':
            problems.append('a fully adjudicated record still fails G9: %s' % closed['detail'])
        migrated = copy.deepcopy(clean)
        migrated['queue']['legacy_freeze_contract'] = '1.6'
        marker_only = g9(workspace, migrated)
        if marker_only['status'] != 'fail':
            problems.append('the workspace-level migration marker alone exempts G9: %s'
                            % marker_only)
        old_units = copy.deepcopy(clean)
        for unit in old_units['units']:
            unit['legacy_schema_version'] = '1.6'
        exempt = g9(workspace, old_units)
        if exempt['status'] != 'skip' or '什么都没核' not in exempt['detail']:
            problems.append('candidates whose members all sit in old-contract units do '
                            'not skip G9, or the row does not say it checked nothing: %s'
                            % exempt)
        half = linked(copy.deepcopy(old_units), [copy.deepcopy(MERGE)])
        if g9(workspace, half)['status'] != 'fail':
            problems.append('a merge that drops a member goes unreported on an '
                            'old-contract workspace: %s' % g9(workspace, half))
        mixed = copy.deepcopy(clean)
        for unit in mixed['units']:
            if unit['id'] != 'U-CC01':
                unit['legacy_schema_version'] = '1.6'
        enforced = g9(workspace, mixed)
        if (enforced['status'] != 'fail' or 'fm:FM-A1.1-01' not in enforced['detail']
                or 'set:F-AA01-01+F-BB01-01' in enforced['detail']):
            problems.append('per-unit grandfathering is wrong: a candidate with one '
                            'member in a new unit must be enforced and an all-old one '
                            'must not: %s' % enforced)
    return problems


@check('report-renders-root-causes')
def report_renders_root_causes():
    """The summary section exists, comes before the findings, and loses no member.

    Nothing was watching `render_report`. The point of the grouping is that the reader
    meets the root cause before the five members and that every member keeps its own
    path, so a section that renders the statement and drops the rows would read as
    complete. The empty case is asserted too: a record with no merge says so in one
    line, because a silent section is indistinguishable from a step nobody ran.
    """
    import copy
    import tempfile
    from records import render_report
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        workspace, clean = root_cause_fixture(tmp)
        state = linked(copy.deepcopy(clean), [copy.deepcopy(MERGE)])
        text = render_report(state, workspace)
        if '## 按根因汇总' not in text:
            problems.append('the report has no root-cause section')
            return problems
        if text.index('## 按根因汇总') > text.index('## 发现（'):
            problems.append('the root-cause section comes after the findings')
        section = text[text.index('## 按根因汇总'):text.index('## 发现（')]
        for wanted in (MERGE['statement'], MERGE['fix_point'], MERGE['by'], MERGE['reason']):
            if wanted not in section:
                problems.append('the root-cause section omits 「%s」' % wanted)
        for path in MERGE['member_paths']:
            missing = [value for value in path.values() if value not in section]
            if missing:
                problems.append('%s loses its affected path in the report: %s'
                                % (path['finding_id'], '、'.join(missing)))
        for fid, expected in (('F-AA01-01', True), ('F-CC01-02', False)):
            body = text[text.index('### ' + fid):]
            body = body[:body.index('影响：')]
            if ('根因：RC-01' in body) != expected:
                problems.append('%s %s a root-cause back link'
                                % (fid, 'lost' if expected else 'grew'))
        empty = linked(copy.deepcopy(clean), [
            {'id': 'RC-02', 'verdict': 'distinct', 'by': 'b', 'reason': 'r',
             'finding_ids': ['F-AA01-01', 'F-CC01-01']}])
        text = render_report(empty, workspace)
        section = text[text.index('## 按根因汇总'):text.index('## 发现（')]
        if '### RC-' in section:
            problems.append('a distinct adjudication renders as a root cause')
        if '没有记录跨单元根因归并' not in section:
            problems.append('a record with no merge does not say so: ' + section.strip())
    return problems


@check('rootcause-apply-refusals')
def rootcause_apply_refusals():
    """The write path refuses what the record cannot hold, and accepts what it can.

    Found by enumerating the refusals in `apply_adjudication` and asking which check
    would go red if one were dropped: none would. `validate` judges a record that is
    already written, so a refusal that stops a bad one from being written has to be
    driven here. The accept direction is half the check — a gatekeeper that refuses
    everything also passes every must-fire case.
    """
    import copy
    import tempfile
    from rootcause import apply_adjudication, digest
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        workspace, clean = root_cause_fixture(tmp)
        good = {'base_sha256': digest(clean), 'by': 'segment reviewer',
                'root_causes': [copy.deepcopy(MERGE)]}
        refused = [
            ('an adjudication submitted against candidates it never read',
             dict(good, base_sha256='0' * 64), 'base_sha256'),
            ('a candidate key no signal produced',
             dict(good, root_causes=[dict(MERGE, candidates=['fm:FM-ZZ-99'])]), '没有'),
            ('a key the record does not define',
             dict(good, root_causes=[dict(MERGE, note='x')]), '未定义键'),
            ('an id that is not a root-cause id',
             dict(good, root_causes=[dict(MERGE, id='F-AA01-01')]), 'RC-'),
            ('a merge missing one member path',
             dict(good, root_causes=[dict(MERGE, member_paths=MERGE['member_paths'][:1])]),
             '恰好一条'),
            ('one finding merged into two root causes',
             dict(good, root_causes=[dict(MERGE), dict(MERGE, id='RC-03')]), '只有一个根因'),
            ('an adjudication with no reason',
             dict(good, root_causes=[{k: v for k, v in MERGE.items() if k != 'reason'}]),
             'reason'),
            ('a cluster of one',
             dict(good, root_causes=[dict(MERGE, finding_ids=['F-AA01-01'])]), '至少两条'),
            # The row has a key whitelist and the affected paths did not, so an extra
            # key written into one landed in the record while records.md enumerates
            # three. Found by a cold-start reviewer whose first payload carried it.
            ('an affected path carrying a key the record does not define',
             dict(good, root_causes=[dict(MERGE, member_paths=[
                 dict(MERGE['member_paths'][0], entry='需要先持有会话'),
                 MERGE['member_paths'][1]])]), '未定义键'),
        ]
        for description, payload, expected in refused:
            state = copy.deepcopy(clean)
            try:
                apply_adjudication(workspace, state, payload)
                problems.append('--apply accepts ' + description)
            except ValueError as exc:
                if expected not in str(exc):
                    problems.append('%s is refused for the wrong reason: %s'
                                    % (description, exc))
            if state.get('root_causes'):
                problems.append('a refused submission still wrote a row: ' + description)
        # And it accepts the legitimate one, writes the back links, and releases a member
        # a replacement no longer claims — the record would otherwise fail `validate`
        # with a finding pointing at a cluster that no longer lists it.
        state = copy.deepcopy(clean)
        result = apply_adjudication(workspace, state, good)
        linked_now = {f['id']: f.get('root_cause_id') for f in state['findings']}
        if result['grouped_findings'] != 2 or linked_now['F-AA01-01'] != 'RC-01':
            problems.append('a legitimate adjudication did not take: %s / %s'
                            % (result, linked_now))
        shrunk = {'base_sha256': digest(state), 'by': 'segment reviewer',
                  'root_causes': [dict(MERGE, finding_ids=['F-AA01-01', 'F-CC01-01'],
                                       member_paths=[MERGE['member_paths'][0],
                                                     {'finding_id': 'F-CC01-01',
                                                      'location': 'c.ts:2-4',
                                                      'difference': '入口在 CLI'}])]}
        again = apply_adjudication(workspace, state, shrunk)
        if again['replaced'] != ['RC-01'] or again['relinked'] != ['F-BB01-01']:
            problems.append('replacing a cluster did not release the member it dropped: %s'
                            % again)
        import records
        stray = [error for error in records.validate(workspace, state) if 'RC-' in error]
        if stray:
            problems.append('the record it wrote does not validate: ' + stray[0])
    return problems


@check('decision-kind-table')
def decision_kind_table():
    """Each decision kind has its own row in the table that teaches them, and vice versa.

    `DECISION_KINDS` is what `decide` accepts and the table in orchestration.md is what a
    model reads before answering; nothing reconciled them. Measured when `cluster_scope`
    was added: the table held 10 of the 11 kinds, and the missing one (`oversized_unit`)
    turned out to be retired — the migration deletes those rows and nothing creates them,
    so the undocumented value was a dead branch rather than a documentation gap. Both
    directions, because a row for a kind the code rejects sends a model to an error.
    """
    from units import DECISION_KINDS
    import re
    lines = [line for line in read_text(SKILL / 'references' / 'orchestration.md').splitlines()
             if line.startswith('| `')]
    listed = {m.group(1) for line in lines for m in [re.match(r'\| `([a-z_]+)`', line)] if m}
    problems = []
    missing = [kind for kind in DECISION_KINDS if kind not in listed]
    if missing:
        problems.append('decision kinds with no row in the table of '
                        'references/orchestration.md: ' + ', '.join(missing))
    stray = sorted(listed - set(DECISION_KINDS) - {'repo_shard', 'artifact', 'residual',
                                                   'cross', 'joint', 'chain', 'goal',
                                                   'xartifact'})
    if stray:
        problems.append('the table teaches kinds `decide` would refuse: ' + ', '.join(stray))
    return problems


@check('cluster-scope-decision')
def cluster_scope_decision():
    """建簇与否是显式裁决: asked when it applies, judged at the freeze, never retroactive.

    `cluster_representative` only questions clusters that already exist, and a cluster
    only exists once `cluster` has run — so nobody ran it and nobody was asked, which is
    how five artifact units (two of them plugin collections) reached phase 2 with
    `clusters` empty and their shared defects filed one unit at a time. Driven through
    the real `pending_decisions`, `decide` and `freeze`: the question has to appear, the
    freeze has to refuse without an answer even when the question list is stale, and a
    workspace already past phase 2 must not be asked for it after the fact.
    """
    import copy
    import tempfile
    from units import CLUSTER_SCOPE_MIN, freeze, new_unit, pending_decisions
    from decide import decide
    import audit
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        workspace, target = Path(tmp) / 'ws', Path(tmp) / 'target'
        target.mkdir()
        for name in ('a.md', 'b.md', 'c.md', 'd.md'):
            (target / name).write_text('x', encoding='utf-8')
        audit.initialize(workspace, 'cluster-probe', ['repo=' + str(target)], [])
        state = audit.read(workspace / 'audit.json')
        materials = sorted(state['materials'])
        units = []
        for index, mid in enumerate(materials):
            # Three artifact units, written as 3 and not as CLUSTER_SCOPE_MIN: a fixture
            # sized from the constant it is testing moves with it, so raising the
            # threshold would leave this check green — the same mistake as a boundary
            # case two notches away from the boundary.
            unit = new_unit('U-%s%02d' % ('AB'[index % 2], index + 1),
                            'artifact' if index < 3 else 'repo_shard',
                            't%d' % index, mapping_note='n')
            unit.update(material_ids=[mid], exposure='INT', exposure_reason='r',
                        depth='standard', depth_reason='r', file_count=1)
            units.append(unit)
        state['units'] = units
        state['queue'].update(partition_confirmed=True, partition_reason='r',
                              phase1_frozen={'units': len(units), 'object_scope': 0,
                                             'spots': 0},
                              census={'enumerated': len(materials),
                                      'in_units': len(materials),
                                      'unit_file_count_sum': len(materials)})
        audit.save(workspace, state)
        asked = [d for d in pending_decisions(workspace, state)
                 if d['kind'] == 'cluster_scope']
        if len(asked) != 1 or 'U-A01' not in asked[0]['question']:
            problems.append('three artifact units did not raise the clustering question: %s'
                            % asked)
        # The threshold is a judgement a model reads in the table before it ever reaches
        # the code, so the two sides have to say the same number.
        import re
        row = [line for line in
               read_text(SKILL / 'references' / 'orchestration.md').splitlines()
               if line.startswith('| `cluster_scope`')]
        taught = re.search(r'制品单元 ≥(\d+) 个', row[0]) if row else None
        if not taught:
            problems.append('the decision table does not teach the clustering threshold: '
                            + (row[0] if row else '(no row)'))
        elif int(taught.group(1)) != CLUSTER_SCOPE_MIN:
            problems.append('the table teaches ≥%s artifact units and the code requires '
                            '≥%d' % (taught.group(1), CLUSTER_SCOPE_MIN))
        # The question list is recomputed, so the freeze has to judge the field itself.
        state['pending_decisions'] = []

        def frozen(candidate):
            try:
                freeze(workspace, copy.deepcopy(candidate), 2)
                return None
            except ValueError as exc:
                return str(exc)
        if not frozen(state):
            problems.append('phase 2 freezes with the clustering question unanswered')
        answered = copy.deepcopy(state)
        decide(workspace, answered, 'cluster_scope:queue', 'not_needed', '各自职责不同')
        if (answered['queue'].get('cluster_scope') or {}).get('decision') != 'not_needed':
            problems.append('decide did not write the answer where the freeze reads it: %s'
                            % answered['queue'].get('cluster_scope'))
        refused = frozen(answered)
        if refused:
            problems.append('an answered not_needed still blocks the freeze: ' + refused)
        wanted = copy.deepcopy(state)
        decide(workspace, wanted, 'cluster_scope:queue', 'needed', '三个插件集合同形')
        if 'no cluster exists' not in (frozen(wanted) or ''):
            problems.append('needed with no cluster built freezes anyway')
        wanted['clusters'] = [{'id': 'CL-01', 'member_unit_ids': ['U-A01', 'U-B02'],
                               'representative_unit_id': None, 'diff_files': [],
                               'decision': None}]
        if frozen(wanted):
            problems.append('needed with a cluster built still blocks the freeze: %s'
                            % frozen(wanted))
        fewer = copy.deepcopy(state)
        fewer['units'][0]['kind'] = 'repo_shard'
        if frozen(fewer):
            problems.append('two artifact units should not be asked to cluster: %s'
                            % frozen(fewer))
        if any(d['kind'] == 'cluster_scope' for d in pending_decisions(workspace, fewer)):
            problems.append('two artifact units are asked to cluster anyway')
        past = copy.deepcopy(state)
        past['queue']['phase2_rows_frozen'] = len(units)
        if any(d['kind'] == 'cluster_scope' for d in pending_decisions(workspace, past)):
            problems.append('a workspace already past phase 2 is asked to cluster '
                            'retroactively')
    return problems


@check('report-volume-split')
def report_volume_split():
    """The mechanical inventories leave the body by default and stay whole in the appendix.

    Measured: 12444-line report, four inventories at 4452 lines — 36% — while the rule
    meant to stop that was scoped to one section's name and satisfied at 4 lines. So the
    body keeps totals and a pointer, the appendix keeps every row, and the gate measures
    the delivered file. Both directions: `--full` must still inline them, because the
    reason to keep that option is that one file sometimes has to stand alone.
    """
    import copy
    import tempfile
    from gate import evaluate
    from records import (MECHANICAL_SECTIONS, render_coverage, render_report,
                         report_shape)
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        workspace, state = root_cause_fixture(tmp)
        state['corrections'] = [{'id': 'CR-AA01-01', 'target': 'F-AA01-01',
                                 'field': 'title', 'before': 'a', 'after': 'b',
                                 'reason': '回源后改写', 'by': 'reviewer'}]
        body = render_report(state, workspace)
        full = render_report(state, workspace, full=True)
        appendix = render_coverage(state, workspace)
        for title in MECHANICAL_SECTIONS:
            if ('## ' + title) not in body:
                problems.append('the body dropped the section instead of summarizing it: '
                                + title)
            if ('## ' + title) not in appendix:
                problems.append('the appendix does not carry the inventory: ' + title)
        if 'coverage-details.md' not in body:
            problems.append('the body points nowhere for the detail')
        def section(text, title):
            start = text.index('## ' + title)
            end = text.find('\n## ', start + 1)
            return text[start:end if end != -1 else len(text)]

        # Nothing is lost by the move, and the ids are checked inside the inventory
        # sections only: every finding legitimately cites its own check and evidence ids
        # in the body («检查项：… ；证据：…»), so a whole-document search would read
        # those cross-references as an inventory that never left.
        for title, rows in (('检查结论与缺口', state['checks']),
                            ('证据索引', state['evidence'])):
            summary, inlined, kept = (section(body, title), section(full, title),
                                      section(appendix, title))
            if 'coverage-details.md' not in summary:
                problems.append('「%s」 in the body points nowhere for the detail' % title)
            for row in rows:
                if row['id'] in summary:
                    problems.append('%s is still listed row-by-row in the body' % row['id'])
                if row['id'] not in inlined:
                    problems.append('--full dropped %s from the body' % row['id'])
                if row['id'] not in kept:
                    problems.append('%s appears in no appendix inventory' % row['id'])
        if state['corrections'][0]['reason'] not in appendix:
            problems.append('the appendix cut a correction instead of keeping it whole')
        # 按命题对账 only has a table when some proposition diverges, and this fixture
        # agrees with itself — so the switch would go untested without forcing one.
        diverged = copy.deepcopy(state)
        for row in diverged['checks']:
            if row['id'] == 'CHK-CC01-0001':
                row['verdict'] = 'not_applicable'
        account = section(render_report(diverged, workspace), '按命题对账')
        inlined = section(render_report(diverged, workspace, full=True), '按命题对账')
        if 'coverage-details.md' not in account or '| 命题 |' in account:
            problems.append('the body still carries the divergence table: '
                            + account.replace('\n', ' ')[:160])
        if '| 命题 |' not in inlined:
            problems.append('--full dropped the divergence table')
        if '不带「说明」列' not in inlined or '| 说明 |' in inlined:
            problems.append('with nothing in reconciliations the table keeps a column '
                            'that would repeat one sentence on every row')
        shape = report_shape(full)
        if shape['mechanical_share'] <= report_shape(body)['mechanical_share']:
            problems.append('inlining the inventories does not raise the measured share: '
                            '%s vs %s' % (shape, report_shape(body)))
        # Preparation can precede authoring; final delivery cannot. Legacy size
        # ratios no longer constitute a completed report.
        row = next(r for r in evaluate(workspace, state, prepare_report=True) if r['id'] == 'G10')
        if row['status'] != 'skip':
            problems.append('G10 blocks report preparation: %s' % row)
        row = next(r for r in evaluate(workspace, state) if r['id'] == 'G10')
        if row['status'] != 'fail':
            problems.append('G10 accepts missing authored reports: %s' % row)
        # Through the command line, because the option and the renderer are wired by one
        # argument that nothing else watches: dropping the pass-through leaves `--full`
        # registered, documented and inert.
        import contextlib
        import io
        import audit
        for argv, wanted in ((['report', '--workspace', str(workspace)], False),
                             (['report', '--workspace', str(workspace), '--full'], True)):
            saved = sys.argv
            sys.argv = ['audit.py'] + argv
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = audit.main()
            finally:
                sys.argv = saved
            indexed = (workspace / 'report' / 'index.json').is_file()
            full_path = workspace / 'report' / 'full-records.md'
            inlined = (full_path.is_file() and state['checks'][0]['id'] in
                       section(full_path.read_text(encoding='utf-8'), '检查结论与缺口'))
            if code != 0 or not indexed or inlined != wanted:
                problems.append('%s produced exit %s, indexed=%s, full records=%s'
                                % (' '.join(argv), code, indexed, inlined))
    return problems


@check('two-stage-reporting')
def two_stage_reporting():
    """Indexed materials and authored reports obey the two-stage delivery contract."""
    from reporting_check import run_checks
    return run_checks(SKILL)


@check('kept-knowledge-is-versioned')
def kept_knowledge_is_versioned():
    """Every kept target knowledge base says which revision it was derived from.

    A pattern is a statement about one revision: it names a file and a line. Kept without
    that stamp, a later audit cannot tell accumulated knowledge from a stale claim, and
    there is nothing to diff against — so an unversioned file would be reused forever.
    The directory also has to stay clear of anything but these files: it is loaded by
    target name, so a stray file is knowledge nobody vouched for.
    """
    directory = SKILL / 'knowledge' / 'targets'
    if not directory.is_dir():
        return []
    problems = []
    for path in sorted(directory.iterdir()):
        if path.is_dir():
            problems.append('%s: the knowledge base directory holds files, not folders'
                            % path.name)
            continue
        if not path.name.endswith('_pattern.json'):
            problems.append('%s: only <target>_pattern.json belongs here' % path.name)
            continue
        try:
            payload = json.loads(read_text(path))
        except ValueError as exc:
            problems.append('%s: not readable as JSON (%s)' % (path.name, exc))
            continue
        revisions = payload.get('revisions')
        if not isinstance(revisions, dict) or not revisions:
            problems.append('%s: no revisions recorded, so nothing can be diffed against it'
                            % path.name)
            continue
        for tid, stamp in revisions.items():
            rev = (stamp or {}).get('revision')
            if rev is not None and not (isinstance(rev, str) and len(rev) == 40):
                problems.append('%s: %s has no full commit id' % (path.name, tid))
        for row in payload.get('patterns') or []:
            if row.get('kind') == 'sink' and not (row.get('reaches') or row.get('gates')):
                problems.append('%s: %s was kept without its evidence chain'
                                % (path.name, row.get('id')))
    return problems


@check('cohesion-not-size-decides-a-unit')
def cohesion_not_size_decides_a_unit():
    """The retired pack command must refuse without changing any partition."""
    from copy import deepcopy
    from units import pack_units
    state = {'units': [], 'queue': {}}
    before = deepcopy(state)
    try:
        pack_units(Path('/nonexistent'), state)
    except ValueError as exc:
        if '--apply' not in str(exc):
            return ['retired pack must explain the explicit plan replacement']
    else:
        return ['retired pack must not silently generate a plan']
    return ['retired pack mutated the state'] if state != before else []


@check('the-cross-unit-exception-holds-everywhere')
def the_cross_unit_exception_holds_everywhere():
    """Cross units own no index; absent optional indexes create no obligations."""
    from surface import reconcile
    from units import new_unit
    state = {'units': [new_unit('U-CX01', 'cross', 'fixture', cross_type='goal'),
                       new_unit('U-SH01', 'repo_shard', 'fixture')]}
    rows = reconcile(Path('/nonexistent'), state)
    return [] if len(rows) == 1 and rows[0]['status'] == 'ok' else ['optional index treated as a required task']


@check('the-validator-does-not-mutate')
def the_validator_does_not_mutate():
    """`_check_scope` collects errors; it must not fold anything into the record.

    Twice a fold landed there instead of in `merge_unit`, because that function holds the
    only other loop over the payload and the anchor reads the same. Neither `working` nor
    `unit_id` exists there, so both slips were a NameError on any product using the new
    key — caught once by an auditor and once by the tests, never by review.
    """
    import re
    code = read_text(SKILL / 'scripts' / 'merge.py')
    match = re.search(r'\ndef _check_scope\(.*?(?=\ndef )', code, re.S)
    if not match:
        return ['scripts/merge.py must define _check_scope']
    body = match.group(0)
    problems = []
    for name in ('working', 'unit_id'):
        if name in body:
            problems.append('_check_scope references `%s`, which only exists in '
                            'merge_unit: a fold belongs there, not in the validator' % name)
    for mutation in ('setdefault(', '] = '):
        if mutation in body and 'errors' not in body.split(mutation)[0][-40:]:
            problems.append('_check_scope writes into the payload (`%s`); it only '
                            'collects errors' % mutation.strip())
    return problems


@check('the-key-list-matches-the-code')
def the_key_list_matches_the_code():
    """The contract's allowed-key list against the one the code enforces.

    Two keys were added to `ALLOWED_KEYS` and to the section that asks for them, and the
    list a cold-start worker actually reads was left behind — so the contract told the
    worker both that the key is required and that it would be rejected. A worker caught it
    mid-round and had to pick one.
    """
    import re
    from merge import ALLOWED_KEYS
    problems = []
    # Both documents carry the list, and fixing one left the other behind twice.
    for name in (Path('references') / 'roles' / 'worker.md',
                 Path('references') / 'records.md'):
        text = read_text(SKILL / name)
        lines = [line for line in text.splitlines() if '只允许这些顶层键' in line]
        if not lines:
            problems.append('%s must list the product\'s allowed top-level keys' % name)
            continue
        listed = set(re.findall(r'`([a-z_]+)`', lines[0]))
        missing = sorted(set(ALLOWED_KEYS) - listed)
        stray = sorted(listed - set(ALLOWED_KEYS))
        if missing:
            problems.append('%s omits keys the code accepts: %s' % (name, '、'.join(missing)))
        if stray:
            problems.append('%s lists keys the code rejects: %s' % (name, '、'.join(stray)))
    return problems


@check('phase-vocabulary')
def phase_vocabulary():
    """The phase names the scripts use and the ones the protocol routes are one set.

    The same shape as the verdict with no landing place: two vocabularies for one thing
    drift, and nothing notices. Here the risk is concrete — the stage numbers shifted by
    one when reconnaissance became a phase of its own, so a document still saying
    「阶段一」 for the per-unit work now points at the wrong phase.
    """
    import audit
    protocol = read_text(SKILL / 'references' / 'orchestration.md')
    problems = []
    keys = set(audit.EMPTY_QUEUE)
    for key in ('phase1_frozen', 'phase2_rows_frozen', 'phase3_rows_frozen', 'phase3_critic'):
        if key not in keys:
            problems.append('the queue has no ' + key)
        if key not in protocol and key != 'phase1_frozen':
            problems.append('the protocol never mentions ' + key)
    stale = [word for word in ('stage1_rows_frozen', 'stage2_rows_frozen', 'stage2_critic',
                               '--stage', '阶段一', '阶段二')
             if word in protocol]
    if stale:
        problems.append('retired phase vocabulary is still in the protocol: ' + ', '.join(stale))
    flags = {o for a in audit.build_parser()._actions for o in a.option_strings}
    if '--phase' not in flags:
        problems.append('the CLI has no --phase')
    if '--stage' in flags:
        problems.append('the CLI still offers the retired --stage')
    for name in ('一阶段', '二阶段', '三阶段'):
        if name not in protocol:
            problems.append('the protocol must name ' + name)
    # Retired unit statuses must stay out of the enum. `redo` went with the verdict of
    # that name; `in_progress` belongs to coverage rows, and using it for a unit left the
    # record invalid after every retraction — widening the enum would have hidden that
    # rather than fixed it.
    from units import STATUSES
    stale_status = [name for name in ('redo', 'in_progress') if name in STATUSES]
    if stale_status:
        problems.append('retired unit statuses are back in the enum: '
                        + ', '.join(stale_status))
    return problems


@check('gate-rows')
def gate_rows():
    """The gate's row titles are unique and each row id is emitted exactly once."""
    from gate import ROWS
    ids = [row.split()[0] for row in ROWS]
    problems = []
    if len(set(ids)) != len(ids):
        problems.append('duplicate gate row ids: ' + ', '.join(ids))
    source = read_text(SCRIPTS / 'gate.py')
    for index, rid in enumerate(ids):
        if ("_row('%s'" % rid) not in source:
            problems.append('%s is declared but never emitted' % rid)
        if ("ROWS[%d]" % index) not in source:
            problems.append('%s does not use its declared title' % rid)
    return problems


@check('knowledge-bundle')
def knowledge_bundle():
    """The pinned knowledge still matches its manifest."""
    from knowledge import load_bundle
    data, manifest, fingerprint = load_bundle()
    problems = []
    if manifest['files']['framework.json'] != fingerprint:
        problems.append('bundle fingerprint does not match the manifest')
    counts = {'failure_modes': 211, 'objects': 36, 'risks': 156}
    for key, expected in counts.items():
        if len(data[key]) != expected:
            problems.append('%s count changed: %d (manifest release declared %d); '
                            'rebuild the skill from the framework data'
                            % (key, len(data[key]), expected))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args(argv)
    if args.list:
        for name, function in CHECKS:
            print('%-24s %s' % (name, (function.__doc__ or '').strip().splitlines()[0]))
        return 0
    rows, failed = [], 0
    advisory = {'role-contracts', 'vocabulary-documented', 'primitive-table',
                'command-surface-routed', 'phase-vocabulary'}
    for name, function in CHECKS:
        crashed = False
        try:
            problems = function() or []
        except Exception as exc:                                  # a crash is a FAIL
            crashed = True
            problems = ['the check itself could not run: %s: %s' % (type(exc).__name__, exc)]
        status = 'PASS' if not problems else ('WARN' if name in advisory and not crashed else 'FAIL')
        failed += status == 'FAIL'
        rows.append({'check': name, 'status': status, 'problems': problems})
        print('%-4s %-24s %s' % (status, name, '; '.join(problems)[:200]))
    print(json.dumps({'verdict': 'FAIL' if failed else 'PASS',
                      'checks': len(CHECKS), 'failed': failed}, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
