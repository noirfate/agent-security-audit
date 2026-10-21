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
                                  'object_scope', 'materials', 'coverage', 'queue']))
    problems = []
    missing = [name for name in known if name not in doc]
    if missing:
        problems.append('records.md does not describe: ' + ', '.join(missing))
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
