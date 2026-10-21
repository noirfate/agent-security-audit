#!/usr/bin/env python3
"""Optional model-authored search patterns and textual locations.
Text matching never establishes actual calls, wrappers, applicability or coverage."""
# Importable under `python3 -I`, which clears the script directory from sys.path:
# the session rule is to read untrusted data with -I, and these scripts import
# their siblings, so without this they fail before doing anything.
import sys as _sys
from pathlib import Path as _Path
if str(_Path(__file__).resolve().parent) not in _sys.path:
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
import json
import os
import re
import sys
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent


def targets_dir():
    """Where kept knowledge bases live. Redirectable, so nothing writes into the
    installed skill while testing — the skill is read-only during an audit, and a test
    that crashes between writing and cleaning up would otherwise leave an artifact in
    it that the next audit of that target would load as knowledge."""
    override = os.environ.get('AUDIT_TARGET_KB_DIR')
    return Path(override) if override else SKILL / 'knowledge' / 'targets'

KINDS = ('sink', 'topic')


def cited_paths(row):
    """Every file one pattern's evidence chain rests on — the drift check's denominator.

    One place, because the gate half was missing from it: a guard that justifies itself by
    the refusal it controls rests on the file holding that refusal, and nothing watched it.
    """
    cited = {(row.get('defined_at') or {}).get('path')}
    for key in ('reaches', 'gates'):
        cited |= {step.get('path') for step in row.get(key) or []}
    return {path for path in cited if path}


def search_call_sites(workspace, state, symbols, call_forms=None, material_ids=None):
    """Locate textual matches. This is not a call graph or a production-call count.

    Definitions, comments, strings, tests and prose remain in the result. Only the
    caller's explicit material selection narrows the search; no text tail is discarded.
    """
    from audit import material_path
    forms = dict(call_forms or {})
    wanted = {}
    for sym in symbols:
        if not sym:
            continue
        expr = str(forms.get(sym) or '') or r'(?<![0-9A-Za-z_])%s\s*[(<:]' % re.escape(sym)
        try:
            wanted[sym] = re.compile(expr)
        except re.error as exc:
            raise ValueError('%s: invalid call_form: %s' % (sym, exc))
    selected = set(material_ids) if material_ids is not None else None
    if selected is not None and selected - set(state['materials']):
        raise ValueError('Unknown material_ids in textual search')
    results = {sym: {'match_lines': 0, 'matches': [], 'pattern': expr.pattern,
                     'method': 'text_regex'} for sym, expr in wanted.items()}
    scanned = 0
    skipped = {}
    for mid, material in state['materials'].items():
        if selected is not None and mid not in selected:
            continue
        if material['status'] != 'present' or material.get('visibility') != 'text':
            reason = material['status'] if material['status'] != 'present' else material.get('visibility', 'unknown')
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        scanned += 1
        # Unreadable input is reported as an error, never silently counted as zero.
        text = material_path(state, material).read_text(encoding='utf-8', errors='replace')
        for number, line in enumerate(text.splitlines(), 1):
            for sym, expr in wanted.items():
                if expr.search(line):
                    results[sym]['matches'].append({'material_id': mid,
                        'path': material['path'], 'line': number, 'excerpt': line})
                    results[sym]['match_lines'] += 1
    for result in results.values():
        result['scope'] = {'selection': 'explicit_materials' if selected is not None else 'all_present_text',
                           'material_ids': sorted(selected) if selected is not None else None,
                           'scanned_materials': scanned, 'skipped_by_status_or_visibility': skipped}
        result['truncated'] = False
    return results


def count_callers(workspace, state, symbols, call_forms=None):
    """Compatibility alias returning textual matching-line counts, never real callers."""
    return {sym: row['match_lines'] for sym, row in
            search_call_sites(workspace, state, symbols, call_forms).items()}


def validate_patterns(workspace, state, payload):
    """Everything a target pattern must carry before it may be registered."""
    from knowledge import baseline_dir, load_bundle, objects
    problems = []
    if not isinstance(payload, dict):
        return ['recall product must be an object']
    rows = payload.get('patterns')
    if not isinstance(rows, list):
        return ['产物里没有 patterns 数组']
    if payload.get('baseline_id') != state['framework']['baseline_id']:
        problems.append('baseline_id 与记录里钉住的基线不符：%s' % payload.get('baseline_id'))
    known = set()
    try:
        bundle, _, _ = load_bundle(baseline_dir(workspace, state['framework']['baseline_id']))
        known = set(objects(bundle))
    except (OSError, ValueError, KeyError):
        problems.append('读不到钉住的基线，无法核对 object_ids')
    materials = {row['path'] for row in state['materials'].values()
                 if row['status'] == 'present'}
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            problems.append('pattern must be an object')
            continue
        pid = str(row.get('id') or '?')
        if not isinstance(row.get('id'), str) or not row['id'].strip():
            problems.append('pattern needs an id')
        if not isinstance(row.get('object_ids'), list):
            problems.append('%s: object_ids must be an array' % pid)
            continue
        for field in ('regex', 'kind', 'object_ids', 'symbol', 'defined_at', 'rationale'):
            if not row.get(field):
                problems.append('%s: 缺 %s' % (pid, field))
        if pid in seen:
            problems.append('%s: 编号重复' % pid)
        seen.add(pid)
        if row.get('kind') not in KINDS:
            problems.append('%s: kind 必须是 sink 或 topic' % pid)
        try:
            re.compile(row.get('regex') or '')
        except re.error as exc:
            problems.append('%s: 正则编译失败（%s）' % (pid, exc))
        if known:
            stray = [oid for oid in row.get('object_ids') or [] if oid not in known]
            if stray:
                problems.append('%s: 对象不在框架里：%s' % (pid, '、'.join(stray)))
        # The chain. A pattern that reaches no language-level construct cannot be shown
        # to be a decision point, and this is the whole difference between a recalled
        # wrapper and a guess.
        # Two kinds of justification, because requiring a language-level construct
        # excluded the most important class outright. An authorization wrapper
        # (`authorize_workspace`, 26 callers; `resolve_and_authorize_sandbox_name`, 31)
        # is the decision point for the approval and policy objects, and it bottoms out
        # in a refusal — `Status::permission_denied`, an early return — not in a process
        # spawn. Measured on the first real recall: those patterns could not be written
        # at all, so the two objects came out structurally thin while the code was full
        # of guards. A `gates` entry says which refusal it controls and where.
        reaches = row.get('reaches') or []
        gates = row.get('gates') or []
        if row.get('kind') == 'sink' and not reaches and not gates:
            problems.append('%s: sink 要么给 reaches（走到哪个语言级构造），'
                            '要么给 gates（它把守哪条拒绝路径）' % pid)
        for step in gates:
            for field in ('path', 'refusal'):
                if not step.get(field):
                    problems.append('%s: gates 缺 %s' % (pid, field))
            if step.get('path') and step['path'] not in materials:
                problems.append('%s: gates 指向不在材料索引里的文件 %s' % (pid, step['path']))
        for step in reaches:
            for field in ('path', 'construct', 'via'):
                if not step.get(field):
                    problems.append('%s: reaches 缺 %s' % (pid, field))
            if step.get('path') and step['path'] not in materials:
                problems.append('%s: reaches 指向不在材料索引里的文件 %s' % (pid, step['path']))
        where = row.get('defined_at') or {}
        if where.get('path') and where['path'] not in materials:
            problems.append('%s: defined_at 指向不在材料索引里的文件 %s' % (pid, where['path']))
        if 'callers' in row and (not isinstance(row['callers'], int) or isinstance(row['callers'], bool) or row['callers'] < 0):
            problems.append('%s: callers must be a nonnegative model-supplied count' % pid)
        if 'call_sites' in row:
            if not isinstance(row['call_sites'], list):
                problems.append('%s: call_sites must be an array of model-confirmed locations' % pid)
                continue
            for site in row['call_sites']:
                if not isinstance(site, dict) or site.get('path') not in materials:
                    problems.append('%s: call_sites path must reference an indexed material' % pid)
                    continue
                matching = [m for m in state['materials'].values()
                            if m['status'] == 'present' and m['path'] == site['path']
                            and (not site.get('material_id') or m['id'] == site['material_id'])]
                from audit import material_path
                line = site.get('line')
                if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                    problems.append('%s: invalid call_sites line' % pid)
                elif not matching or not any(line <= len(material_path(state, m).read_text(
                        encoding='utf-8', errors='replace').splitlines()) for m in matching):
                    problems.append('%s: call_sites line outside material' % pid)
        if row.get('call_form'):
            try:
                re.compile(row['call_form'])
            except re.error as exc:
                problems.append('%s: invalid call_form: %s' % (pid, exc))
    return problems


def brief(workspace, state):
    """Cut the recall agent's whole input: instances, declared objects, and where the
    language-level patterns already fired.

    The contract named this file before anything produced it — the same defect a
    cold-start worker run turned up elsewhere (a contract pointing at something that does
    not exist at run time). It is cut by the dispatcher, from the record, so the agent
    never needs to read the shared record itself.
    """
    workspace = Path(workspace)
    from surface import load_hits
    out = workspace / 'units' / '_recall'
    out.mkdir(parents=True, exist_ok=True)
    units = [u for u in state.get('units', []) if u['kind'] != 'cross']
    lines = ['# 召回 brief · %s' % state.get('target_id'), '',
             '仅在模型已有具体检索问题时召回：从架构、实例或可选命中查找目标封装，'
             '每条模式带模型核实的依据。空 patterns 合法；以下是定位信息，可继续读取原始材料。', '',
             '## 目标与版本', '']
    for target in state.get('targets', []):
        lines.append('- `%s` → %s（revision %s%s）'
                     % (target['id'], target['path'],
                        (target.get('revision') or '非 git 仓')[:12],
                        '，工作树有未提交改动' if target.get('dirty') else ''))
    kept = knowledge_base(state.get('target_id'))
    lines += ['', '## 已留存的目标知识库', '']
    if not kept:
        lines.append('无——本目标第一次召回。')
    else:
        rows = drift(state, state.get('target_id'))
        lines.append('%d 条留存模式，其中 %d 条存在版本待核项（见下）；未报漂移也不证明语义可复用。'
                     % (len(kept.get('patterns') or []), len(rows)))
        for row in rows:
            lines.append('- %s：%s%s' % (row['pattern_id'], row['reason'],
                                         '（%s）' % '、'.join(row['files']) if row['files'] else ''))
    lines += ['', '## 已登记的实例（模式要挂到这些对象上）', '']
    for instance in state.get('instances', []):
        lines.append('- `%s` %s｜对象 %s｜单元 %s'
                     % (instance['id'], instance.get('name', ''),
                        '、'.join(instance.get('framework_object_ids') or []) or '未映射',
                        instance.get('unit_id') or '未归属'))
    if not state.get('instances'):
        lines.append('（还没有实例：按各单元声明的对象找封装。）')
    lines += ['', '## 各单元声明的对象', '', '| 单元 | 对象 | 文件 | 候选聚合数 | 语言零匹配统计 |',
              '|---|---|---:|---:|---|']
    for unit in units:
        lines.append('| %s | %s | %d | %s | %s |'
                     % (unit['id'], '、'.join(unit.get('object_ids') or []) or '（无）',
                        unit['file_count'],
                        '未建索引' if unit.get('surface_hits') is None else unit['surface_hits'],
                        '、'.join('%s/%d' % kv for kv in
                                  sorted((unit.get('blind_languages') or {}).items())) or '无'))
    # Bounded location sample; complete scanned results remain in each surface JSON.
    by_family = {}
    total = 0
    for unit in units:
        payload = load_hits(workspace, unit['id'])
        if not payload:
            continue
        for spot in payload.get('spots') or []:
            by_family.setdefault(spot['family'], []).append((spot['matches'], unit['id'], spot))
            total += 1
    for rows in by_family.values():
        rows.sort(key=lambda row: -row[0])
    starts, order = [], sorted(by_family, key=lambda fid: -len(by_family[fid]))
    while len(starts) < 60 and any(by_family[fid] for fid in order):
        for fid in order:
            if by_family[fid]:
                starts.append(by_family[fid].pop(0))
            if len(starts) >= 60:
                break
    lines += ['', '## 语言级模式已命中的位置（你的起点）', '',
              '**按模式族轮转取样，族内按重复度排。**不是全局最重复的 60 处——那样一个族就能'
              '占掉一半，实测前 60 处里 32 处同族、只覆盖 33 个族中的 12 个，召回因此整片留空。'
              '**按具体问题追踪定义和调用关系**，由模型决定哪些封装值得记录；没有检索起点时，'
              '从该语言的入口文件读起。全目标共 %d 处、%d 个族，下面是 %d 处覆盖 %d 个族——'
              '不够用时自己去 `surface/<单元>.json` 取。'
              % (total, len(by_family), len(starts), len({r[2]['family'] for r in starts})), '']
    for matches, uid, spot in starts:
        lines.append('- %s｜`%s`｜%s×%d｜符号 %s'
                     % (uid, spot['path'], spot['family'], matches,
                        '、'.join(spot['symbols'][:4])))
    path = out / 'brief.md'
    text = '\n'.join(lines) + '\n'
    path.write_text(text, encoding='utf-8')
    return {'brief': str(path), 'bytes': len(text.encode('utf-8')),
            'units': len(units), 'instances': len(state.get('instances', [])),
            'note': '产出写到 %s，再用 recall --apply 登记' % (out / 'patterns.json')}


def validate_form_gaps(state, payload):
    """Forms the shipped families do not recognise, as reported by the recall pass.

    The sinks are produced by the model in phase 1 — the shipped families are only a
    cold-start seed — so a seed that misses a library is not itself the defect: the
    recall pass is what covers it, and on the first real run it did, by reading the code.
    The defect was that its finding had nowhere to go: it ended up as one string inside
    `method_notes`, which nothing reads and no gate counts. Measured there: `libc::` 1153
    lines of which 945 matched no shipped sink, `nix::` 217 of 224, the whole of `russh::`.

    So it gets a place of its own. These are not patterns — nobody is asked to dispose of
    them per hit — they are the input for refining the seed after delivery, and the honest
    answer to "what did the index not look for".
    """
    problems = []
    materials = {row['path'] for row in state['materials'].values()
                 if row['status'] == 'present'}
    for row in payload.get('form_gaps') or []:
        gid = str(row.get('id') or '?')
        for field in ('form', 'where', 'reason'):
            if not row.get(field):
                problems.append('%s: 形态缺口缺 %s' % (gid, field))
        # Counted, not asserted: "the seed misses this" is a claim about how much, and a
        # claim without a number cannot be acted on or checked later.
        for field in ('files', 'lines_unmatched'):
            if not isinstance(row.get(field), int):
                problems.append('%s: 形态缺口要给 %s（整数）——'
                                '「种子漏了这个」是个量的断言' % (gid, field))
        sample = row.get('where')
        if isinstance(sample, str) and sample and sample not in materials:
            problems.append('%s: where 指向不在材料索引里的文件 %s' % (gid, sample))
    return problems


def apply_patterns(workspace, state, path, replace_all=False):
    """Register a recall product. Refuses rather than registers a guess.

    Merges by pattern id: the protocol tells its reader to "重新召回该条（`recall --apply`
    以新证据覆盖同一条）", and this used to replace the whole set instead, so bringing one
    corrected pattern deleted the other thirty-three. A real run noticed and had to carry
    all 34 patterns and 17 form gaps through every re-registration. `--replace-all` is the
    way to say "this product is the complete set", which is what withdrawing a pattern
    needs.
    """
    from audit import save
    from knowledge import read
    workspace = Path(workspace)
    payload = read(Path(path))
    problems = validate_patterns(workspace, state, payload)
    if isinstance(payload, dict):
        problems += validate_form_gaps(state, payload)
    if problems:
        raise ValueError('召回产物被拒（%d 处问题）：%s'
                         % (len(problems), '；'.join(problems[:4])))
    out = workspace / 'target_patterns.json'
    # Stamped with the revision each pattern was derived from. Without it a later audit
    # of the same target cannot tell accumulated knowledge from a stale claim.
    stamps = {t['id']: {'revision': t.get('revision'), 'dirty': t.get('dirty')}
              for t in state.get('targets', [])}
    from copy import deepcopy
    brought = deepcopy(payload['patterns'])
    incoming = {row['id'] for row in brought}
    # Counted before the old rows are dropped, or it is always zero: `kept` has already
    # excluded the ids this product brings, so the arithmetic that used it cancelled out.
    overwritten = sum(1 for row in (state.get('target_patterns') or [])
                      if row['id'] in incoming)
    if replace_all:
        kept, gaps = [], []
    else:
        kept = [row for row in (state.get('target_patterns') or [])
                if row['id'] not in incoming]
        gap_ids = {g['id'] for g in (payload.get('form_gaps') or [])}
        gaps = [g for g in (state.get('form_gaps') or []) if g['id'] not in gap_ids]
    state['target_patterns'] = sorted(kept + brought, key=lambda row: row['id'])
    state['form_gaps'] = sorted(gaps + list(payload.get('form_gaps') or []),
                                key=lambda g: g['id'])
    out.write_text(json.dumps({'target': payload.get('target'),
                               'baseline_id': payload['baseline_id'],
                               'revisions': stamps,
                               'patterns': state['target_patterns']},
                              ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    save(workspace, state)
    kinds = {k: sum(r['kind'] == k for r in state['target_patterns']) for k in KINDS}
    return {'registered': len(brought), 'total': len(state['target_patterns']),
            'replaced': overwritten,
            'by_kind': kinds, 'form_gaps': len(state['form_gaps']),
            'file': str(out),
            'note': '按条合并：带来的条覆盖同编号的旧条，其余保留。'
                    '要整套替换（撤回某条）用 --replace-all。'
                    '按需运行 surface 定位候选；终报之后才考虑提炼进技能的目标知识库'}


def load_target_patterns(workspace, target_name=None):
    """This audit's recalled patterns, plus any the skill has kept for the same target.

    Two sources, deliberately separate. The workspace file is **this** audit's product.
    The skill's `knowledge/targets/<name>_pattern.json` is what a previous audit of the
    same target left behind, hand-picked after delivery — so a second audit starts from
    accumulated knowledge instead of the language-level seed. It is loaded only for a
    target of that name, so one target never inherits another's guesses.
    """
    from knowledge import read
    rows = []
    path = Path(workspace) / 'target_patterns.json'
    if path.is_file():
        rows += (read(path).get('patterns') or [])
    if target_name:
        kept = targets_dir() / ('%s_pattern.json' % target_name)
        if kept.is_file():
            rows += (read(kept).get('patterns') or [])
    seen, out = set(), []
    for row in rows:
        key = (row.get('kind'), row.get('regex'))
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def knowledge_base(target_name):
    """The kept knowledge base for this target, or None."""
    if not target_name:
        return None
    path = targets_dir() / ('%s_pattern.json' % target_name)
    if not path.is_file():
        return None
    from knowledge import read
    return read(path)


def drift(state, target_name):
    """Kept patterns whose evidence may no longer hold at the target's current revision.

    Three outcomes per pattern, and only the first one is silence:

    * the files it cites did not change between the recorded revision and now — reusable;
    * they changed — the symbol may have moved, been renamed or deleted, so the pattern
      has to be re-recalled before it may be trusted;
    * the comparison cannot be made (no revision recorded, target is not a git repo, the
      recorded commit is absent from this clone, the tree is dirty) — **every** kept
      pattern needs re-verification. Unknown is not absence: a pattern that cannot be
      checked against the code it describes is exactly as unreliable as one known stale.
    """
    from vcs import changed_paths
    kept = knowledge_base(target_name)
    if not kept or not kept.get('patterns'):
        return []
    stamps = kept.get('revisions') or {}
    rows = []
    for target in state.get('targets', []):
        recorded = (stamps.get(target['id']) or {}).get('revision')
        moved = changed_paths(target['path'], recorded)
        if moved is None:
            reason = ('知识库没有记录该目标的 revision' if not recorded else
                      '无法与记录的 revision %s 比对（目标不是 git 仓、该提交不在本克隆里，'
                      '或 git 不可用）' % recorded[:12])
            for row in kept['patterns']:
                rows.append({'pattern_id': row.get('id'), 'target': target['id'],
                             'reason': reason, 'files': [], 'verdict': 'unverifiable'})
            continue
        if (stamps.get(target['id']) or {}).get('dirty'):
            for row in kept['patterns']:
                rows.append({'pattern_id': row.get('id'), 'target': target['id'],
                             'reason': '知识库是在有未提交改动的工作树上产出的，'
                                       'revision 描述不了当时读到的代码',
                             'files': [], 'verdict': 'unverifiable'})
            continue
        touched = set(moved)
        for row in kept['patterns']:
            cited = cited_paths(row)
            cited = {p for p in cited if p}
            # Exact, repo-relative comparison. A looser match (endswith either way) was
            # tried and silently accepted patch text as if it were a path list, so a
            # content diff would have appeared to work while reporting nothing real.
            hit = sorted(p for p in cited if p in touched)
            if hit:
                rows.append({'pattern_id': row.get('id'), 'target': target['id'],
                             'reason': '依据文件在 %s..HEAD 之间变了' % recorded[:12],
                             'files': hit, 'verdict': 'stale'})
    return rows


def status(workspace, state, target_name=None):
    """What a later audit of the same target must settle before it starts."""
    from vcs import revision
    target_name = target_name or state.get('target_id')
    kept = knowledge_base(target_name)
    rows = drift(state, target_name)
    fresh = {row['id'] for row in load_target_patterns(workspace)}
    unresolved = [row for row in rows if row['pattern_id'] not in fresh]
    return {
        'target': target_name,
        'knowledge_base': None if not kept else {
            'patterns': len(kept.get('patterns') or []),
            'revisions': kept.get('revisions') or {}},
        'current_revisions': {t['id']: revision(t['path']) for t in state.get('targets', [])},
        'drifted': rows,
        'unresolved': unresolved,
        'note': '受影响的模式要重新召回（recall --apply 会以新证据覆盖同一条），'
                '确认已不存在的从知识库里删掉。一阶段冻结前必须清零。'}


def main():
    if len(sys.argv) != 3:
        print(json.dumps({'error': 'usage: recall.py <workspace> <patterns.json>'},
                         ensure_ascii=False), file=sys.stderr)
        return 2
    from knowledge import read
    workspace = Path(sys.argv[1])
    state = read(workspace / 'audit.json')
    try:
        print(json.dumps(apply_patterns(workspace, state, sys.argv[2]),
                         ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
