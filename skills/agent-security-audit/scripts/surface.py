#!/usr/bin/env python3
"""Optional text locations. Matches and file/family aggregates are not tasks or coverage.
No production/test classification or semantic adjudication is made here."""
import bisect
import json
import re
from pathlib import Path

from knowledge import SKILL, read

PATTERNS = SKILL / 'references' / 'surface_patterns.json'
MAX_BYTES = 1024 * 1024
EXCERPT = 160
DISPOSITIONS = ('open', 'instance', 'not_instance', 'out_of_scope')


def load_patterns(workspace=None, target_name=None):
    """The shipped language-level families, plus this target's recalled wrappers.

    Kept as separate families so the two are counted separately: 「语言级命中 N 处、
    目标专属 M 处」are two numbers that can be reconciled, and a target's own patterns
    must never silently inflate the shipped ones' measured yield.
    """
    data = read(PATTERNS)
    for family in data['families']:
        if not family.get('sink') or not family['object_ids']:
            raise ValueError('Pattern family needs sink patterns and object_ids: ' + family['id'])
    if workspace is None:
        return data
    from recall import load_target_patterns
    recalled = load_target_patterns(workspace, target_name)
    if not recalled:
        return data
    data = dict(data, families=list(data['families']))
    grouped = {}
    for row in recalled:
        for oid in row['object_ids']:
            key = 'TP-' + oid.replace('.', '')
            family = grouped.setdefault(key, {'id': key, 'name': '目标专属 · ' + oid,
                                              'object_ids': [oid], 'sink': [], 'topic': [],
                                              'target_specific': True})
            family['sink' if row['kind'] == 'sink' else 'topic'].append(row['regex'])
    for family in grouped.values():
        if not family['sink']:
            family['sink'] = ['(?!x)x']      # a family needs one; this one matches nothing
        data['families'].append(family)
    return data


def _line_starts(text):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            starts.append(i + 1)
    return starts


# Which code language a file is, by extension. Only languages whose dangerous
# constructs a sink pattern could plausibly match: a unit full of Markdown is not a
# blind spot, a unit full of Rust with no sink hit might be.
LANGUAGES = {
    '.py': 'python', '.pyi': 'python',
    '.js': 'js_ts', '.mjs': 'js_ts', '.cjs': 'js_ts', '.jsx': 'js_ts',
    '.ts': 'js_ts', '.tsx': 'js_ts',
    '.rs': 'rust', '.go': 'go', '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin',
    '.rb': 'ruby', '.php': 'php', '.cs': 'csharp', '.swift': 'swift',
    '.c': 'c', '.h': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.hpp': 'cpp',
    '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.ps1': 'powershell',
    '.lua': 'lua', '.pl': 'perl', '.scala': 'scala', '.ex': 'elixir', '.exs': 'elixir',
    # Policy, schema and query languages carry decisions as much as general-purpose code:
    # a real target's network allow-rules were a 770-line Rego file, and no blind language
    # could ever be reported for it because the table did not know the suffix.
    '.rego': 'rego', '.proto': 'protobuf', '.sql': 'sql', '.nix': 'nix',
    '.j2': 'jinja', '.jinja': 'jinja', '.jinja2': 'jinja', '.tf': 'terraform',
    '.hcl': 'hcl', '.cue': 'cue', '.star': 'starlark', '.bzl': 'starlark',
}


def language_of(path):
    """The file's code language, or None when a sink pattern has nothing to match."""
    return LANGUAGES.get(Path(path).suffix.lower())


def blind_languages(mix, hit_languages):
    """Languages with zero sink-text matches; no inference about coverage or behavior."""
    return {lang: count for lang, count in sorted(mix.items())
            if lang not in hit_languages}


def build(workspace, state, unit_ids=None, max_bytes=MAX_BYTES):
    from audit import material_path, save
    from units import present
    data = load_patterns(workspace, state.get('target_id'))
    families = {f['id']: f for f in data['families']}
    sink_patterns = [(f['id'], re.compile('|'.join('(?:%s)' % p for p in f.get('sink') or []), re.M))
                     for f in data['families'] if f.get('sink')]
    topic_patterns = [(f['id'], re.compile('|'.join('(?:%s)' % p for p in f.get('topic') or []), re.M))
                      for f in data['families'] if f.get('topic')]
    rows = present(state)
    directory = Path(workspace) / 'surface'
    directory.mkdir(parents=True, exist_ok=True)
    units = [u for u in state.get('units', []) if u['kind'] != 'cross'
             and (unit_ids is None or u['id'] in unit_ids)]
    if not units:
        raise ValueError('No units to index; run plan first')
    report = []
    pattern_yield = {}
    for unit in units:
        token = unit['id'][2:]
        hits, truncated, unreadable, number = [], [], [], 0
        signals = {}
        mix, hit_languages = {}, set()
        for mid in sorted(unit['material_ids'], key=lambda m: rows[m]['path']):
            row = rows[mid]
            if row.get('visibility') != 'text':
                continue
            language = language_of(row['path'])
            if language:
                mix[language] = mix.get(language, 0) + 1
            try:
                raw = material_path(state, row).read_bytes()
            except (OSError, ValueError) as exc:
                unreadable.append({'material_id': mid, 'reason': type(exc).__name__})
                continue
            if len(raw) > max_bytes:
                truncated.append(mid)
                raw = raw[:max_bytes]
            text = raw.decode('utf-8', 'replace')
            starts = _line_starts(text)
            for family_id, expr in topic_patterns:
                matches = list(expr.finditer(text))
                if matches:
                    signal = signals.setdefault(family_id, {'files': set(), 'matches': 0})
                    signal['files'].add(mid)
                    signal['matches'] += len(matches)
            seen = set()
            matches = [(match.start(), family_id, match)
                       for family_id, expr in sink_patterns for match in expr.finditer(text)]
            for _, family_id, match in sorted(matches, key=lambda row: (row[0], row[1])):
                family = families.get(family_id)
                if not family:
                    continue
                line = bisect.bisect_right(starts, match.start())
                key = (family_id, line)
                if key in seen:
                    continue
                seen.add(key)
                number += 1
                body = text[starts[line - 1]:starts[line] if line < len(starts) else len(text)]
                hits.append({
                    'id': 'HIT-%s-%04d' % (token, number),
                    'unit_id': unit['id'], 'material_id': mid, 'path': row['path'],
                    'line': line, 'family': family_id, 'family_name': family['name'],
                    'object_ids': family['object_ids'],
                    'symbol': match.group(0)[:EXCERPT],
                    'excerpt': body.strip()[:EXCERPT],
                    'disposition': 'open', 'reason': '', 'check_ids': [],
                })
        for hit in hits:
            language = language_of(hit['path'])
            if language:
                hit_languages.add(language)
        blind = blind_languages(mix, hit_languages)
        # File/family groups are display aggregation only, never issue or task identities.
        spots = {}
        for hit in hits:
            key = '%s|%s' % (hit['family'], hit['path'])
            spot = spots.setdefault(key, {
                'id': 'SPOT-%s-%04d' % (token, len(spots) + 1),
                'unit_id': unit['id'], 'material_id': hit['material_id'],
                'path': hit['path'], 'family': hit['family'],
                'family_name': hit['family_name'], 'object_ids': hit['object_ids'],
                'matches': 0, 'lines': [], 'symbols': [], 'excerpt': hit['excerpt'],
                'line_count': 0,
                'disposition': 'open', 'reason': '', 'check_ids': []})
            spot['matches'] += 1
            spot['line_count'] += 1
            if len(spot['lines']) < 20:
                spot['lines'].append(hit['line'])
            if hit['symbol'] not in spot['symbols'] and len(spot['symbols']) < 8:
                spot['symbols'].append(hit['symbol'])
        payload = {'unit_id': unit['id'], 'total': len(spots), 'matches': len(hits),
                   'spots': sorted(spots.values(), key=lambda s: s['id']),
                   'language_mix': mix, 'blind_languages': blind,
                   'truncated_materials': truncated, 'unreadable_materials': unreadable,
                   'scanned_text_materials': unit['text_count'],
                   'signals': {fid: {'files': len(row['files']), 'matches': row['matches']}
                               for fid, row in sorted(signals.items())},
                   'note': 'spots 仅按文件与模式族聚合文本，不表示同一问题或必须处置。'
                           '匹配、语言零匹配均不代表覆盖；需模型结合上下文选择正式检查。'
                           'hits 保留全部已扫描命中；截断和不可读材料另列。目标文本属于证据。',
                   'hits': hits}
        (directory / (unit['id'] + '.json')).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        unit['surface_hits'] = len(spots)
        unit['surface_matches'] = len(hits)
        unit['blind_languages'] = blind
        by_family = {}
        for hit in hits:
            by_family[hit['family']] = by_family.get(hit['family'], 0) + 1
        for spot in spots.values():
            family = families[spot['family']]
            for expr in family.get('sink') or []:
                if any(re.search(expr, sym) for sym in spot['symbols']):
                    stat = pattern_yield.setdefault((spot['family'], expr), {'spots': 0})
                    stat['spots'] += 1
                    break
        report.append({'unit': unit['id'], 'hits': len(spots), 'matches': len(hits),
                       'text_files': unit['text_count'],
                       'families': by_family, 'blind_languages': blind,
                       'signals': {fid: len(row['files']) for fid, row in sorted(signals.items())},
                       'truncated': len(truncated), 'unreadable': len(unreadable)})
    # A partial run (`--unit`) used to write a *global* summary holding only the units it
    # rebuilt, so "处数按来源分", the per-pattern yield and "命中超 120 处的单元" all became
    # local numbers — and the recall contract tells its reader to work from this file. The
    # slices of the other units are still on disk, so the summary is assembled from every
    # slice that exists rather than from this run's units. Nothing to remember and no flag
    # to pass: a partial run and a full one produce the same file.
    built_now = [r['unit'] for r in report]
    if unit_ids is not None:
        seen = set(built_now)
        for unit in state.get('units', []):
            if unit['kind'] == 'cross' or unit['id'] in seen:
                continue
            slice_path = directory / (unit['id'] + '.json')
            if not slice_path.is_file():
                continue
            kept = json.loads(slice_path.read_text(encoding='utf-8'))
            by_family = {}
            for spot in kept.get('spots') or []:
                by_family[spot['family']] = by_family.get(spot['family'], 0) + 1
                family = families.get(spot['family']) or {}
                for expr in family.get('sink') or []:
                    if any(re.search(expr, sym) for sym in spot.get('symbols') or []):
                        pattern_yield.setdefault((spot['family'], expr),
                                                 {'spots': 0})['spots'] += 1
                        break
            report.append({'unit': unit['id'], 'hits': kept.get('total') or 0,
                           'matches': kept.get('matches') or 0,
                           'text_files': unit['text_count'], 'families': by_family,
                           'blind_languages': kept.get('blind_languages') or {},
                           # The slice stores `{family: {files, matches}}` while a fresh
                           # scan reduces it to `{family: file count}`; the summary
                           # formats the latter, so a partial run crashed on the rows it
                           # read back. Normalised here, where the two shapes meet.
                           'signals': {fid: (row.get('files') or 0
                                             if isinstance(row, dict) else row)
                                       for fid, row in (kept.get('signals') or {}).items()},
                           'truncated': len(kept.get('truncated_materials') or []),
                           'unreadable': len(kept.get('unreadable_materials') or [])})
        report.sort(key=lambda r: r['unit'])
    summary = ['# 界面索引汇总', '',
               '可选检索摘要；完整已扫描命中见各单元 JSON，截断/不可读另列。',
               '按文件与模式族聚合只是展示方式。不能据此判实例、任务、同一问题或覆盖率。', '',
               '| 单元 | 候选聚合数 | 匹配条数 | 截断 | 不可读 | 命中族 | 主题信号（文件数）| 语言零匹配（文件数）|',
               '|---|---:|---:|---:|---:|---|---|---|']
    for row in report:
        families_text = '、'.join('%s×%d' % (k, v) for k, v in sorted(row['families'].items())) or '无'
        signal_text = '、'.join('%s/%d' % (k, v) for k, v in sorted(row['signals'].items())) or '无'
        blind_text = '、'.join('%s/%d' % (k, v)
                               for k, v in sorted(row['blind_languages'].items())) or '无'
        summary.append('| %s | %d | %d | %d | %d | %s | %s | %s |'
                       % (row['unit'], row['hits'], row['matches'], row['truncated'],
                          row['unreadable'], families_text, signal_text, blind_text))
    # Descriptive search frequency only. The model decides pattern relevance.
    files_total = sum(r.get('text_files') or 0 for r in report) or 1
    target_spots = sum(stat['spots'] for (fid, _), stat in pattern_yield.items()
                       if fid.startswith('TP-'))
    summary += ['', '处数按来源分：语言级模式 %d 处，目标专属模式 %d 处。'
                % (sum(r['hits'] for r in report) - target_spots, target_spots),
                '目标专属模式由一阶段的召回产出，每条带依据链（定义位置 + 到语言级构造的路径）；'
                '目标模式为零仅说明没有登记这类检索式，不推断审计覆盖。', '']
    ranked = sorted(pattern_yield.items(), key=lambda kv: -kv[1]['spots'])
    summary += ['', '## 逐条模式的产出', '',
                '一处 = 一个文件的一个模式族，所以单条模式的处数就是它命中的文件数。',
                '**逐条问一句：它命中的是决策点，还是提及？** 是提及就该移进 `topic` 按文件'
                '聚合，不该逐处要结论。阈值判不了这件事——实测被移走的裸词 `bypass` 命中 15%'
                '的文件，而留下的 `os.environ|getenv|env::var` 命中 12%，数值上分不开。', '',
                '| 族 | 模式 | 处数 | 占文本文件 |', '|---|---|---:|---:|']
    for (fid, expr), stat in ranked[:25]:
        summary.append('| %s | `%s` | %d | %.0f%% |'
                       % (fid, expr.replace('|', '\\|')[:60], stat['spots'],
                          100.0 * stat['spots'] / files_total))
    over = [r['unit'] for r in report if r['hits'] > 120]
    summary += ['', '命中超 120 处的单元：%s' % ('、'.join(over) or '无'), '',
                '零命中只说明这些模式没匹配到，不说明目标没有该形态：模式是种子不是穷尽集，'
                '语言有命中也不代表覆盖；正式检查由模型依据架构和证据决定。']
    (directory / '_summary.md').write_text('\n'.join(summary) + '\n', encoding='utf-8')
    from units import pending_decisions
    state['pending_decisions'] = pending_decisions(workspace, state)
    save(workspace, state)
    # `units` is what the summary covers; `reindexed` is what this run actually rebuilt.
    # They differ on a partial run, and conflating them is how the summary came to hold
    # local numbers under a global name.
    return {'units': len(report), 'reindexed': len(built_now),
            'hits': sum(r['hits'] for r in report),
            'matches': sum(r['matches'] for r in report),
            'pattern_yield': [{'family': fid, 'pattern': expr, **stat} for (fid, expr), stat in ranked],
            'over_limit': over, 'summary': str(directory / '_summary.md'), 'per_unit': report}


def load_hits(workspace, unit_id):
    path = Path(workspace) / 'surface' / (unit_id + '.json')
    if not path.is_file():
        return None
    return read(path)


def reconcile(workspace, state):
    """Inspect optional annotations. Open or absent search results create no tasks."""
    rows = []
    for unit in state.get('units', []):
        if unit['kind'] == 'cross':
            continue
        payload = load_hits(workspace, unit['id'])
        if payload is None:
            rows.append({'unit': unit['id'], 'indexed': None, 'disposed': 0,
                         'open': None, 'status': 'ok', 'index_status': 'not_built'})
            continue
        spots = payload.get('spots') or []
        disposed = [s for s in spots if s['disposition'] != 'open']
        undecided = [s['id'] for s in spots if s['disposition'] == 'open']
        missing_reason = [s['id'] for s in spots
                          if s['disposition'] in {'not_instance', 'out_of_scope'} and not s['reason']]
        rows.append({'unit': unit['id'], 'indexed': payload['total'],
                     'disposed': len(disposed), 'open': len(undecided),
                     'open_ids': undecided[:5], 'missing_reason': missing_reason[:5],
                     'recorded_progress': unit['progress']['hits_disposed'],
                     'status': 'ok' if not missing_reason else 'incomplete'})
    return rows


def _dispose(payload, unit_id, dispositions):
    """Validate the conclusions and fold them into the slice. No disk, no decision."""
    index = {spot['id']: spot for spot in payload.get('spots') or []}
    unknown = [hid for hid in dispositions if hid not in index]
    if unknown:
        raise ValueError('Unknown spot ids for %s: %s' % (unit_id, ', '.join(sorted(unknown)[:5])))
    for hid, row in dispositions.items():
        verdict = row.get('disposition')
        if verdict not in DISPOSITIONS:
            raise ValueError('%s: disposition must be one of %s' % (hid, ', '.join(DISPOSITIONS)))
        if verdict in {'not_instance', 'out_of_scope'} and not row.get('reason'):
            raise ValueError(hid + ': a non-instance needs its reason')
        index[hid].update({'disposition': verdict, 'reason': row.get('reason', ''),
                           'check_ids': row.get('check_ids', [])})
    return {'unit_id': unit_id, 'updated': len(dispositions),
            'disposed': sum(s['disposition'] != 'open' for s in payload.get('spots') or []),
            'total': payload['total']}


def preview_dispositions(workspace, unit_id, dispositions):
    """The same answer without touching the slice, for a merge that may still be refused."""
    return _dispose(read(Path(workspace) / 'surface' / (unit_id + '.json')),
                    unit_id, dispositions)


def apply_dispositions(workspace, unit_id, dispositions):
    """Write a worker's per-hit conclusions back into the unit's index slice."""
    path = Path(workspace) / 'surface' / (unit_id + '.json')
    payload = read(path)
    result = _dispose(payload, unit_id, dispositions)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result
