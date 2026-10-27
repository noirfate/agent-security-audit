#!/usr/bin/env python3
"""Validate structure and explicit counts, then render full evidence for model review.
No wording, relevance, evidence sufficiency or severity decision is made here."""
import json
import re
from pathlib import Path

from knowledge import SKILL, read

RETURN_RE = re.compile(r'候选\s*(\d+)\s*\(confirmed=(\d+),\s*fp=(\d+),\s*unclosed=(\d+)\)')


def _mechanical(workspace, state, unit, payload, *, replace=False):
    """Everything whose answer is fixed by the files. Returns a list of problems."""
    from merge import validate_partial, would_introduce, legacy_product
    problems = []
    problems += ['产物结构：' + p for p in validate_partial(state, unit, payload, legacy=legacy_product(workspace, unit, payload), replace=replace)]
    if problems:
        return problems                      # a refused product has nothing to review

    # Would merging break the shared record? Asked through the same path the real merge
    # takes, so the answer here and the merge's own decision cannot drift apart.
    problems += ['合入试算：' + e for e in would_introduce(workspace, state, unit['id'], replace=replace)]

    # Optional search annotations are checked by merge; raw matches are not tasks.
    done = (payload.get('progress') or {}).get('files_done')
    if done is not None and int(done) != unit['file_count']:
        problems.append('文件分母：已处理 %s / 本单元 %d' % (done, unit['file_count']))

    line = payload.get('return_line') or ''
    match = RETURN_RE.search(line)
    if not match:
        problems.append('return 行：缺失或格式不符（候选 N (confirmed=a, fp=b, unclosed=c) …）')
    else:
        # The denominators are fixed in roles/worker.md: the three terminal states count
        # findings, not checks, and a false positive is one the worker deleted. So the
        # rows still in the product are exactly the confirmed plus the unclosed ones.
        # Four units gave four different readings of this line the first time.
        total, confirmed, false_positive, unclosed = (int(g) for g in match.groups())
        findings = payload.get('findings') or []
        kept = len(findings)
        if confirmed + unclosed != kept:
            problems.append('return 行：confirmed=%d 加 unclosed=%d 应等于产物里的发现数 %d'
                            % (confirmed, unclosed, kept))
        if total != kept + false_positive:
            problems.append('return 行：候选 %d 应等于发现数 %d 加 fp=%d'
                            % (total, kept, false_positive))
        if not legacy_product(workspace, unit, payload):
            dismissed = payload.get('dismissed_candidates') or []
            if false_positive != len({r['id'] for r in dismissed}):
                problems.append('return 行：fp 必须等于 dismissed_candidates 中的独立候选号数量')
    for row in payload.get('findings') or []:
        if row.get('status') != 'needs_review':
            problems.append('发现状态：%s 是 %s，候选必须从 needs_review 起'
                            % (row.get('id'), row.get('status')))
    return problems


def evidence_leads(state, payload):
    """Evidence whose observation carries a mechanism the check that took it never asks about.

    Measured: an observation stating that `env.PATH` was spliced unescaped into
    `export PATH` and handed to the container's `sh -lc` was cited by exactly one check,
    whose proposition is resource quota, so the injection it describes reached no
    proposition at all and the report concluded denial of service. Nothing in the flow
    asked「这条证据还证明了别的什么」, because every denominator is a check and this was
    written into an observation.

    The word pairs are a sampling floor, not a verdict: one group names a dangerous
    construction, the other an interpreter or a boundary, and only their co-occurrence
    puts an item on the list. A lead closes three ways, all of them already recorded —
    a second check citing the same evidence, or the evidence id named in `method_notes`
    or in a `crosslead`.
    """
    spec = read(SKILL / 'references' / 'evidence_semantics.json')
    construction = [re.compile(pattern, re.I) for pattern in spec['construction']]
    boundary = [re.compile(pattern, re.I) for pattern in spec['boundary']]
    checks = {c['id']: c for c in (state.get('checks') or [])}
    checks.update({c['id']: c for c in (payload.get('checks') or [])})
    cited = {}
    for check in checks.values():
        for eid in (check.get('evidence_ids') or []) + (check.get('counterevidence_ids') or []):
            cited.setdefault(eid, set()).add(check['id'])
    answered = json.dumps({'notes': payload.get('method_notes') or [],
                           'crossleads': payload.get('crossleads') or []}, ensure_ascii=False)
    leads = []
    for row in payload.get('evidence') or []:
        if row.get('kind') != 'code' or len(cited.get(row['id'], ())) != 1:
            continue
        text = row.get('observation') or ''
        made = next((p.pattern for p in construction if p.search(text)), None)
        crossed = next((p.pattern for p in boundary if p.search(text)), None)
        if not (made and crossed):
            continue
        leads.append({'evidence_id': row['id'], 'cited_by': sorted(cited[row['id']]),
                      'matched': [made, crossed], 'observation': text,
                      'open': row['id'] not in answered})
    return leads


def _worklist(workspace, state, unit, payload):
    """Render full semantic context without prose or evidence truncation."""
    from merge import legacy_product
    evidence = {e['id']: e for e in state.get('evidence') or []}
    evidence.update({e['id']: e for e in payload.get('evidence') or []})
    checks = {c['id']: c for c in state.get('checks') or []}
    checks.update({c['id']: c for c in payload.get('checks') or []})
    lines = ['# 核验清单 · %s（%s）' % (unit['id'], unit['title']), '',
             '已核对结构、引用、指纹、行号、显式任务状态与计数一致性。',
             '未核对语义：scope 是否合理、证据是否足够、反证是否相关、措辞含义和定级均由复核者判断。',
             '这是导航材料；可读取 partial.json、共享记录及原始材料。以下保留检查记录、可选分析笔记与原证据。', '']
    if legacy_product(workspace, unit, payload):
        lines += ['旧契约产物：历史 fp 仅为原始自报数，未补造候选到反证的关联；未按新契约验证。', '']
    lines += ['## 撤下候选的明确关联', '',
              '不得用无关 not_established 检查凑数；核对每个候选与所引反证的语义关系。', '']
    for row in payload.get('dismissed_candidates') or []:
        lines += ['```json', json.dumps(row, ensure_ascii=False, indent=2), '```', '']
    selected = {c['id'] for c in payload.get('checks') or []}
    selected |= {cid for r in payload.get('dismissed_candidates') or [] for cid in r.get('check_ids') or []}
    referenced = set()
    for cid in sorted(selected):
        check = checks.get(cid) or {'id': cid}
        lines += ['## 检查 %s · %s' % (cid, check.get('verdict', '')), '',
                  '核对命题在目标中的检查方式、实例、版本、scope、结论依据与反证；条件笔记可选，不以参考条件逐条满足代替语义复核。',
                  '```json', json.dumps(check, ensure_ascii=False, indent=2), '```', '']
        ids = set(check.get('evidence_ids') or []) | set(check.get('counterevidence_ids') or [])
        for criterion in (check.get('prerequisites') or []) + (check.get('criteria') or []):
            ids.update(criterion.get('evidence_ids') or [])
        referenced.update(ids)
    lines += ['## 原始证据（按 ID 去重，内容完整保留）', '']
    for eid in sorted(referenced):
        row = evidence.get(eid) or {'id': eid, 'missing': True}
        material = state['materials'].get(row.get('material_id')) or {}
        lines += ['### 证据 %s · %s' % (eid, material.get('path', '动态观察')), '',
                  '```json', json.dumps(row, ensure_ascii=False, indent=2), '```', '']
    leads = evidence_leads(state, payload)
    if leads:
        lines += ['## 证据语义剩余项', '',
                  '这些观察里同时出现了「危险构造」与「解释器／边界」，而只有一条检查引用它——'
                  '那条检查的命题未必问到观察里已经写出来的机制。逐条回答一个问题：'
                  '**这段观察是否还支持本检查之外的失效机制？**',
                  '三种答案都算闭合：立本地检查（`CHK-…-09xx` 引用同一条证据）、'
                  '在 `method_notes` 里写明为何不适用（句中带上证据号）、'
                  '或转 `crosslead`（同样带上证据号）。',
                  '词表（`references/evidence_semantics.json`）是兜底取样，不是判定：'
                  '共现不代表漏洞，零命中也不代表没有。', '']
        for lead in leads:
            lines += ['### %s%s' % (lead['evidence_id'], '' if lead['open'] else '（已闭合）'), '',
                      '```json', json.dumps(lead, ensure_ascii=False, indent=2), '```', '']
    lines += ['## 发现的机理、影响范围与定级', '']
    for row in payload.get('findings') or []:
        lines += ['```json', json.dumps(row, ensure_ascii=False, indent=2), '```', '']
    lines += ['## 可选检索信息', '',
              '语言零匹配只描述检索结果；有匹配也不表示覆盖，不需按语言补交结论。',
              json.dumps(unit.get('blind_languages') or {}, ensure_ascii=False), '',
              '## 交接、对账任务与范围说明', '']
    for key in ('crossleads', 'reconciliations', 'scope_notes', 'method_notes'):
        lines += ['```json', json.dumps({key: payload.get(key) or []}, ensure_ascii=False, indent=2), '```', '']
    return '\n'.join(lines) + '\n'


def prepare(workspace, state, unit_id, *, replace=False):
    workspace = Path(workspace)
    unit = next((u for u in state.get('units', []) if u['id'] == unit_id), None)
    if unit is None:
        raise ValueError('Unknown unit: ' + unit_id)
    path = workspace / 'units' / unit_id / 'partial.json'
    if not path.is_file():
        raise ValueError('No product to review at ' + str(path))
    payload = read(path)
    problems = _mechanical(workspace, state, unit, payload, replace=replace)
    out = workspace / 'units' / unit_id / 'review_worklist.md'
    if problems:
        return {'unit': unit_id, 'mechanical': 'FAIL', 'problems': problems,
                'worklist': None,
                'note': '机械判据未过：退回订正，先不要派复核者。这些项不该由模型人工重做。'}
    out.write_text(_worklist(workspace, state, unit, payload), encoding='utf-8')
    semantic = {
        'decisive': sum(c.get('verdict') == 'confirmed' for c in payload.get('checks') or []),
        'counterevidence': len(payload.get('dismissed_candidates') or []),
        'negative': sum(c.get('verdict') in {'not_established', 'not_applicable', 'insufficient_evidence'}
                        for c in payload.get('checks') or []),
        'findings': len(payload.get('findings') or []),
        'checks_total': len(payload.get('checks') or []),
        'verdicts': {verdict: sum(c.get('verdict') == verdict for c in payload.get('checks') or [])
                     for verdict in ('confirmed', 'not_established', 'not_applicable', 'insufficient_evidence')},
        'unfinished_checks': sum(c.get('status') != 'complete' for c in payload.get('checks') or []),
        'dismissed_candidates': len(payload.get('dismissed_candidates') or []),
    }
    leads = evidence_leads(state, payload)
    semantic['evidence_leads'] = {'flagged': len(leads),
                                  'open': sum(1 for lead in leads if lead['open']),
                                  'ids': [lead['evidence_id'] for lead in leads if lead['open']]}
    return {'unit': unit_id, 'mechanical': 'PASS', 'problems': [],
            'worklist': str(out), 'semantic_items': semantic, 'merge_mode': 'replace' if replace else 'merge',
            'note': 'checks_total 是检查分母，verdicts 是裁决分项；counterevidence 是撤下候选号数，不是反证检查数。'
                    'evidence_leads.open 大于 0 表示还有证据没人回答「它是否还支持别的失效机制」，'
                    '清单里逐条列着；取样词表是兜底，判断仍由模型做。清单保留全部检查与原证据，复核仍需回源。'}
