"""Small source-bound records for attribution and report-organization tests.

This file only creates a caller-owned temporary workspace. It never changes an
installed skill or the source audit. Fixtures preserve the current record shape
and bind every current finding through the real review ledger.

Call build_case(tmp_path, "merged", skill_dir) and pass its workspace/state to
the reporting implementation. EXPECTED is deliberately authored independently
of the implementation under test.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True

EXPECTED = {
    "empty": {"current": [], "high": [], "reports": [], "ext": [], "vulnerabilities": []},
    "small": {
        "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "high": ["F-AA01-01", "F-BB01-01"],
        "reports": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "vulnerabilities": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "ext": [],
    },
    "mixed": {
        "current": ["F-AA01-01", "F-CC01-02"],
        "high": ["F-AA01-01"],
        "reports": ["F-AA01-01", "F-CC01-02"],
        "vulnerabilities": ["F-AA01-01", "F-CC01-02"],
        "ext": [],
        "not_current": ["F-BB01-01", "F-CC01-01"],
    },
    "merged": {
        "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "high": ["RC-01", "F-CC01-01"],
        "reports": ["RC-01", "F-CC01-01", "F-CC01-02"],
        "vulnerabilities": ["RC-01", "F-CC01-01", "F-CC01-02"],
        "ext": [],
        "members": {"RC-01": ["F-AA01-01", "F-BB01-01"]},
    },
    "ext": {
        "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "high": ["F-AA01-01", "F-BB01-01"],
        "reports": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "vulnerabilities": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "ext": ["CHAIN-AA01-01", "CHAIN-CC01-01"],
        "candidate": ["CHAIN-CC01-01"],
        "not_ext": ["CHAIN-BB01-01"],
    },
    "zero_current": {
        "current": [], "high": [], "reports": [], "ext": [], "vulnerabilities": [],
        "not_current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
    },
}

# The shapes preserve the pilot's duplicate-observation / independent-control /
# check-only-chain distinctions. Identifiers and content are deliberately generic.
EXPECTED["grouped"] = {
    "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
    "high": ["F-AA01-01", "F-BB01-01"],
    "vulnerabilities": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
    "reports": ["REPORT-ACCESS", "REPORT-TASK"], "ext": [],
}
EXPECTED["non_independent"] = {
    "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
    "high": ["F-AA01-01"], "vulnerabilities": ["F-AA01-01"],
    "reports": ["F-AA01-01"], "ext": [],
    "pending": ["F-BB01-01"], "observations": ["F-CC01-02"],
    "supplements": ["F-CC01-01"],
}
EXPECTED["check_chain"] = {
    **deepcopy(EXPECTED["small"]), "ext": ["CHAIN-AA01-02"],
    "candidate": ["CHAIN-AA01-02"],
}


def _fixture_module(skill_dir):
    scripts = Path(skill_dir).resolve() / "scripts"
    sys.path.insert(0, str(scripts))
    spec = importlib.util.spec_from_file_location(
        "report_fixture_origin", scripts / "self_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _give_meaning(state):
    """Use actual field relationships rather than a bag of ids and empty prose."""
    titles = {
        "F-AA01-01": "网络入口把调用方自报身份用于读取其他用户的凭据",
        "F-BB01-01": "管理通道对同一凭据读取器缺少归属检查",
        "F-CC01-01": "任务消息可选择另一会话的输出目录",
        "F-CC01-02": "错误响应暴露内部请求标识",
    }
    mechanisms = {
        "F-AA01-01": "handler 直接使用请求头中的 user_id 查询凭据表，既不认证调用者，也不比较凭据所有者。",
        "F-BB01-01": "管理入口虽然检查令牌存在，但将自报 user_id 传入同一读取器，没有绑定令牌主体。",
        "F-CC01-01": "输出目录由消息中的 session_id 拼接得到，落盘前没有确认会话归属。",
        "F-CC01-02": "解析失败时错误响应直接包含进程内部生成的 request_id。",
    }
    impacts = {
        "F-AA01-01": "能接触网络入口的主体可读取其他用户的服务凭据。",
        "F-BB01-01": "持有管理通道令牌的主体可跨用户读取凭据；本路径需要既有管理权限。",
        "F-CC01-01": "取得任务会话后可以把输出写入另一会话目录。",
        "F-CC01-02": "调用者能够关联内部请求标识，现有证据不支持凭据泄露或命令执行。",
    }
    severities = ["critical", "high", "medium", "low"]
    exposures = ["EXT", "ADJ", "INT", "EXT"]
    for row, severity, exposure in zip(state["findings"], severities, exposures):
        fid = row["id"]
        row.update(title=titles[fid], mechanism=mechanisms[fid], impact=impacts[fid],
                   severity=severity, exposure=exposure,
                   severity_reason="按此入口已有的权限前提和证据支持的影响定级。",
                   responsibility="示例组件维护者",
                   validation="仅静态走查；未启动目标或执行端到端利用。",
                   residual_risk="运行期入口的网络限制未纳入本夹具。")
    for row in state["checks"]:
        row["explanation"] = "已读入口到资源访问器的调用链，调用方身份未绑定资源归属。"
    for row in state["evidence"]:
        row["observation"] = "本位置把入站标识传到资源读取器；前置包装层没有添加主体校验。"
    state["chains"] = []
    state["root_causes"] = []
    state["report_todos"] = []


def _review(workspace, state, decisions=None):
    """Rebind review fingerprints after meaningful fixture variations."""
    from review import record_review
    decisions = decisions or {}
    state["reviews"] = []
    for row in list(state["findings"]):
        record_review(workspace, state, row["id"], {
            "reviewer": "同一模型回源复核（报告检查夹具）；非独立实现验证",
            "decision": decisions.get(row["id"], "retain"),
            "rationale": "按当前字段和目标代码位置登记夹具结论。",
            "counterevidence_analysis": "包装层只检查输入格式，未建立主体与资源的对应关系。",
            "evidence_ids": row["evidence_ids"][:1],
            "counterevidence_ids": [],
        })


def build_case(tmp_path, case, skill_dir):
    """Return (workspace, state, independent expectations), all under tmp_path."""
    if case not in EXPECTED:
        raise ValueError("Unknown report fixture: " + case)
    origin = _fixture_module(skill_dir)
    root = Path(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    workspace, state = origin.root_cause_fixture(root)
    _give_meaning(state)
    decisions = {}
    if case == "empty":
        state["findings"] = []
    elif case == "mixed":
        state["findings"][2]["severity"] = "high"
        decisions = {"F-BB01-01": "needs_evidence", "F-CC01-01": "reject"}
    elif case == "merged":
        state["findings"][1]["severity"] = "low"
        state["findings"][2]["severity"] = "high"
        state["findings"][3]["severity"] = "medium"
        merged = deepcopy(origin.MERGE)
        merged.update(statement="共享凭据读取器没有绑定调用主体与资源归属",
                      fix_point="a.ts 的 read_credential()")
        origin.linked(state, [merged])
    elif case == "ext":
        state["chains"] = [
            {"id": "CHAIN-AA01-01", "unit_id": "U-AA01", "entry_exposure": "EXT",
             "title": "外部请求头 → 自报身份 → 他人凭据",
             "description": "静态调用链已定位；没有登记动态复现。",
             "steps": [
                 {"unit_id": "U-AA01", "primitive": "IMPERSONATE",
                  "check_id": "CHK-AA01-0001", "finding_id": "F-AA01-01",
                  "note": "使用 user_id 请求头选择读取主体。"},
                 {"unit_id": "U-BB01", "primitive": "READ",
                  "check_id": "CHK-BB01-0001", "finding_id": "F-BB01-01",
                  "note": "共享读取器返回所选主体的凭据。"},
             ]},
            {"id": "CHAIN-CC01-01", "unit_id": "U-CC01", "entry_exposure": "EXT",
             "status": "candidate", "title": "外部消息 → 任务会话 → 跨会话写入",
             "description": "任务内部写入机制已定位，外部消息进入该任务的调用点仍缺证据。",
             "steps": [{"unit_id": "U-CC01", "primitive": "PERSIST",
                        "check_id": "CHK-CC01-0001", "finding_id": "F-CC01-01",
                        "note": "下游目录选择成立；上游外部入口未闭合。"}]},
            {"id": "CHAIN-BB01-01", "unit_id": "U-BB01", "entry_exposure": "ADJ",
             "title": "本机管理通道 → 自报身份 → 他人凭据",
             "description": "需要同主机访问位置与管理通道令牌。",
             "steps": [{"unit_id": "U-BB01", "primitive": "READ",
                        "check_id": "CHK-BB01-0001", "finding_id": "F-BB01-01",
                        "note": "不应因高影响把 ADJ 改成 EXT。"}]},
        ]
    elif case == "grouped":
        state["findings"][1]["mechanism"] = (
            "另一管理适配器使用独立的读取实现，只检查令牌存在，没有比较资源属主。")
    elif case == "non_independent":
        state["findings"][2].update(
            title="同一读取缺口的附加入口条件", severity="medium",
            mechanism="另一入口到达已确认的读取器，补足请求字段和条件，没有新增失效实现。",
            impact="补充已确认读取缺口的影响范围，不增加独立缺陷。")
        state["findings"][3].update(
            mechanism="错误响应包含非敏感内部 request_id；当前证据显示它只用于追踪。",
            impact="已确认的设计观察，当前证据不支持独立安全影响。")
    elif case == "check_chain":
        state["chains"] = [
            {"id": "CHAIN-AA01-02", "entry_exposure": "EXT", "status": "candidate",
             "title": "外部标识进入跨组件读取与任务路径",
             "description": "比较材料只通过 check_id 关联；组件衔接仍待取证。",
             "steps": [{"check_id": "CHK-AA01-0001", "note": "外部读取观察。"},
                       {"check_id": "CHK-CC01-0001", "note": "任务落点观察，不能省略衔接条件。"}]},
            {"id": "CHAIN-CC01-02", "entry_exposure": "INT",
             "title": "只保留在边界索引的内部观察",
             "steps": [{"check_id": "CHK-CC01-0002", "note": "不增加独立缺陷。"}]},
        ]
    elif case == "zero_current":
        decisions = {row["id"]: ("reject" if i % 2 else "needs_evidence")
                     for i, row in enumerate(state["findings"])}
    _review(workspace, state, decisions)
    adjudicate_fixture(state)
    if case == "non_independent":
        from attribution import decision_digest
        for row in state["finding_dispositions"]:
            fid = row["finding_id"]
            if fid == "F-BB01-01":
                row.update(kind="pending", reason="失效机制已证实，独立归属比较尚未闭合。")
                row.pop("comparison", None)
            elif fid == "F-CC01-01":
                row.update(kind="supplement", target_finding_id="F-AA01-01",
                           reason="同一缺口的补充入口材料。")
                row.pop("comparison", None)
            elif fid == "F-CC01-02":
                row.update(kind="observation", evidence_ids=["E-CC01-002"],
                           reason="已核对为非敏感追踪标识，仅保留设计观察。")
                row.pop("comparison", None)
            row["source_digest"] = decision_digest(state, row)
    if case == "grouped":
        confirm_fixture_plan(state, groups={
            "REPORT-ACCESS": ["F-AA01-01", "F-BB01-01"],
            "REPORT-TASK": ["F-CC01-01", "F-CC01-02"],
        })
    elif case == "ext":
        confirm_fixture_plan(state, scenarios=[{
            "id": "SCENE-ENTRY", "title": "外部入口的不同条件分支",
            "chain_ids": ["CHAIN-AA01-01", "CHAIN-CC01-01"],
            "vulnerability_ids": ["F-AA01-01", "F-BB01-01", "F-CC01-01"],
            "grouping_reason": "共同说明外部入口，但分别保留已定位路径和待定衔接。",
        }], chain_placements=[{
            "chain_id": "CHAIN-BB01-01", "kind": "report", "target_id": "F-BB01-01",
            "reason": "需要管理令牌的邻接路径随对应技术报告呈现。",
        }])
    elif case == "check_chain":
        confirm_fixture_plan(state, scenarios=[{
            "id": "SCENE-CROSS", "title": "跨组件条件与证据边界",
            "chain_ids": ["CHAIN-AA01-02"],
            "vulnerability_ids": ["F-AA01-01", "F-CC01-01"],
            "grouping_reason": "通过检查引用关联不同组件，不改变独立缺陷身份。",
        }], chain_placements=[{
            "chain_id": "CHAIN-CC01-02", "kind": "boundary", "target_id": None,
            "reason": "此内部观察只需在机械链边界索引保留。",
        }])
    else:
        confirm_fixture_plan(state)
    from audit import save
    save(workspace, state)
    return workspace, state, deepcopy(EXPECTED[case])


def add_large_record(state, size=150_000):
    """One indivisible record may exceed the shard target; nothing may be cut."""
    row = state["evidence"][0]
    prefix = "开始 <T> | `code`\n```\n"
    suffix = "\n```\n结束：仍须保留最后一句。"
    row["observation"] = prefix + ("证据原文。" * (size // 15)) + suffix
    return row["id"], row["observation"]


def change_one_finding(workspace, state):
    """Legitimate source change: re-review it, then old report must be stale."""
    from review import record_review
    state["findings"][0]["impact"] += " 新证据同时证明服务刷新令牌可被读取。"
    row = state["findings"][0]
    record_review(workspace, state, row["id"], {
        "reviewer": "同一模型回源复核（来源变化夹具）；非独立实现验证",
        "decision": "retain", "rationale": "新证据支持新增影响，按变更后的发现重新登记。",
        "counterevidence_analysis": "未发现能够限制新增读取范围的包装层。",
        "evidence_ids": row["evidence_ids"][:1], "counterevidence_ids": [],
    })
    return row["id"]


def confirm_fixture_plan(state, groups=None, scenarios=None, chain_placements=None):
    """Explicit test-author confirmation; never called implicitly by adjudication.

    The default hand-authored cases retain one report for each known identity.
    Multi-identity cases pass their intended groups. No production code may use
    this fixture convenience to silently refresh stale plans or decide grouping.
    """
    from attribution import build_vulnerability_view
    from report_plan import bind_plan
    view = build_vulnerability_view(state)
    if groups is None:
        groups = {v["id"]: [v["id"]] for v in view["vulnerabilities"]}
    raw = {"version": 1, "groups": [
        {"id": gid, "title": "示例安全问题 " + gid,
         "framework_object_ids": [], "vulnerability_ids": list(vids),
         "grouping_reason": "夹具作者明确指定阅读组织，各独立失效身份分别保留。"}
        for gid, vids in groups.items()],
        "scenarios": deepcopy(scenarios or []),
        "chain_placements": deepcopy(chain_placements or [])}
    state["report_plan"] = bind_plan(state, raw, view)
    return state["report_plan"]


def main():
    import argparse
    import json
    import tempfile
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill", required=True)
    parser.add_argument("--case", choices=sorted(EXPECTED), default="merged")
    parser.add_argument("--verify-fixture", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="report-fixture-") as temporary:
        workspace, state, expected = build_case(temporary, args.case, args.skill)
        errors = []
        if args.verify_fixture:
            from records import validate
            errors = validate(workspace, state)
            from reporting import build_tasks
            if sorted(t['id'] for t in build_tasks(state)) != sorted(expected['reports']):
                errors.append('Fixture report identities differ from independent expectations')
        print(json.dumps({"case": args.case, "expected": expected,
                          "record_validation_errors": errors}, ensure_ascii=False, indent=2))
        return bool(errors)


def adjudicate_fixture(state):
    """Explicit model verdicts for the hand-authored report cases, not a classifier."""
    from attribution import decision_digest
    state['finding_dispositions'] = []
    owners = {fid: r['id'] for r in state.get('root_causes', []) if r.get('verdict') == 'merge'
              for fid in r['finding_ids']}
    for f in state['findings']:
        if f['status'] != 'current': continue
        row = {'id': 'FD-' + f['id'], 'finding_id': f['id'], 'kind': 'defect',
               'by': 'fixture-reviewer', 'reason': '夹具指定的具体控制缺陷及比较结论',
               'comparison': {'by': 'fixture-reviewer', 'scope': '已核对夹具全部入口和控制位置',
                              'finding_ids': [x['id'] for x in state['findings']],
                              'evidence_ids': f['evidence_ids'],
                              'reason': '按夹具预期分别保留失效实现；同源成员引用同一组',
                              'conclusion': 'grouped' if f['id'] in owners else 'standalone'}}
        row['source_digest'] = decision_digest(state, row)
        state['finding_dispositions'].append(row)
    for row in state.get('root_causes', []):
        row['evidence_ids'] = state['findings'][0]['evidence_ids']
        row['source_digest'] = decision_digest(state, row)

if __name__ == "__main__":
    raise SystemExit(main())
