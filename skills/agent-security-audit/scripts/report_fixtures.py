"""Small realistic records for two-stage report tests.

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
    "empty": {"current": [], "high": [], "reports": [], "ext": []},
    "small": {
        "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "high": ["F-AA01-01", "F-BB01-01"],
        "reports": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "ext": [],
    },
    "mixed": {
        "current": ["F-AA01-01", "F-CC01-02"],
        "high": ["F-AA01-01"],
        "reports": ["F-AA01-01", "F-CC01-02"],
        "ext": [],
        "not_current": ["F-BB01-01", "F-CC01-01"],
    },
    "merged": {
        "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "high": ["F-AA01-01", "F-CC01-01"],
        "reports": ["RC-01", "F-CC01-01", "F-CC01-02"],
        "ext": [],
        "members": {"RC-01": ["F-AA01-01", "F-BB01-01"]},
    },
    "ext": {
        "current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "high": ["F-AA01-01", "F-BB01-01"],
        "reports": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
        "ext": ["CHAIN-AA01-01", "CHAIN-CC01-01"],
        "candidate": ["CHAIN-CC01-01"],
        "not_ext": ["CHAIN-BB01-01"],
    },
    "zero_current": {
        "current": [], "high": [], "reports": [], "ext": [],
        "not_current": ["F-AA01-01", "F-BB01-01", "F-CC01-01", "F-CC01-02"],
    },
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
                   responsibility="示例组件维护者", remediation="按调用主体约束资源归属。",
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
    elif case == "zero_current":
        decisions = {row["id"]: ("reject" if i % 2 else "needs_evidence")
                     for i, row in enumerate(state["findings"])}
    _review(workspace, state, decisions)
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
        print(json.dumps({"case": args.case, "expected": expected,
                          "record_validation_errors": errors}, ensure_ascii=False, indent=2))
        return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
