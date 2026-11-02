"""Behavior and counterexample checks for the two-stage reporting package."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True

SUMMARY_HEADINGS = (
    "1. 主要发现概览", "2. 从 EXT 外部入口进入的攻击链",
    "3. 覆盖与结论边界", "4. 全部 Critical / High 漏洞",
)
VULNERABILITY_HEADINGS = (
    "1. 基本信息", "2. 组件与安全边界", "3. 漏洞原理与影响",
    "4. 攻击路径与成立前提", "5. 代码与证据分析",
    "6. 验证情况与复现方法", "7. 影响范围与结论边界",
)


def metadata_line(meta):
    return "<!-- audit-report: " + json.dumps(meta, ensure_ascii=False, sort_keys=True) + " -->\n"


def read_metadata(text):
    line = text.splitlines()[0]
    prefix, suffix = "<!-- audit-report: ", " -->"
    assert line.startswith(prefix) and line.endswith(suffix), "fixture metadata is malformed"
    return json.loads(line[len(prefix):-len(suffix)])


def replace_once(path, old, new):
    """Mutations prove that the break happened before asking whether it is caught."""
    text = path.read_text(encoding="utf-8")
    assert old != new, "a mutation must change bytes"
    assert text.count(old) == 1, (str(path), old, text.count(old))
    changed = text.replace(old, new, 1)
    path.write_text(changed, encoding="utf-8")
    assert path.read_text(encoding="utf-8") != text, "mutation had no effect"


def rewrite_metadata(path, change):
    text = path.read_text(encoding="utf-8")
    meta = read_metadata(text)
    old = metadata_line(meta)
    change(meta)
    replace_once(path, old, metadata_line(meta))


def author_fixture(workspace, state, index):
    """Write small authored golden artifacts for tests, not production reports."""
    report = workspace / "report"
    findings = {f["id"]: f for f in state["findings"]}
    reports_by_finding = {fid: row["path"] for fid, row in index.get("finding_map", {}).items()}
    for task in index["tasks"]:
        path = report / task["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        for fid in task["finding_ids"]:
            reports_by_finding[fid] = task["path"]
        meta = {"type": "vulnerability", "source_digest": task["source_digest"],
                "finding_ids": task["finding_ids"],
                "root_cause_id": task.get("root_cause_id"),
                "todo_ids": task.get("todo_ids", [])}
        rows = [metadata_line(meta).rstrip(), "", "# 主体与资源归属没有绑定", ""]
        for heading in VULNERABILITY_HEADINGS:
            rows.extend(["## " + heading, ""])
            if heading.startswith("1."):
                rows.extend(["| 项目 | 内容 |", "|---|---|",
                             "| 发现编号 | " + ", ".join(task["finding_ids"]) + " |",
                             "| 验证程度 | 静态分析；未执行目标 |", ""])
            elif heading.startswith("3."):
                for fid in task["finding_ids"]:
                    f = findings[fid]
                    rows.extend(['<a id="' + fid + '"></a>', "",
                                 f["mechanism"], "", f["impact"], ""])
            elif heading.startswith("4."):
                rows.extend(["入口消息中的标识被传到读取器，读取器使用所选主体访问资源。"
                             "网络可达、已有令牌和内部会话是不同路径各自的前提。", ""])
            elif heading.startswith("5."):
                rows.extend(["入口调用点和资源访问器形成所述静态路径。"
                             "输入格式检查没有提供主体与资源的对应关系。", ""])
            elif heading.startswith("6."):
                rows.extend(["代码路径已定位；未执行端到端复现。"
                             "运行期网络策略与安装方式仍需要单独验证。", ""])
            elif heading.startswith("7."):
                rows.extend(["本结论限于列出的入口及配置。"
                             "持有管理令牌与无身份网络访问不能合并成同一攻击前提。", ""])
            else:
                rows.extend(["组件把调用方传入的标识用于查询资源；安全边界要求调用主体只能读取自己的资源。", ""])
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    ext = [c for c in state.get("chains", []) if c.get("entry_exposure") == "EXT"]
    required_other_chains = {cid for row in index.get("finding_map", {}).values() for cid in row.get("chain_ids", [])}
    dispositions = {c["id"]: ("needs_evidence" if c.get("status") == "candidate"
                              else "static_trace") for c in ext}
    meta = {"type": "summary", "source_digest": index["source_digest"],
            "todo_ids": [], "chain_dispositions": dispositions}
    rows = [metadata_line(meta).rstrip(), "", "# 示例组件安全审计摘要", "",
            "本夹具审计代码中的身份与资源访问关系；未启动目标。", "",
            "## " + SUMMARY_HEADINGS[0], "",
            "调用方可以选择资源读取主体，包装层未将这一选择绑定到调用者身份。"
            "影响和入口条件以每条发现的范围为准。", "",
            "## " + SUMMARY_HEADINGS[1], ""]
    if not ext:
        rows.extend(["本记录没有登记 EXT 起点攻击链。", ""])
    for chain in ext:
        rows.extend(["### " + chain["id"] + " " + chain["title"], "",
                     "入口与前提：外部主体向已开放的入口发送标识字段。", "",
                     "攻击路径：入站标识 → 资源选择器 → 目标资源。", "",
                     "影响：取得所选主体的资源；各跳受对应发现的权限前提限制。", "",
                     "证据边界：" + ("候选链；外部入口到任务的环节仍缺证据。"
                                  if chain.get("status") == "candidate"
                                  else "静态路径已定位；没有动态复现结论。"), ""])
    for fid, location in index.get("finding_map", {}).items():
        if location["path"].startswith("summary.md#"):
            rows.extend(['<a id="' + fid + '"></a>', findings[fid]["mechanism"], ""])
    for chain in state.get("chains", []):
        if chain["id"] in required_other_chains and chain.get("entry_exposure") != "EXT":
            rows.extend(["### " + chain["id"] + " " + chain["title"], "", "组合关系及其已知边界。", ""])
    rows.extend(["## " + SUMMARY_HEADINGS[2], "",
                 "运行期入口的网络限制尚未取得；仅以代码证据判断机制。", "",
                 "## " + SUMMARY_HEADINGS[3], "",
                 "| 编号 | 等级 | 漏洞原理 | 影响 |", "|---|---|---|---|"])
    high = [f for f in state["findings"] if f["status"] == "current"
            and f["severity"] in {"critical", "high"}]
    for f in sorted(high, key=lambda row: ({"critical": 0, "high": 1}[row["severity"]], row["id"])):
        rows.append("| [%s](%s) | %s | %s | %s |" % (
            f["id"], reports_by_finding[f["id"]], f["severity"].title(),
            f["mechanism"], f["impact"]))
    if not high:
        rows.extend(["", "当前没有 High 或 Critical 的有效发现。"])
    (report / "summary.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def run_checks(skill_dir):
    import reporting
    from report_fixtures import EXPECTED, build_case, change_one_finding, add_large_record, _review, adjudicate_fixture
    problems = []
    import self_check
    if 'two-stage-reporting' not in {name for name, _ in self_check.CHECKS}:
        problems.append('two-stage reporting is not registered in the full suite')
    for name, expected in [('summary', SUMMARY_HEADINGS),
                           ('vulnerability', VULNERABILITY_HEADINGS)]:
        path = Path(skill_dir) / 'references' / 'templates' / (name + '.md')
        headings = re.findall(r'^## (.+)$', path.read_text(encoding='utf-8'), re.M)
        if headings != list(expected):
            problems.append('authored template differs from checked structure: ' + name)
    if tuple(reporting.SUMMARY_HEADINGS) != SUMMARY_HEADINGS or tuple(reporting.VULNERABILITY_HEADINGS) != VULNERABILITY_HEADINGS:
        problems.append('template and validator headings differ')

    @contextmanager
    def prepared(case):
        with tempfile.TemporaryDirectory(prefix="two-stage-report-test-") as tmp:
            workspace, state, expected = build_case(tmp, case, skill_dir)
            index = reporting.export_package(workspace, state)
            author_fixture(workspace, state, index)
            errors = reporting.validate_package(workspace, state)
            assert not errors, "positive fixture did not pass: %s: %s" % (case, errors)
            yield workspace, state, expected, index

    def test(name, fn):
        try:
            fn()
        except Exception as exc:
            problems.append(name + ": " + str(exc))

    def positive(case):
        with prepared(case) as (workspace, state, expected, index):
            actual = sorted(t["id"] for t in index["tasks"])
            assert actual == sorted(expected["reports"]), (actual, expected["reports"])
            source_current = sorted(fid for task in index["tasks"] for fid in task["finding_ids"])
            assert source_current == sorted(expected["current"]), source_current
            text = (workspace / "report/summary.md").read_text(encoding="utf-8")
            last = text.split("## " + SUMMARY_HEADINGS[-1], 1)[1]
            ids = re.findall(r"^\| \[(F-[^]]+)\]\(", last, re.M)
            assert sorted(ids) == sorted(expected["high"]), ids
            assert len(ids) == len(set(ids)), "summary silently duplicated a finding"

    for case in EXPECTED:
        test("positive-" + case, lambda case=case: positive(case))

    def reject(name, mutate, case="merged"):
        def run():
            with prepared(case) as (workspace, state, expected, index):
                mutate(workspace, state, index)
                errors = reporting.validate_package(workspace, state)
                assert errors, "violating artifact passed"
        test(name, run)

    def table_row(workspace, fid="F-AA01-01"):
        p = workspace / "report/summary.md"
        matches = [line for line in p.read_text(encoding="utf-8").splitlines(keepends=True)
                   if line.startswith("| [" + fid + "](")]
        assert len(matches) == 1, matches
        return p, matches[0]

    def delete_high(workspace, state, index):
        p, line = table_row(workspace)
        replace_once(p, line, "")
    reject("missing-high-row", delete_high)

    def duplicate_high(workspace, state, index):
        p, line = table_row(workspace)
        replace_once(p, line, line + line)
    reject("duplicated-high-row", duplicate_high)

    def insert_non_current(workspace, state, index):
        p, line = table_row(workspace)
        extra = "| [F-BB01-01](vulnerabilities/F-AA01-01.md) | High | 该发现仍待取证。 | 影响尚未确定。 |\n"
        replace_once(p, line, line + extra)
    reject("needs-review-is-not-current", insert_non_current, "mixed")

    def missing_member(workspace, state, index):
        task = next(t for t in index["tasks"] if t["id"] == "RC-01")
        replace_once(workspace / "report" / task["path"], '<a id="F-BB01-01"></a>', "")
    reject("merged-low-member-cannot-disappear", missing_member)

    def missing_report(workspace, state, index):
        p = workspace / "report" / index["tasks"][0]["path"]
        assert p.is_file()
        p.unlink()
        assert not p.exists()
    reject("missing-authored-report", missing_report)

    def stale_digest(workspace, state, index):
        p = workspace / "report" / index["tasks"][0]["path"]
        rewrite_metadata(p, lambda meta: meta.update(source_digest="0" * 64))
    reject("stale-report-fingerprint", stale_digest)

    def wrong_source(workspace, state, index):
        task = next(t for t in index["tasks"] if t["id"] == "RC-01")
        p = workspace / "report" / task["path"]
        rewrite_metadata(p, lambda meta: meta.update(finding_ids=["F-AA01-01"]))
    reject("source-member-list-must-match-root-cause", wrong_source)

    def wrong_severity(workspace, state, index):
        p, line = table_row(workspace)
        assert "| Critical |" in line
        replace_once(p, line, line.replace("| Critical |", "| High |"))
    reject("severity-mismatch", wrong_severity)

    def wrong_link(workspace, state, index):
        p, line = table_row(workspace)
        changed = re.sub(r"\]\([^)]+\)", "](vulnerabilities/missing.md)", line, count=1)
        replace_once(p, line, changed)
    reject("dangling-summary-link", wrong_link)

    def wrong_report_link(workspace, state, index):
        p, line = table_row(workspace)
        changed = line.replace("vulnerabilities/RC-01.md", "vulnerabilities/F-CC01-01.md")
        replace_once(p, line, changed)
    reject("link-exists-but-belongs-to-another-finding", wrong_report_link)

    def empty_summary_cell(workspace, state, index, column):
        p, line = table_row(workspace)
        cells = line.rstrip("\n").split("|")
        assert cells[column].strip(), "fixture cell is already empty"
        cells[column] = " "
        replace_once(p, line, "|".join(cells) + "\n")
    reject("principle-is-required", lambda w, s, i: empty_summary_cell(w, s, i, 3))
    reject("impact-is-required", lambda w, s, i: empty_summary_cell(w, s, i, 4))

    def index_hides_required_finding(workspace, state, index):
        p = workspace / "report/index.json"
        stored = json.loads(p.read_text(encoding="utf-8"))
        assert stored["high_findings"], "fixture has no high finding to remove"
        before = len(stored["high_findings"])
        stored["high_findings"].pop()
        p.write_text(json.dumps(stored, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        assert len(json.loads(p.read_text())["high_findings"]) == before - 1
    reject("audit-record-not-index-is-the-denominator", index_hides_required_finding)

    def section_after_table(workspace, state, index):
        p = workspace / "report/summary.md"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\n## 5. 其他说明\n\n一段附加内容。\n", encoding="utf-8")
        assert p.read_text(encoding="utf-8") != text
    reject("high-table-must-be-last-section", section_after_table)

    def missing_template_section(workspace, state, index):
        task = index["tasks"][0]
        p = workspace / "report" / task["path"]
        replace_once(p, "## " + VULNERABILITY_HEADINGS[5] + "\n", "")
    reject("authored-template-section-is-required", missing_template_section)

    def lose_ext_heading(workspace, state, index):
        p = workspace / "report/summary.md"
        replace_once(p, "### CHAIN-AA01-01 ", "### 已隐藏编号 ")
    reject("ext-chain-missing-from-body", lose_ext_heading, "ext")

    def promote_candidate(workspace, state, index):
        p = workspace / "report/summary.md"
        def change(meta):
            assert meta["chain_dispositions"]["CHAIN-CC01-01"] == "needs_evidence"
            meta["chain_dispositions"]["CHAIN-CC01-01"] = "static_trace"
        rewrite_metadata(p, change)
    reject("candidate-is-not-a-closed-chain", promote_candidate, "ext")

    def drift(workspace, state, index):
        old = index["source_digest"]
        changed_fid = change_one_finding(workspace, state)
        assert changed_fid == "F-AA01-01"
        new_index = reporting.export_package(workspace, state)
        assert old != new_index["source_digest"], "source change was not reflected in export"
    reject("updated-evidence-leaves-authored-report-stale", drift)

    def regeneration_preserves_authored():
        with prepared("merged") as (workspace, state, expected, index):
            paths = [workspace / "report/summary.md"] + [workspace / "report" / task["path"]
                                                          for task in index["tasks"]]
            before = {p: p.read_bytes() for p in paths}
            again = reporting.export_package(workspace, state)
            assert all(p.read_bytes() == original for p, original in before.items())
            assert again["source_digest"] == index["source_digest"]
            assert not reporting.validate_package(workspace, state)
    test("reexport-preserves-authored-bytes", regeneration_preserves_authored)

    def checking_is_read_only():
        with prepared("merged") as (workspace, state, expected, index):
            root = workspace / "report"
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            original = deepcopy(state)
            assert not reporting.validate_package(workspace, state)
            after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            assert before == after, "validate_package modified the package"
            assert original == state, "validate_package modified audit state"
    test("validation-is-read-only", checking_is_read_only)

    def snapshot_preserves_authored():
        from audit import archive
        with prepared("merged") as (workspace, state, expected, index):
            paths = [Path("report/summary.md")] + [Path("report") / task["path"]
                                                    for task in index["tasks"]]
            before = {p: (workspace / p).read_bytes() for p in paths}
            snapshot = archive(workspace, state, "report-check")
            for p, original in before.items():
                assert (snapshot / "workspace" / p).read_bytes() == original, p
                assert (workspace / p).read_bytes() == original, p
    test("snapshot-preserves-authored-bytes", snapshot_preserves_authored)

    def large_record_is_whole():
        with tempfile.TemporaryDirectory(prefix="report-large-record-") as tmp:
            workspace, state, expected = build_case(tmp, "small", skill_dir)
            eid, observation = add_large_record(state)
            _review(workspace, state)
            adjudicate_fixture(state)
            reporting.export_package(workspace, state)
            chunks = list((workspace / "report/records").rglob("*.md"))
            assert chunks, "no record shards exported"
            material = "\n".join(p.read_text(encoding="utf-8") for p in chunks)
            assert eid in material
            assert "结束：仍须保留最后一句。" in material, "record tail was cut to satisfy a shard budget"
    test("oversize-record-keeps-tail", large_record_is_whole)

    def coordinate_id_is_not_a_path():
        with tempfile.TemporaryDirectory(prefix="report-coordinate-id-") as tmp:
            workspace, state, expected = build_case(tmp, "small", skill_dir)
            state["pending_decisions"] = [{"id": "object_mapping:U-AA01", "resolution": "accept"}]
            index = reporting.export_package(workspace, state)
            location = index["locations"]["pending_decisions"]["object_mapping:U-AA01"]
            path, anchor = location.split("#", 1)
            body = (workspace / "report" / path).read_text(encoding="utf-8")
            assert 'id="' + anchor + '"' in body
            assert "object_mapping:U-AA01" in body
    test("record-coordinate-is-not-a-filename", coordinate_id_is_not_a_path)

    def repeated_history_ids_keep_both_records():
        with tempfile.TemporaryDirectory(prefix="report-history-id-") as tmp:
            workspace, state, expected = build_case(tmp, "small", skill_dir)
            state["corrections"] = [
                {"id": "CORR-AA01-01", "before": "旧甲", "after": "新甲"},
                {"id": "CORR-AA01-01", "before": "旧乙", "after": "新乙"}]
            index = reporting.export_package(workspace, state)
            locations = index["locations"]["corrections"]
            assert len(locations) == 2
            assert len(index["aliases"]["corrections"]["CORR-AA01-01"]) == 2
            bodies = "\n".join((workspace / "report" / p.split("#", 1)[0]).read_text(encoding="utf-8")
                               for p in set(locations.values()))
            for row in state["corrections"]:
                assert row["after"] in bodies, "export lost a historical correction"
            assert index["catalog"]["corrections"]["records"] == 2
    test("historical-duplicate-ids-are-not-deduplicated", repeated_history_ids_keep_both_records)

    def root_index_is_a_directory():
        with prepared("merged") as (workspace, state, expected, index):
            stored = json.loads((workspace / "report/index.json").read_text(encoding="utf-8"))
            assert "tasks" not in stored and "locations" not in stored
            assert stored["task_indexes"]
            expanded = reporting.load_index(workspace)
            assert [t["id"] for t in expanded["tasks"]] == [t["id"] for t in index["tasks"]]
            assert expanded["locations"] == index["locations"]
            assert reporting.finalize_package(workspace, state)["valid"]
            assert not reporting.validate_package(workspace, state)
    test("root-index-resolves-sharded-metadata", root_index_is_a_directory)

    def metadata_bytes_change(workspace, state, index):
        root = json.loads((workspace / "report/index.json").read_text(encoding="utf-8"))
        relative = root["catalog"]["findings"]["index_path"]
        path = workspace / "report" / relative
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        assert path.read_bytes() != original
    reject("changed-metadata-index-digest", metadata_bytes_change)

    def statistics_change(workspace, state, index):
        path = workspace / "report/index.json"
        root = json.loads(path.read_text(encoding="utf-8"))
        original = root["statistics"]["checks"]
        root["statistics"]["checks"] = original + 1
        path.write_text(json.dumps(root, ensure_ascii=False) + "\n", encoding="utf-8")
        assert json.loads(path.read_text())["statistics"]["checks"] != original
    reject("indexed-statistics-cannot-drift", statistics_change)

    def todo_routing_matches_complete_ids():
        for case in ("small", "merged"):
            with tempfile.TemporaryDirectory(prefix="report-todo-routing-") as tmp:
                workspace, state, expected = build_case(tmp, case, skill_dir)
                base = next(f for f in state["findings"] if f["id"] == "F-AA01-01")
                for fid in ("F-AA01-012", "F-AA01-10", "F-AA01-100"):
                    finding = deepcopy(base)
                    finding["id"] = fid
                    finding["root_cause_id"] = None
                    state["findings"].append(finding)
                _review(workspace, state)
                adjudicate_fixture(state)
                state["report_todos"] = [
                    {"id": "RT-AA01-01", "instruction": "仅调整 F-AA01-012 的呈现", "status": "open"},
                    {"id": "RT-AA01-02", "instruction": "核对F-AA01-01的影响", "status": "open"},
                    {"id": "RT-AA01-03", "instruction": "核对 `F-AA01-01`、[F-AA01-012](vulnerabilities/F-AA01-012.md)。", "status": "open"},
                    {"id": "RT-AA01-04", "instruction": "F-AA01-01", "status": "open"},
                    {"id": "RT-AA01-05", "instruction": "仅调整 F-AA01-100 的呈现", "status": "open"},
                    {"id": "RT-AA01-06", "instruction": "引用 AF-AA01-01 与 F-AA01-01-extra，不含完整发现 ID。", "status": "open"},
                    {"id": "RT-AA01-07", "instruction": "总览说明证据边界。", "status": "open"},
                ]
                index = reporting.export_package(workspace, state)
                actual = {t["id"]: t["todo_ids"] for t in index["tasks"]}
                short_task = "RC-01" if case == "merged" else "F-AA01-01"
                wanted = {rid: [] for rid in expected["reports"]}
                wanted.update({short_task: ["RT-AA01-02", "RT-AA01-03", "RT-AA01-04"],
                               "F-AA01-012": ["RT-AA01-01", "RT-AA01-03"],
                               "F-AA01-10": [], "F-AA01-100": ["RT-AA01-05"]})
                assert actual == wanted, (case, actual, wanted)
                assert index["summary_todo_ids"] == ["RT-AA01-06", "RT-AA01-07"]
    test("todo-routing-matches-complete-ids", todo_routing_matches_complete_ids)

    def task_fingerprint_is_process_stable():
        import os
        import subprocess
        with tempfile.TemporaryDirectory(prefix="report-hash-seed-") as tmp:
            workspace, state, expected = build_case(tmp, "small", skill_dir)
            finding = state["findings"][0]
            base = deepcopy(next(c for c in state["checks"] if c["id"] in finding["check_ids"]))
            for number in range(101, 109):
                check = deepcopy(base)
                check["id"] = "CHK-AA01-%d" % number
                state["checks"].append(check)
                finding["check_ids"].append(check["id"])
                state["controls"].append({"id": "CTL-AA01-%d" % number,
                    "description": "验证记录排序不应改变同一来源的任务指纹。",
                    "check_ids": [check["id"]]})
            _review(workspace, state)
            adjudicate_fixture(state)
            from records import validate
            assert not validate(workspace, state), "hash-seed fixture must remain a valid audit"
            source = Path(tmp) / "source.json"
            source.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
            code = ("import json,sys;sys.path.insert(0,sys.argv[1]);import reporting;"
                    "from pathlib import Path;state=json.loads(Path(sys.argv[2]).read_text());"
                    "print(json.dumps({t['id']:t['source_digest'] for t in reporting.build_tasks(state)},sort_keys=True))")
            results = []
            for seed in ("1", "2", "3"):
                env = dict(os.environ, PYTHONHASHSEED=seed)
                result = subprocess.run([sys.executable, "-B", "-c", code,
                    str(Path(skill_dir).resolve() / "scripts"), str(source)],
                    env=env, capture_output=True, text=True, check=True)
                results.append(json.loads(result.stdout))
            assert all(value == results[0] for value in results[1:]), "task fingerprints depend on process hash seed"
            first = reporting.build_tasks(state)
            state["controls"].reverse()
            assert reporting.build_tasks(state) == first, "control inventory order changed task fingerprints"
    test("task-fingerprint-is-process-stable", task_fingerprint_is_process_stable)

    return problems


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill", required=True)
    args = parser.parse_args()
    scripts = Path(args.skill).resolve() / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        problems = run_checks(args.skill)
    except Exception as exc:
        problems = ['checker could not run: %s: %s' % (type(exc).__name__, exc)]
    for problem in problems:
        print("FAIL:", problem)
    if not problems:
        print("PASS: two-stage reporting scenarios and counterexamples")
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
