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
    "1. 审计对象与关键结论", "2. 全部严重问题", "3. 重要攻击场景", "4. 证据边界",
)
VULNERABILITY_HEADINGS = (
    "1. 问题概述", "2. 组件与安全边界", "3. 触发条件与输入",
    "4. 漏洞机制与证据", "5. 受影响范围", "6. 验证与复现材料", "7. 结论边界与来源",
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
    """Author golden test pages independently of the production renderer."""
    report = workspace / "report"
    findings = {f["id"]: f for f in state["findings"]}
    for task in index["tasks"]:
        path = report / task["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        meta = {"type": "vulnerability", "report_id": task["id"],
                "source_digest": task["source_digest"], "finding_ids": task["finding_ids"],
                "vulnerability_ids": task["vulnerability_ids"],
                "root_cause_id": task.get("root_cause_id"), "todo_ids": task.get("todo_ids", [])}
        rows = [metadata_line(meta).rstrip(), "", "# " + task["title"], ""]
        for heading in VULNERABILITY_HEADINGS:
            rows.extend(["## " + heading, ""])
            if heading.startswith("1."):
                rows.extend(["这份报告综合相关入口，各自的独立失效身份及权限前提保留。", ""])
            elif heading.startswith("4."):
                evidence = {row["id"]: row for row in state["evidence"]}
                materials = state.get("materials", {})
                for fid in task["finding_ids"]:
                    f = findings[fid]
                    rows.extend(['<a id="' + fid + '"></a>', ""])
                    for eid in f["evidence_ids"]:
                        row = evidence.get(eid)
                        material = materials.get((row or {}).get("material_id"))
                        lines = (row.get("locator") or {}).get("lines") if row else None
                        if material and lines:
                            rows.extend(["**文件**：`%s:%d-%d`" % (material["path"], lines[0], lines[1]),
                                         "", "```text", row["observation"], "```", ""])
                            break
                    rows.extend([f["mechanism"], "", f["impact"], ""])
            elif heading.startswith("3."):
                rows.extend(["请求中的标识会进入读取器。网络可达、管理令牌与任务会话是不同路径各自的前提。", ""])
            elif heading.startswith("5."):
                rows.extend(["只覆盖记录中已确认的入口；共同阅读不会把不同权限前提合成一种。", ""])
            elif heading.startswith("6."):
                rows.extend(["已静态定位代码；请求材料未执行。现场网络策略及真实响应没有核验。", ""])
            elif heading.startswith("7."):
                rows.extend(["没有把候选路径当成已闭合链，来源记录中的反证与待定范围继续保留。", ""])
                for cid, placement in index.get("chain_locations", {}).items():
                    if placement.get("kind") == "report" and placement.get("target_id") == task["id"]:
                        rows.extend(['<a id="' + cid + '"></a>', "相关静态链及其已知前提，未做运行验证。", ""])
            else:
                rows.extend(["组件接收入站标识并查询资源；安全边界要求调用主体只能读取获准资源。", ""])
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    high_by_report = {}
    for vuln in index["high_vulnerabilities"]:
        high_by_report.setdefault(vuln["report_id"], []).append(vuln)
    entries = [{"id": "H-" + task["id"], "report_id": task["id"],
                "vulnerability_ids": sorted(v["id"] for v in high_by_report[task["id"]])}
               for task in index["tasks"] if task["id"] in high_by_report]
    dispositions = {c["id"]: ("needs_evidence" if c.get("status") == "candidate" else "static_trace")
                    for c in state.get("chains", [])}
    meta = {"type": "summary", "source_digest": index["source_digest"], "todo_ids": [],
            "summary_entries": entries, "chain_dispositions": dispositions}
    rows = [metadata_line(meta).rstrip(), "", "# 示例组件安全审计摘要", "",
            "## " + SUMMARY_HEADINGS[0], "",
            "审计代码中调用身份与资源归属的关系；各入口已有权限不同，未执行目标。", "",
            "## " + SUMMARY_HEADINGS[1], "",
            "| 问题 | 等级 | 原理与条件 | 影响 |", "|---|---|---|---|"]
    for entry in entries:
        task = next(t for t in index["tasks"] if t["id"] == entry["report_id"])
        levels = {v["severity"] for v in high_by_report[entry["report_id"]]}
        level_text = " / ".join(x.title() for x in ("critical", "high") if x in levels)
        rows.append('| <a id="%s"></a> [%s](%s) | %s | %s | %s |' % (
            entry["id"], task["title"], task["path"], level_text,
            "调用主体没有绑定所选资源；每个入口各自保留网络或令牌条件。",
            "可访问未被授权的资源，具体范围由报告内各独立子问题限定。"))
    if not entries:
        rows.extend(["", "没有已确认的 High/Critical 独立缺陷。"])
    rows.extend(["", "## " + SUMMARY_HEADINGS[2], ""])
    if not index.get("scenarios"):
        rows.extend(["没有需要在正文综合解释的已登记场景；其他链保留各自主去向。", ""])
    chains = {c["id"]: c for c in state.get("chains", [])}
    for scene in index.get("scenarios", []):
        rows.extend(['<a id="' + scene["id"] + '"></a>', "", "### " + scene["title"], "",
                     "调用者最初只控制入口字段；它进入组件后影响资源选择，继而接触目标资产。"
                     "已有令牌、任务会话等条件须按各分支分别满足，不能互相借用。", ""])
        for cid in scene["chain_ids"]:
            chain = chains[cid]
            rows.extend([cid + "：" + ("候选路径，组件衔接仍缺证据。" if chain.get("status") == "candidate"
                         else "已有静态调用证据，未执行目标。"), ""])
    rows.extend(["## " + SUMMARY_HEADINGS[3], "",
                 "未取得现场网络策略；链描述不提升记录状态。非独立观察和待定项不混入已确认问题数。", ""])
    for fid, location in index.get("finding_map", {}).items():
        if (location.get("path") or "").startswith("summary.md#"):
            rows.extend(['<a id="' + fid + '"></a>', "归因待定：" + findings[fid]["mechanism"], ""])
    (report / "summary.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def run_checks(skill_dir):
    import reporting
    from report_fixtures import (EXPECTED, build_case, change_one_finding, add_large_record,
                                 _review, adjudicate_fixture, confirm_fixture_plan)
    problems = []
    import self_check
    required_checks = {'two-stage-reporting', 'report-plan', 'framework-plan'}
    missing_checks = required_checks - {name for name, _ in self_check.CHECKS}
    if missing_checks:
        problems.append('report workflow checks not registered: ' + ', '.join(sorted(missing_checks)))
    contract = (Path(skill_dir) / 'references/report-format.md').read_text(encoding='utf-8')
    versions = re.findall(r'^<!-- report-index-version: (\d+) -->$', contract, re.M)
    if len(versions) != 1 or int(versions[0]) != reporting.VERSION:
        problems.append('report index version differs from its contract')
    for name, expected in [('summary', SUMMARY_HEADINGS),
                           ('vulnerability', VULNERABILITY_HEADINGS)]:
        path = Path(skill_dir) / 'references' / 'templates' / (name + '.md')
        headings = re.findall(r'^## (.+)$', path.read_text(encoding='utf-8'), re.M)
        if headings != list(expected):
            problems.append('authored template differs from checked structure: ' + name)
    if tuple(reporting.SUMMARY_HEADINGS) != SUMMARY_HEADINGS or tuple(reporting.VULNERABILITY_HEADINGS) != VULNERABILITY_HEADINGS:
        problems.append('template and validator headings differ')

    # A citation resolves by its shortest unambiguous tail, or not at all. Guessing
    # matters here and nowhere else: this target ships 267 packages, so `SKILL.md`
    # and `config.yaml` each name many different files, and picking the first one
    # reports a confident, wrong line count against a file the author never cited.
    decoys = {"m1": {"id": "m1", "target_id": "repo", "path": "one/dup.ts"},
              "m2": {"id": "m2", "target_id": "repo", "path": "two/dup.ts"},
              "m3": {"id": "m3", "target_id": "repo", "path": "two/only.ts"}}
    index = reporting._material_suffix_index(decoys)
    if reporting._resolve_citation("dup.ts", index) is not None:
        problems.append("an ambiguous citation resolves to a guess instead of nothing")
    if (reporting._resolve_citation("one/dup.ts", index) or {}).get("id") != "m1":
        problems.append("a qualified citation does not resolve to its own material")
    if (reporting._resolve_citation("only.ts", index) or {}).get("id") != "m3":
        problems.append("an unambiguous basename does not resolve")
    if reporting._resolve_citation("absent.ts", index) is not None:
        problems.append("a citation outside the audit resolves to something")

    @contextmanager
    def prepared(case):
        with tempfile.TemporaryDirectory(prefix="two-stage-report-test-") as tmp:
            workspace, state, expected = build_case(tmp, case, skill_dir)
            from records import validate
            assert not validate(workspace, state), "positive fixture is not a valid audit record"
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
            assert sorted(index["finding_map"]) == sorted(expected["current"])
            task_members = [fid for task in index["tasks"] for fid in task["finding_ids"]]
            assert len(task_members) == len(set(task_members)), "finding has duplicate primary report"
            identities = [vid for task in index["tasks"] for vid in task["vulnerability_ids"]]
            assert sorted(identities) == sorted(expected["vulnerabilities"]), identities
            assert index["statistics"]["report_tasks"] == len(expected["reports"])
            assert index["statistics"]["attribution"]["independent_vulnerabilities"] == len(identities)
            text = (workspace / "report/summary.md").read_text(encoding="utf-8")
            entries = read_metadata(text)["summary_entries"]
            ids = [vid for entry in entries for vid in entry["vulnerability_ids"]]
            assert sorted(ids) == sorted(expected["high"]), ids
            assert len(ids) == len(set(ids)), "summary silently duplicated an independent defect"
            section = text.split("## " + SUMMARY_HEADINGS[1], 1)[1].split("## " + SUMMARY_HEADINGS[2], 1)[0]
            row_ids = re.findall(r'^\| <a id="([^"]+)"></a>', section, re.M)
            assert row_ids == [e["id"] for e in entries], row_ids
            assert set(read_metadata(text)["chain_dispositions"]) == {c["id"] for c in state["chains"]}
            for fid in expected.get("observations", []):
                assert index["finding_map"][fid]["kind"] == "observation"
                assert fid not in task_members and index["finding_map"][fid]["path"]
            for fid in expected.get("pending", []):
                assert index["finding_map"][fid]["path"] == "summary.md#" + fid
                assert '<a id="' + fid + '"></a>' in text

    for case in EXPECTED:
        test("positive-" + case, lambda case=case: positive(case))

    def reject(name, mutate, case="merged"):
        def run():
            with prepared(case) as (workspace, state, expected, index):
                before_state = deepcopy(state)
                before_files = {p.relative_to(workspace): p.read_bytes()
                                for p in workspace.rglob("*") if p.is_file()}
                mutate(workspace, state, index)
                after_files = {p.relative_to(workspace): p.read_bytes()
                               for p in workspace.rglob("*") if p.is_file()}
                assert state != before_state or after_files != before_files, "mutation had no effect"
                errors = reporting.validate_package(workspace, state)
                assert errors, "violating artifact passed"
        test(name, run)

    def table_row(workspace, entry_id=None):
        p = workspace / "report/summary.md"
        if entry_id is None:
            entry_id = read_metadata(p.read_text(encoding="utf-8"))["summary_entries"][0]["id"]
        matches = [line for line in p.read_text(encoding="utf-8").splitlines(keepends=True)
                   if line.startswith('| <a id="' + entry_id + '"></a>')]
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
        extra = '| <a id="H-NOT-CURRENT"></a> [待取证问题](vulnerabilities/F-AA01-01.md) | High | 该发现仍待取证。 | 影响尚未确定。 |\n'
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
        assert stored["high_vulnerabilities"], "fixture has no high identity to remove"
        before = len(stored["high_vulnerabilities"])
        stored["high_vulnerabilities"].pop()
        p.write_text(json.dumps(stored, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        assert len(json.loads(p.read_text())["high_vulnerabilities"]) == before - 1
    reject("audit-record-not-index-is-the-denominator", index_hides_required_finding)

    def section_after_table(workspace, state, index):
        p = workspace / "report/summary.md"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\n## 5. 其他说明\n\n一段附加内容。\n", encoding="utf-8")
        assert p.read_text(encoding="utf-8") != text
    reject("summary-template-has-no-unregistered-section", section_after_table)

    def missing_template_section(workspace, state, index):
        task = index["tasks"][0]
        p = workspace / "report" / task["path"]
        replace_once(p, "## " + VULNERABILITY_HEADINGS[5] + "\n", "")
    reject("authored-template-section-is-required", missing_template_section)

    def authored_page(workspace, index):
        p = workspace / "report" / index["tasks"][0]["path"]
        return p, p.read_text(encoding="utf-8")

    def strip_code_excerpts(workspace, state, index):
        p, text = authored_page(workspace, index)
        assert "```" in text, "positive fixture carries no excerpt to remove"
        p.write_text(text.replace("```", "~~~"), encoding="utf-8")

    reject("authored-report-needs-a-code-excerpt", strip_code_excerpts)

    def widen_cited_span(workspace, state, index):
        p, text = authored_page(workspace, index)
        match = re.search(r"`([^`\n]+):(\d+)-(\d+)`", text)
        assert match, "positive fixture cites no file:line"
        widened = "`%s:%s-%d`" % (match.group(1), match.group(2), int(match.group(3)) + 10000)
        p.write_text(text.replace(match.group(0), widened, 1), encoding="utf-8")

    reject("cited-span-must-sit-inside-an-evidence-locator", widen_cited_span)

    def hide_member_source(workspace, state, index):
        """Drop the location without leaving a dangling citation.

        Renaming the file instead would leave `elsewhere.txt:1-3` behind, which the
        locator-span rule catches — and then this case passes while the rule it is
        meant to pin stays disabled. Measured: that is exactly how the first version
        of this case went green against a mutant with the member rule switched off.
        """
        p, text = authored_page(workspace, index)
        kept = [line for line in text.splitlines(keepends=True)
                if not line.startswith("**文件**：")]
        stripped = "".join(kept)
        assert stripped != text, "positive fixture carries no file line to drop"
        for name in sorted({m["path"].rsplit("/", 1)[-1] for m in state["materials"].values()}):
            stripped = stripped.replace(name, "（位置已抹去）")
        assert "```" in stripped, "this case must leave the excerpt rule satisfied"
        assert not re.search(r"`[^`\n]+\.[A-Za-z][A-Za-z0-9]{0,5}:\d+", stripped), \
            "a surviving file:line would trip the span rule instead of the member rule"
        p.write_text(stripped, encoding="utf-8")

    reject("every-member-needs-a-source-location", hide_member_source)

    def lose_scene_anchor(workspace, state, index):
        p = workspace / "report/summary.md"
        replace_once(p, '<a id="SCENE-ENTRY"></a>', '')
    reject("scene-missing-from-body", lose_scene_anchor, "ext")

    def promote_candidate(workspace, state, index):
        p = workspace / "report/summary.md"
        def change(meta):
            assert meta["chain_dispositions"]["CHAIN-CC01-01"] == "needs_evidence"
            meta["chain_dispositions"]["CHAIN-CC01-01"] = "static_trace"
        rewrite_metadata(p, change)
    reject("candidate-is-not-a-closed-chain", promote_candidate, "ext")

    def drift():
        with prepared("merged") as (workspace, state, expected, index):
            changed_fid = change_one_finding(workspace, state)
            assert changed_fid == "F-AA01-01"
            # record_review legitimately saves audit.json; isolate the export's
            # side effects only after that authorized record write has finished.
            before = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
            assert reporting.validate_package(workspace, state), "old report accepted changed source"
            for operation in (lambda: reporting.build_tasks(state),
                              lambda: reporting.export_package(workspace, state)):
                try:
                    operation()
                except ValueError:
                    pass
                else:
                    raise AssertionError("stale/unconfirmed plan was silently refreshed")
            after = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
            assert before == after, "rejected export changed or archived old authored files"
            adjudicate_fixture(state)
            confirm_fixture_plan(state)
            new_index = reporting.export_package(workspace, state)
            assert index["source_digest"] != new_index["source_digest"]
            assert reporting.validate_package(workspace, state), "old authored body survived source change"
    test("updated-source-requires-explicit-reconfirmation", drift)

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
            confirm_fixture_plan(state)
            reporting.export_package(workspace, state)
            chunks = list((workspace / "report/records").rglob("*.md"))
            assert chunks, "no record shards exported"
            material = "\n".join(p.read_text(encoding="utf-8") for p in chunks)
            assert eid in material
            assert "结束：仍须保留最后一句。" in material, "record tail was cut to satisfy a shard budget"
            assert json.dumps(observation, ensure_ascii=False) in material, "record content was altered or truncated"
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
                confirm_fixture_plan(state)
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
            confirm_fixture_plan(state)
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

    def multi_identity_report():
        with prepared("grouped") as (workspace, state, expected, index):
            task = next(t for t in index["tasks"] if t["id"] == "REPORT-ACCESS")
            assert task["vulnerability_ids"] == ["F-AA01-01", "F-BB01-01"]
            assert task["root_cause_id"] is None
            assert index["statistics"]["report_tasks"] == 2
            assert index["statistics"]["attribution"]["independent_vulnerabilities"] == 4
            text = (workspace / "report/summary.md").read_text(encoding="utf-8")
            assert "| Critical / High |" in text
            assert len(read_metadata(text)["summary_entries"]) == 1
    test("one-report-retains-several-independent-identities", multi_identity_report)

    def omit_independent_identity(workspace, state, index):
        p = workspace / "report/summary.md"
        def change(meta):
            row = meta["summary_entries"][0]
            assert len(row["vulnerability_ids"]) == 2
            row["vulnerability_ids"].pop()
        rewrite_metadata(p, change)
    reject("same-report-high-subproblem-cannot-disappear", omit_independent_identity, "grouped")

    def high_coverage_without_grade_or_link_error():
        with prepared("grouped") as (workspace, state, expected, index):
            p = workspace / "report/summary.md"
            original_meta = read_metadata(p.read_text(encoding="utf-8"))
            assert original_meta["summary_entries"][0]["vulnerability_ids"] == ["F-AA01-01", "F-BB01-01"]
            def change(meta):
                meta["summary_entries"][0]["vulnerability_ids"].remove("F-BB01-01")
            rewrite_metadata(p, change)
            p, line = table_row(workspace)
            assert "| Critical / High |" in line
            replace_once(p, line, line.replace("| Critical / High |", "| Critical |", 1))
            modified_meta = read_metadata(p.read_text(encoding="utf-8"))
            assert modified_meta["summary_entries"][0]["vulnerability_ids"] == ["F-AA01-01"]
            errors = reporting.validate_package(workspace, state)
            assert len(errors) == 1 and "summary 严重问题覆盖缺失或重复" in errors[0], errors
    test("high-coverage-independent-of-grade-and-link", high_coverage_without_grade_or_link_error)

    def duplicate_identity_in_metadata(workspace, state, index):
        p = workspace / "report/summary.md"
        def change(meta):
            row = meta["summary_entries"][0]
            row["vulnerability_ids"].append(row["vulnerability_ids"][0])
        rewrite_metadata(p, change)
    reject("duplicate-cross-reference-does-not-create-another-high-identity", duplicate_identity_in_metadata)

    def wrong_entry_owner(workspace, state, index):
        p = workspace / "report/summary.md"
        rewrite_metadata(p, lambda meta: meta["summary_entries"][0].update(report_id="REPORT-TASK"))
    reject("summary-entry-cannot-borrow-another-report-identity", wrong_entry_owner, "grouped")

    def include_low_identity(workspace, state, index):
        p = workspace / "report/summary.md"
        rewrite_metadata(p, lambda meta: meta["summary_entries"][0]["vulnerability_ids"].append("F-CC01-02"))
    reject("low-severity-member-is-not-a-high-summary-identity", include_low_identity, "grouped")

    def wrong_report_metadata(workspace, state, index, field, value):
        p = workspace / "report" / index["tasks"][0]["path"]
        rewrite_metadata(p, lambda meta: meta.update({field: value}))
    reject("report-id-is-bound-to-plan", lambda w, s, i: wrong_report_metadata(w, s, i, "report_id", "REPORT-OTHER"))
    reject("report-independent-members-are-bound-to-plan",
           lambda w, s, i: wrong_report_metadata(w, s, i, "vulnerability_ids", []))

    def missing_chain_disposition(workspace, state, index):
        p = workspace / "report/summary.md"
        rewrite_metadata(p, lambda meta: meta["chain_dispositions"].pop("CHAIN-BB01-01"))
    reject("non-ext-chain-also-needs-disposition", missing_chain_disposition, "ext")

    def missing_report_chain_anchor(workspace, state, index):
        task = next(t for t in index["tasks"] if t["id"] == "F-BB01-01")
        replace_once(workspace / "report" / task["path"], '<a id="CHAIN-BB01-01"></a>', '')
    reject("report-placed-chain-needs-body-anchor", missing_report_chain_anchor, "ext")

    def multi_chain_scene_is_legal():
        with prepared("ext") as (workspace, state, expected, index):
            body = (workspace / "report/summary.md").read_text(encoding="utf-8")
            assert '<a id="SCENE-ENTRY"></a>' in body
            assert "### CHAIN-" not in body, "positive fixture still encodes obsolete per-chain headings"
            assert not reporting.validate_package(workspace, state)
    test("multiple-chain-scene-does-not-require-per-chain-headings", multi_chain_scene_is_legal)

    def pending_anchor_missing(workspace, state, index):
        replace_once(workspace / "report/summary.md", '<a id="F-BB01-01"></a>', '')
    reject("serious-pending-needs-explicit-boundary-anchor", pending_anchor_missing, "non_independent")

    def observation_masquerades_as_defect(workspace, state, index):
        p = workspace / "report/summary.md"
        rewrite_metadata(p, lambda meta: meta["summary_entries"][0]["vulnerability_ids"].append("F-CC01-02"))
    reject("observation-is-not-independent-defect", observation_masquerades_as_defect, "non_independent")

    def check_only_chain_input():
        with prepared("check_chain") as (workspace, state, expected, index):
            chain = next(c for c in state["chains"] if c["id"] == "CHAIN-AA01-02")
            assert all("finding_id" not in step for step in chain["steps"])
            for fid in ("F-AA01-01", "F-CC01-01"):
                task = next(t for t in index["tasks"] if fid in t["finding_ids"])
                assert "CHAIN-AA01-02" in task["input_refs"].get("chains", [])
                assert {"CHK-AA01-0001", "CHK-CC01-0001"} <= set(task["input_refs"]["checks"])
            location = index["chain_locations"]["CHAIN-CC01-02"]
            assert location["kind"] == "boundary" and location["path"].startswith("records/")
    test("check-only-chain-keeps-cross-component-inputs", check_only_chain_input)

    def chain_check_without_finding_is_still_writer_input():
        from report_plan import bind_plan
        with tempfile.TemporaryDirectory(prefix="report-chain-check-input-") as tmp:
            workspace, state, expected = build_case(tmp, "check_chain", skill_dir)
            evidence = deepcopy(next(e for e in state["evidence"] if e["id"] == "E-CC01-002"))
            evidence["id"] = "E-CC01-003"
            state["evidence"].append(evidence)
            check = deepcopy(next(c for c in state["checks"] if c["id"] == "CHK-CC01-0002"))
            check.update(id="CHK-CC01-0901", evidence_ids=[evidence["id"]])
            state["checks"].append(check)
            chain = next(c for c in state["chains"] if c["id"] == "CHAIN-AA01-02")
            chain["steps"].append({"check_id": check["id"], "note": "没有独立 finding 的衔接控制。"})
            raw = deepcopy(state["report_plan"])
            raw.pop("source_digest")
            for key in ("groups", "scenarios", "chain_placements"):
                for row in raw[key]:
                    row.pop("source_digest")
            state["report_plan"] = bind_plan(state, raw)
            assert all(check["id"] not in f["check_ids"] for f in state["findings"])
            index = reporting.export_package(workspace, state)
            task = next(t for t in index["tasks"] if "F-AA01-01" in t["finding_ids"])
            assert check["id"] in task["input_refs"]["checks"], "chain-only check omitted from writer inputs"
            assert evidence["id"] in task["input_refs"]["evidence"], "chain-only evidence omitted from writer inputs"
    test("chain-check-without-finding-remains-writer-input", chain_check_without_finding_is_still_writer_input)

    def every_finding_body_carries_its_mechanism():
        with prepared("small") as (workspace, state, expected, index):
            for finding in state["findings"]:
                relative = index["locations"]["findings"][finding["id"]].split("#", 1)[0]
                body = (workspace / "report" / relative).read_text(encoding="utf-8")
                assert finding["mechanism"] in body
    test("every-finding-body-carries-its-mechanism", every_finding_body_carries_its_mechanism)

    def withdrawn_source_does_not_publish():
        from review import record_review
        with prepared("small") as (workspace, state, expected, index):
            finding = state["findings"][0]
            record_review(workspace, state, finding["id"], {
                "reviewer": "同一模型回源复核（撤回夹具）", "decision": "reject",
                "rationale": "受影响路径的前提不成立，撤回该发现。",
                "counterevidence_analysis": "上游控制阻断入口。",
                "evidence_ids": finding["evidence_ids"][:1], "counterevidence_ids": [],
            })
            assert finding["status"] == "withdrawn", "withdrawal mutation did not take effect"
            before = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
            assert reporting.validate_package(workspace, state)
            try:
                reporting.export_package(workspace, state)
            except ValueError:
                pass
            else:
                raise AssertionError("withdrawn member silently reused old report plan")
            after = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
            assert before == after, "rejected export archived or changed author artifacts"
    test("withdrawn-source-rejects-before-author-file-changes", withdrawn_source_does_not_publish)

    def missing_plan_export_is_non_destructive():
        with prepared("small") as (workspace, state, expected, index):
            before = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
            assert state["report_plan"] is not None
            state["report_plan"] = None
            assert reporting.validate_package(workspace, state)
            try:
                reporting.export_package(workspace, state)
            except ValueError:
                pass
            else:
                raise AssertionError("missing report plan was silently regenerated")
            after = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
            assert before == after
    test("missing-plan-export-preserves-existing-package", missing_plan_export_is_non_destructive)

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
