"""Framework routing, attribution envelopes and reconciliation counterexamples.

The fixture records come from report_fixtures, including real review bindings and
pinned framework snapshots. Tests write only their TemporaryDirectory. Negative
cases prove a valid precursor, prove the mutation, and match the target rejection
reason; a stale fact review or unrelated exception is never accepted as success.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True


def serialized(value):
    """Detach nested records exactly as a written/read task packet does."""
    return json.loads(json.dumps(value, ensure_ascii=False))


def file_bytes(root):
    root = Path(root)
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def analysis_result(run_id, task, attempt):
    origin = attempt.get("origin", {})
    return {
        "run_id": origin.get("run_id", run_id),
        "task_id": origin.get("task_id", task["id"]),
        "attempt": origin.get("attempt", attempt["n"]),
        "input_digest": task["input_digest"], "reviewer": "framework-fixture-reviewer",
        "assessments": [{"finding_id": fid, "proposed_kind": "defect",
                         "reason": "已核对本任务负责的具体失效；上下文不重复裁决。"}
                        for fid in task.get("owner_finding_ids", task["finding_ids"])],
        "group_proposals": [], "comparisons": [], "cross_file_leads": [],
        "fact_corrections": [], "open_items": [], "read_dependencies": [], "resolutions": [],
    }


def run_checks(skill_dir):
    import audit
    import attribution as attr
    import rootcause as rc
    import rootcause_run as runs
    import self_check
    from knowledge import baseline_dir, load_bundle, objects
    from records import validate
    from report_fixtures import (build_case, _review, adjudicate_fixture, confirm_fixture_plan)

    problems = []
    if "framework-plan" not in {name for name, _ in self_check.CHECKS}:
        problems.append("framework-plan is not registered in the full suite")

    def test(name, operation):
        try:
            operation()
        except Exception as exc:
            problems.append(name + ": " + type(exc).__name__ + ": " + str(exc))

    def expect_error(fragment, operation):
        try:
            operation()
        except ValueError as exc:
            assert fragment in str(exc), "wrong rejection: %s; expected %s" % (exc, fragment)
        else:
            raise AssertionError("invalid input accepted; expected " + fragment)

    def assert_facts(state):
        for finding in state["findings"]:
            if finding["status"] == "current":
                errors = attr.fact_errors(state, finding)
                assert not errors, (finding["id"], errors)

    @contextmanager
    def fixture(case="small"):
        with tempfile.TemporaryDirectory(prefix="framework-plan-check-") as tmp:
            workspace, state, expected = build_case(tmp, case, skill_dir)
            assert not validate(workspace, state), "fixture must be a valid source audit"
            assert_facts(state)
            yield workspace, state

    def rebind(workspace, state):
        _review(workspace, state)
        adjudicate_fixture(state)
        confirm_fixture_plan(state)
        audit.save(workspace, state)
        assert_facts(state)
        assert not validate(workspace, state), "mutated positive fixture is structurally invalid"

    def catalog(workspace, state):
        bundle, _, _ = load_bundle(baseline_dir(workspace, state["framework"]["baseline_id"]))
        topics = {row["id"] for key in ("layers", "domains") for row in bundle.get(key, [])}
        return bundle, topics, objects(bundle)

    def make_ambiguous(workspace, state):
        bundle, topics, object_rows = catalog(workspace, state)
        finding = state["findings"][0]
        first = next(c for c in state["checks"] if c["id"] == finding["check_ids"][0])
        primary_object = bundle["failure_modes"][first["failure_mode_id"]]["object_id"]
        primary_topic = primary_object.split(".")[0]
        choices = [(mid, mode["object_id"]) for mid, mode in bundle["failure_modes"].items()
                   if mode.get("object_id") in object_rows
                   and mode["object_id"].split(".")[0] in topics
                   and mode["object_id"].split(".")[0] != primary_topic]
        assert choices, "pinned fixture framework needs two actual topics"
        mode_id, other_object = sorted(choices)[0]
        instance = deepcopy(next(i for i in state["instances"] if i["id"] == first["instance_ids"][0]))
        instance.update(id="INST-AA01-0901", framework_object_ids=[other_object],
                        name="另一控制职责", responsibility="同一发现跨越的第二项控制职责")
        assert all(i["id"] != instance["id"] for i in state["instances"])
        state["instances"].append(instance)
        check = deepcopy(first)
        check.update(id="CHK-AA01-0901", failure_mode_id=mode_id, instance_ids=[instance["id"]])
        assert all(c["id"] != check["id"] for c in state["checks"])
        state["checks"].append(check)
        finding["check_ids"].append(check["id"])
        rebind(workspace, state)
        return finding["id"], primary_topic, other_object.split(".")[0], other_object

    def route_request(routing, preferred=None):
        index = json.loads(Path(routing["topic_index_path"]).read_text(encoding="utf-8"))
        rows = []
        for row in index["findings"]:
            fid = row["finding_id"]
            options = row["topic_candidates"]
            topic = (preferred or {}).get(fid, options[0] if len(options) == 1 else "local" if not options else options[-1])
            rows.append({"finding_id": fid, "topic_id": topic,
                         "reason": "测试作者按第二控制的实际职责选择主主题；其他职责保留为上下文。"})
        return {"base_sha256": routing["base_sha256"], "topic_assignments": rows}

    def no_partial_run(workspace, run_id):
        assert not runs.run_dir(workspace, run_id).exists(), "rejected request left a run"
        parent = Path(workspace) / "units/_reviews/rootcause"
        assert not list(parent.glob(".building-*")), "rejected request left staging directories"

    def default_requires_reason():
        with fixture() as (workspace, state):
            fid, primary, other, _ = make_ambiguous(workspace, state)
            before_audit = (workspace / "audit.json").read_bytes()
            result = runs.prepare(workspace, state, run_id="RUN-routing")
            assert result.get("routing_required") is True
            assert result["unassigned_findings"] == [fid]
            no_partial_run(workspace, "RUN-routing")
            index = json.loads(Path(result["topic_index_path"]).read_text(encoding="utf-8"))
            row = next(r for r in index["findings"] if r["finding_id"] == fid)
            assert {primary, other} <= set(row["topic_candidates"])
            assert other != row["topic_candidates"][0], "fixture must exercise a nonfirst primary choice"
            unresolved = next(r for r in index["topic_assignments"] if r["finding_id"] == fid)
            assert unresolved["topic_id"] is None and not unresolved["reason"]
            request = route_request(result, {fid: other})
            bad = deepcopy(request)
            next(r for r in bad["topic_assignments"] if r["finding_id"] == fid)["reason"] = " "
            assert bad != request
            expect_error("主题主归属缺少判断理由", lambda: runs.prepare(workspace, state, "RUN-no-reason", bad))
            no_partial_run(workspace, "RUN-no-reason")
            done = runs.prepare(workspace, state, "RUN-decided", request)
            root, manifest, _ = runs.load(workspace, done["run_id"])
            owner_tasks = [runs.task_input(root, t) for t in manifest["tasks"].values()
                           if fid in t["owner_finding_ids"]]
            assert len(owner_tasks) == 1 and owner_tasks[0]["topic_id"] == other
            assert (workspace / "audit.json").read_bytes() == before_audit
    test("ambiguous-default-requires-model-reason-and-honors-nonfirst-choice", default_requires_reason)

    def routing_member_errors():
        with fixture() as (workspace, state):
            make_ambiguous(workspace, state)
            routing = runs.prepare(workspace, state, run_id="RUN-index")
            valid = route_request(routing)
            assert runs.framework_task_plan(workspace, state, valid)["tasks"]
            mutations = {
                "missing": lambda r: r["topic_assignments"].pop(),
                "duplicate": lambda r: r["topic_assignments"].append(deepcopy(r["topic_assignments"][0])),
                "extra": lambda r: r["topic_assignments"].append({"finding_id": "F-UNKNOWN-01", "topic_id": "local", "reason": "多余。"}),
            }
            for name, change in mutations.items():
                bad = deepcopy(valid); change(bad); assert bad != valid
                run_id = "RUN-route-" + name
                expect_error("主题主归属必须完整且唯一", lambda: runs.prepare(workspace, state, run_id, bad))
                no_partial_run(workspace, run_id)
    test("routing-assignments-have-complete-unique-owners", routing_member_errors)

    def owner_plan(state):
        ids = sorted(f["id"] for f in state["findings"] if f["status"] == "current")
        return {"mode": "framework", "tasks": [
            {"finding_ids": ids, "owner_finding_ids": ids[:2], "context_finding_ids": ids[2:], "reason": "前两项由本任务裁决，其余作跨主题证据。"},
            {"finding_ids": ids, "owner_finding_ids": ids[2:], "context_finding_ids": ids[:2], "reason": "后两项由本任务裁决，其余只读。"},
        ]}

    def owners_and_context():
        with fixture() as (workspace, state):
            plan = owner_plan(state)
            prepared = runs.prepare(workspace, state, "RUN-owners", plan)
            root, manifest, _ = runs.load(workspace, prepared["run_id"])
            claimed = []
            for task in manifest["tasks"].values():
                packet = runs.task_input(root, task)
                claimed.extend(packet["owner_finding_ids"])
                assert set(packet["owner_finding_ids"]).isdisjoint(packet["context_finding_ids"])
                assert set(packet["owner_finding_ids"]) | set(packet["context_finding_ids"]) == set(packet["finding_ids"])
                attempt = {"n": 1}
                result = analysis_result(prepared["run_id"], task, attempt)
                runs.validate_result(state, task, result, attempt, prepared["run_id"])
                bad = deepcopy(result)
                bad["assessments"].append({"finding_id": packet["context_finding_ids"][0],
                                           "proposed_kind": "defect", "reason": "错误重复裁决只读上下文。"})
                assert bad != result
                expect_error("逐条覆盖任务 finding", lambda: runs.validate_result(state, task, bad, attempt, prepared["run_id"]))
            assert sorted(claimed) == sorted(f["id"] for f in state["findings"])
            for name in ("missing", "duplicate"):
                bad = deepcopy(plan)
                if name == "missing":
                    fid = bad["tasks"][1]["owner_finding_ids"].pop()
                    bad["tasks"][1]["context_finding_ids"].append(fid)
                else:
                    fid = bad["tasks"][0]["owner_finding_ids"][0]
                    bad["tasks"][1]["context_finding_ids"].remove(fid)
                    bad["tasks"][1]["owner_finding_ids"].append(fid)
                assert bad != plan
                expect_error("框架任务主成员必须完整且唯一", lambda: runs.prepare(workspace, state, "RUN-owner-" + name, bad))
                no_partial_run(workspace, "RUN-owner-" + name)
            bad = deepcopy(plan)
            bad["tasks"][0]["context_finding_ids"].append(bad["tasks"][0]["owner_finding_ids"][0])
            expect_error("互斥分区", lambda: runs.prepare(workspace, state, "RUN-overlap", bad))
    test("context-is-input-not-a-second-assessment-obligation", owners_and_context)

    def cross_topic_context():
        with fixture() as (workspace, state):
            fid, _, other, _ = make_ambiguous(workspace, state)
            left = next(f for f in state["findings"] if f["id"] == fid)
            right = state["findings"][1]
            for owner, peer in ((left, right), (right, left)):
                owner["related_findings"] = [{"finding_id": peer["id"], "relation": "possible_same_defect",
                                               "reason": "跨主题的同控制候选，须保留只读上下文。",
                                               "evidence_ids": owner["evidence_ids"][:1]}]
            rebind(workspace, state)
            routing = runs.prepare(workspace, state, "RUN-context-index")
            plan = runs.framework_task_plan(workspace, state, route_request(routing, {fid: other}))
            left_task = next(t for t in plan["tasks"] if left["id"] in t["owner_finding_ids"])
            right_task = next(t for t in plan["tasks"] if right["id"] in t["owner_finding_ids"])
            assert left_task["topic_id"] != right_task["topic_id"]
            assert right["id"] in left_task["context_finding_ids"]
            assert left["id"] in right_task["context_finding_ids"]
            owners = [fid for t in plan["tasks"] for fid in t["owner_finding_ids"]]
            assert sorted(owners) == sorted(f["id"] for f in state["findings"])
    test("framework-routes-preserve-cross-topic-context-with-one-owner", cross_topic_context)

    def local_and_empty():
        with fixture() as (workspace, state):
            local = next(c for c in state["checks"] if c["failure_mode_id"] is None)
            plan = runs.framework_task_plan(workspace, state)
            index = json.loads(Path(plan["topic_index_path"]).read_text(encoding="utf-8"))
            finding = next(f for f in state["findings"] if local["id"] in f["check_ids"])
            mapped = next(r for r in index["findings"] if r["finding_id"] == finding["id"])
            assert mapped["topic_candidates"] and not mapped["mapping_gap"], "no FM can still inherit a real instance responsibility"
            instance = deepcopy(next(i for i in state["instances"] if i["id"] == local["instance_ids"][0]))
            instance.update(id="INST-CC01-LOCAL", framework_object_ids=[], mapping_gap="本地职责未被当前固定框架覆盖。")
            state["instances"].append(instance)
            local["instance_ids"] = [instance["id"]]
            rebind(workspace, state)
            plan = runs.framework_task_plan(workspace, state)
            index = json.loads(Path(plan["topic_index_path"]).read_text(encoding="utf-8"))
            unmapped = next(r for r in index["findings"] if r["finding_id"] == finding["id"])
            assert unmapped["mapping_gap"] and not unmapped["topic_candidates"]
            assert any(t["topic_id"] == "local" and finding["id"] in t["owner_finding_ids"] for t in plan["tasks"])
        with fixture("empty") as (workspace, state):
            prepared = runs.prepare(workspace, state, "RUN-empty")
            assert prepared["tasks"] == [] and not prepared.get("routing_required")
            root, manifest, source = runs.load(workspace, prepared["run_id"])
            assert manifest["finding_ids"] == [] and not manifest["tasks"]
    test("no-fm-uses-instance-role-and-mapping-gap-is-local-with-valid-zero-output", local_and_empty)

    def packet_boundaries():
        with fixture() as (workspace, state):
            finding = state["findings"][0]
            long_text = "完整机制开头。" + "范围与前提不能截断。" * 12000 + "最后一条重要条件。"
            finding["mechanism"] = long_text
            rebind(workspace, state)
            prepared = runs.prepare(workspace, state, "RUN-batched", packet_bytes=64)
            root, manifest, _ = runs.load(workspace, prepared["run_id"])
            claimed, recovered = [], {}
            for task in manifest["tasks"].values():
                packet = runs.task_input(root, task)
                claimed.extend(packet["owner_finding_ids"])
                recovered.update({f["id"]: f for f in packet["findings"]})
            assert sorted(claimed) == sorted(f["id"] for f in state["findings"])
            assert len(claimed) == len(set(claimed))
            assert recovered[finding["id"]]["mechanism"] == long_text
            assert any((root / t["input_path"]).stat().st_size > 64 for t in manifest["tasks"].values()), "indivisible record was truncated to the byte budget"
    test("packet-budget-splits-owners-never-truncates-records", packet_boundaries)

    def stale_routing(change_kind):
        with fixture() as (workspace, state):
            fid, _, _, other_object = make_ambiguous(workspace, state)
            routing = runs.prepare(workspace, state, "RUN-before-route")
            request = route_request(routing)
            assert runs.framework_task_plan(workspace, state, request)["tasks"]
            before = deepcopy(state)
            if change_kind == "fact":
                next(f for f in state["findings"] if f["id"] == fid)["impact"] += " 增补已复核的范围条件。"
                rebind(workspace, state)
            elif change_kind == "instance":
                instance = next(i for i in state["instances"] if i["id"] == "INST-AA01")
                assert other_object not in instance["framework_object_ids"]
                instance["framework_object_ids"].append(other_object)
                # Instance metadata does not stale the existing finding review.
                # Re-reviewing here would change the digest for an unrelated reason.
                assert state["reviews"] == before["reviews"]
            else:
                state["framework"]["version"] += "-revised"
            assert state != before
            assert_facts(state)
            run_id = "RUN-stale-" + change_kind
            before_files = file_bytes(workspace)
            expect_error("主题路由来源已变化", lambda: runs.prepare(workspace, state, run_id, request))
            no_partial_run(workspace, run_id)
            assert file_bytes(workspace) == before_files, "rejected stale routing modified existing files"
    for change_kind in ("fact", "instance", "framework"):
        test("stale-routing-base-" + change_kind,
             lambda change_kind=change_kind: stale_routing(change_kind))

    def task_dependencies():
        with fixture() as (workspace, state):
            state["chains"] = [{"id": "CHAIN-AA01-ONLYCHECK", "entry_exposure": "ADJ",
                                "title": "仅检查引用的跨组件关系", "status": "candidate",
                                "steps": [{"check_id": state["findings"][0]["check_ids"][0], "description": "入口到资源选择器；衔接条件待核。"}]}]
            fid = state["findings"][0]["id"]
            data = serialized(runs.packet(state, [fid]))
            assert [c["id"] for c in data["chains"]] == ["CHAIN-AA01-ONLYCHECK"]
            assert not runs.stale_reasons(state, data)
            report_input = runs.packet(state, [fid], kind='report-organization')
            assert [v['id'] for v in report_input['effective_vulnerabilities']] == [fid]
            assert [r['finding_id'] for r in report_input['finding_dispositions']] == [fid]
            changes = {
                "相关链及其条件已改变": lambda s: s["chains"][0]["steps"][0].update(description="需增加用户确认的衔接条件。"),
                "实例职责或对象映射已改变": lambda s: s["instances"][0].update(responsibility="新增凭据验证职责。"),
                "框架基线已改变": lambda s: s["framework"].update(version=s["framework"]["version"] + "-revised"),
                "相关归因处置已改变": lambda s: s['finding_dispositions'][0].update(reason='补充了独立性比较范围。'),
            }
            for reason, change in changes.items():
                bad = deepcopy(state); change(bad); assert bad != state
                assert_facts(bad)
                reasons = runs.stale_reasons(bad, data)
                assert reason in reasons, (reason, reasons)
                assert "任务事实或复核已改变" not in reasons, "unrelated stale review masked missing dependency"
    test("check-only-chain-instance-and-framework-stale-for-their-own-reasons", task_dependencies)

    def chain_only_sources_and_file_drift():
        with fixture() as (workspace, state):
            used_materials = {e["material_id"] for e in state["evidence"]}
            unused = sorted(set(state["materials"]) - used_materials)
            assert unused, "fixture must have a material unreferenced by all findings"
            mid = unused[0]
            evidence = deepcopy(state["evidence"][0])
            evidence.update(id="E-BB01-004", material_id=mid,
                            sha256=state["materials"][mid]["sha256"], locator={"lines": [2, 3]})
            state["evidence"].append(evidence)
            instance = deepcopy(next(i for i in state["instances"] if i["id"] == "INST-BB01"))
            instance.update(id="INST-BB01-0901", material_ids=[mid], responsibility="仅链衔接使用的控制职责。")
            state["instances"].append(instance)
            check = deepcopy(next(c for c in state["checks"] if c["id"] == "CHK-BB01-0001"))
            check.update(id="CHK-BB01-0901", instance_ids=[instance["id"]], evidence_ids=[evidence["id"]])
            state["checks"].append(check)
            control = {"id": "CTL-BB01-0901", "description": "仅链上的身份限制及反证。",
                       "instance_ids": [instance["id"]], "check_ids": [check["id"]], "evidence_ids": [evidence["id"]]}
            state["controls"].append(control)
            state["chains"] = [{"id": "CHAIN-AA01-DEPENDENCIES", "title": "包含无独立发现的控制跳", "entry_exposure": "ADJ",
                                "steps": [{"check_id": state["findings"][0]["check_ids"][0], "description": "入口检查。"},
                                          {"check_id": check["id"], "description": "下游控制与其材料。"}]}]
            confirm_fixture_plan(state, chain_placements=[{"chain_id": "CHAIN-AA01-DEPENDENCIES", "kind": "boundary",
                                                           "target_id": None, "reason": "保留链上额外控制的边界证据。"}])
            assert_facts(state)
            assert not validate(workspace, state), "chain-only dependency fixture must be valid"
            data = serialized(runs.packet(state, [state["findings"][0]["id"]]))
            assert all(check["id"] not in f["check_ids"] for f in state["findings"])
            assert mid not in data["materials"] and mid in data["chain_sources"]["materials"]
            assert check["id"] in {c["id"] for c in data["chain_sources"]["checks"]}
            assert control["id"] in {c["id"] for c in data["chain_sources"]["controls"]}
            assert instance["id"] in data["chain_sources"]["instances"]
            assert not runs.stale_reasons(state, data)
            variations = [
                ("checks", check["id"], "explanation", "这道控制新增一个已知前提。"),
                ("controls", control["id"], "description", "反证有效范围发生变化。"),
                ("instances", instance["id"], "responsibility", "链上职责范围变化。"),
                ("evidence", evidence["id"], "observation", "源码读取结果变化。"),
            ]
            for category, rid, field, value in variations:
                bad = deepcopy(state)
                row = next(r for r in bad[category] if r["id"] == rid)
                assert row[field] != value
                row[field] = value
                assert_facts(bad)
                reasons = runs.stale_reasons(bad, data)
                assert "链检查、反证或材料依赖已改变" in reasons, (category, reasons)
                assert "任务事实或复核已改变" not in reasons
            path = audit.material_path(state, state["materials"][mid])
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\nsource changed\n")
                assert path.read_bytes() != original
                reasons = runs.stale_reasons(state, data)
                assert "源文件已变化或不可读：" + mid in reasons
                assert "任务事实或复核已改变" not in reasons
            finally:
                path.write_bytes(original)
    test("chain-only-check-control-instance-evidence-and-material-drift-are-bound", chain_only_sources_and_file_drift)

    def protocol_task(state, kind="analysis", version=2):
        ids = sorted(f["id"] for f in state["findings"])
        data = serialized(runs.packet(state, ids))
        return {"id": "T-PROTOCOL", "kind": kind, "finding_ids": ids,
                "owner_finding_ids": ids, "input_digest": attr.fingerprint(data), "protocol_version": version}

    def raw_signals_are_not_obligations():
        # The second half writes `related_findings` by hand because the fixture is its only
        # producer: no role can satisfy 「目标须已存在」 for a finding in another unit that
        # has not merged yet, so the field measures 0 on real audits. Green here proves the
        # obligation fires when the field is set — not that anything sets it.
        with fixture() as (workspace, state):
            assert any(c["key"].startswith("fm:") for c in rc.candidates(state))
            assert any(c["key"].startswith("file:") for c in rc.candidates(state))
            assert rc.comparison_candidates(state) == []
            task = protocol_task(state); attempt = {"n": 1}
            result = analysis_result("RUN-signals", task, attempt)
            runs.validate_result(state, task, result, attempt, "RUN-signals")
            assert runs._issues(state, {"T1": result}) == [], "raw retrieval hits became required comparison tasks"
            left, right = state["findings"][:2]
            left["related_findings"] = [{"finding_id": right["id"], "relation": "possible_same_defect",
                                          "reason": "共享失效实现的显式待核关系。", "evidence_ids": left["evidence_ids"][:1]}]
            right["related_findings"] = [{"finding_id": left["id"], "relation": "overlaps",
                                           "reason": "反向观察同一显式关系。", "evidence_ids": right["evidence_ids"][:1]}]
            rebind(workspace, state)
            task = protocol_task(state); result = analysis_result("RUN-signals", task, attempt)
            assert len(rc.comparison_candidates(state)) == 1
            issues = runs._issues(state, {"T1": result})
            assert len(issues) == 1 and issues[0]["kind"] == "candidate_comparison"
            assert set(issues[0]["finding_ids"]) == {left["id"], right["id"]}
            result["comparisons"] = [{"finding_ids": [left["id"], right["id"]],
                                      "conclusion": "distinct", "reason": "已回源确认两个独立控制实现。"}]
            runs.validate_result(state, task, result, attempt, "RUN-signals")
            assert runs._issues(state, {"T1": result}) == []
    test("only-explicit-relations-create-comparison-obligations", raw_signals_are_not_obligations)

    def deduplicate_basis():
        with fixture() as (workspace, state):
            task = protocol_task(state); attempt = {"n": 1}; pair = task["finding_ids"][:2]
            results = {}
            for number, evidence_id in ((1, "E-AA01-001"), (2, "E-BB01-001")):
                result = analysis_result("RUN-basis", task, attempt)
                item = {"finding_ids": list(reversed(pair)) if number == 2 else pair,
                        "reason": "不同核查来源报告同一待核关系。", "evidence_ids": [evidence_id]}
                result["cross_file_leads"] = [deepcopy(item), deepcopy(item)]
                runs.validate_result(state, task, result, attempt, "RUN-basis")
                results["T" + str(number)] = result
            issues = runs._issues(state, results)
            assert len(issues) == 1
            assert issues[0]["finding_ids"] == sorted(pair)
            assert len(issues[0]["basis"]) == 2, "deduplication dropped a source or retained an identical duplicate"
            assert {b["task_id"] for b in issues[0]["basis"]} == {"T1", "T2"}
            assert {b["item"]["evidence_ids"][0] for b in issues[0]["basis"]} == {"E-AA01-001", "E-BB01-001"}
            assert runs._issues(state, dict(reversed(list(results.items())))) == issues
    test("same-issue-deduplicates-with-all-distinct-basis-preserved", deduplicate_basis)

    def overlap_is_not_transitive_merge():
        with fixture() as (workspace, state):
            task = protocol_task(state); attempt = {"n": 1}
            first, second, third = task["finding_ids"][:3]
            results = {}
            for number, members in enumerate(((first, second), (second, third), (first, third)), 1):
                result = analysis_result("RUN-overlapping", task, attempt)
                result["group_proposals"] = [{"finding_ids": list(members), "reason": "局部同源建议；重叠部分需收口裁决。"}]
                runs.validate_result(state, task, result, attempt, "RUN-overlapping")
                results["T" + str(number)] = result
            before = deepcopy(state)
            issues = runs._issues(state, results)
            overlaps = [i for i in issues if i["kind"] == "overlapping_groups"]
            assert len(overlaps) == 1 and len(overlaps[0]["basis"]) == 3
            assert overlaps[0]["finding_ids"] == sorted((first, second, third))
            assert state == before, "overlap closure silently merged defects or altered records"
    test("overlap-conflict-has-one-issue-all-basis-and-no-transitive-merge", overlap_is_not_transitive_merge)

    def finish(workspace, state, run_id, task_id, change=None):
        runs.dispatch(workspace, state, run_id, task_id, {"limit": 8, "active_agent_ids": []})
        root, manifest, _ = runs.load(workspace, run_id)
        task = manifest["tasks"][task_id]; attempt = task["attempts"][-1]
        result = analysis_result(run_id, task, attempt)
        if change:
            change(result)
        runs.validate_result(state, task, result, attempt, run_id)
        audit.write_json(root / attempt["result_path"], result)
        return runs.collect(workspace, state, run_id, [{"task_id": task_id, "attempt": attempt["n"], "event": "completed"}])

    def collect_preserves_later_basis():
        with fixture() as (workspace, state):
            run_id = runs.prepare(workspace, state, "RUN-collect-basis", owner_plan(state))["run_id"]
            pair = sorted(f["id"] for f in state["findings"])[:2]
            def add_lead(result, reason):
                result["cross_file_leads"].append({"finding_ids": pair, "reason": reason})
            finish(workspace, state, run_id, "T0001", lambda r: add_lead(r, "来源一。"))
            summary = finish(workspace, state, run_id, "T0002", lambda r: add_lead(r, "来源二。"))
            assert len(summary["issues"]) == 1 and len(summary["issues"][0]["basis"]) == 2
            root, manifest, _ = runs.load(workspace, run_id)
            followups = [t["id"] for t in manifest["tasks"].values() if t["kind"] == "reconciliation"]
            assert len(followups) == 1
            summary = finish(workspace, state, run_id, followups[0], lambda r: add_lead(r, "收口阶段补充的第三来源。"))
            assert len(summary["issues"]) == 1
            basis = summary["issues"][0]["basis"]
            assert {b["task_id"] for b in basis} == {"T0001", "T0002", followups[0]}, "collect discarded later reconciliation basis"
            before_tasks = set(runs.load(workspace, run_id)[1]["tasks"])
            again = runs.collect(workspace, state, run_id)
            assert set(runs.load(workspace, run_id)[1]["tasks"]) == before_tasks
            assert again["issues"] == summary["issues"], "repeated collect changed or recursively expanded the same issue"
    test("collect-unions-analysis-and-reconciliation-basis-without-growing-queue", collect_preserves_later_basis)

    def typed_envelopes():
        with fixture() as (workspace, state):
            assert_facts(state)
            attempt = {"n": 1}; run_id = "RUN-envelopes"
            for kind in ("synthesis-forward", "synthesis-sink", "synthesis-edges", "report-organization"):
                task = protocol_task(state, kind)
                result = {"run_id": run_id, "task_id": task["id"], "attempt": 1,
                          "input_digest": task["input_digest"], "reviewer": "typed-fixture"}
                if kind == "report-organization":
                    result.update(report_plan=deepcopy(state["report_plan"]), read_dependencies=[], fact_corrections=[], open_items=[])
                else:
                    result["proposals"] = [{"outcome": "no_chain", "reason": "入口与落点条件不相容，保留无链结论。"}]
                runs.validate_result(state, task, result, attempt, run_id)
                for field, replacement in (("run_id", "RUN-other"), ("task_id", "T-other"),
                                           ("attempt", 2), ("input_digest", "0" * 64)):
                    bad = deepcopy(result); bad[field] = replacement; assert bad != result
                    expect_error("结果的任务、尝试或输入指纹不匹配",
                                 lambda: runs.validate_result(state, task, bad, attempt, run_id))
            task = protocol_task(state)
            result = analysis_result(run_id, task, attempt)
            runs.validate_result(state, task, result, attempt, run_id)
            before = deepcopy(task)
            task["kind"] = "unknown-future-kind"
            assert task != before
            expect_error("未知归因任务类型", lambda: runs.validate_result(state, task, result, attempt, run_id))
            task["protocol_version"] = 1
            expect_error("未知归因任务类型", lambda: runs.validate_result(state, task, result, attempt, run_id))
            plan = owner_plan(state); plan["tasks"][0].update(kind="unknown-future-kind", instructions="不能落入 synthesis 默认分支。")
            expect_error("未知归因任务类型", lambda: runs.prepare(workspace, state, "RUN-unknown", plan))
            no_partial_run(workspace, "RUN-unknown")
            task = protocol_task(state, "report-organization")
            wrong_shape = analysis_result(run_id, task, attempt)
            expect_error("报告组织结果字段或reviewer无效", lambda: runs.validate_result(state, task, wrong_shape, attempt, run_id))
            task = protocol_task(state, "synthesis-forward")
            wrong_shape = analysis_result(run_id, task, attempt)
            expect_error("synthesis 产物需要非空 proposals", lambda: runs.validate_result(state, task, wrong_shape, attempt, run_id))
    test("explicit-kinds-and-all-v2-envelope-fields-are-validated", typed_envelopes)

    def resume_is_byte_stable():
        """Re-preparing an existing run returns it untouched rather than re-planning."""
        with fixture() as (workspace, state):
            ids = sorted(f["id"] for f in state["findings"] if f["status"] == "current")
            plan = {"tasks": [{"id": "T0001", "kind": "analysis", "finding_ids": ids,
                               "reason": "显式计划一次覆盖全部 current。"}]}
            result = runs.prepare(workspace, state, "RUN-resume", task_plan=plan)
            assert "run_id" in result and not result.get("routing_required")
            root, manifest, _ = runs.load(workspace, result["run_id"])
            task = next(iter(manifest["tasks"].values()))
            # An explicit plan names only finding_ids; owners are normalised at creation.
            assert task["owner_finding_ids"] == ids
            before = file_bytes(root)
            resumed = runs.prepare(workspace, state, result["run_id"])
            assert resumed["run_id"] == result["run_id"] and file_bytes(root) == before
    test("existing-run-resume-returns-it-untouched", resume_is_byte_stable)


    def deterministic_reuse_and_read_only():
        with fixture() as (workspace, state):
            before_state = deepcopy(state)
            run_id = runs.prepare(workspace, state, "RUN-original")["run_id"]
            root, manifest, _ = runs.load(workspace, run_id)
            for tid in sorted(manifest["tasks"]):
                finish(workspace, state, run_id, tid)
            before = file_bytes(root)
            assert all(t["effective_state"] == "returned" for t in runs.status(workspace, state, run_id)["tasks"])
            assert file_bytes(root) == before and state == before_state
            again = runs.prepare(workspace, state, "RUN-reuse")
            newer, new_manifest, _ = runs.load(workspace, again["run_id"])
            assert all(t["state"] == "returned" for t in new_manifest["tasks"].values())
            for task in new_manifest["tasks"].values():
                attempt = task["attempts"][0]
                result = json.loads((newer / attempt["result_path"]).read_text(encoding="utf-8"))
                assert result["run_id"] == run_id
                assert attempt["origin"]["run_id"] == run_id
                runs.validate_result(state, task, result, attempt, again["run_id"])
    test("unchanged-input-reuses-origin-bound-results-and-status-is-read-only", deterministic_reuse_and_read_only)

    def parallel_policy_contract():
        # This checks the declared coordinator contract, not model compliance or
        # host quota availability. Both runtime entry points must say the same thing.
        clauses = (
            "分单元工作默认按宿主可用容量并发执行。",
            "只有宿主不具备子代理能力或用户明确要求单执行者时，才按同一份单元清单顺序执行。",
            "临时使用额度耗尽不触发单执行者降级，也不改小并发上限。保存已完成产物和未完成范围，额度恢复后按可用容量继续并发，主代理不接管分析或写作。",
        )
        sections = (
            ("SKILL.md", "## 分单元与派单", "## 执行流程"),
            ("references/orchestration.md", "## 9 容量与三档并行", "## 归因派单与回交"),
        )
        for relative, start, end in sections:
            text = (Path(skill_dir) / relative).read_text(encoding="utf-8")
            assert text.count(start + "\n") == 1, relative + ": missing/duplicate parallel policy section"
            body = text.split(start + "\n", 1)[1].split(end + "\n", 1)[0]
            for clause in clauses:
                assert body.count(clause) == 1, relative + ": parallel/quota policy is missing or inconsistent"
            assert "并行能力不可用或用户未授权" not in body, relative + ": ambiguous serial fallback remains"
    test("temporary-usage-quota-preserves-parallel-coordination", parallel_policy_contract)
    return problems


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill", required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(Path(args.skill).resolve() / "scripts"))
    try:
        problems = run_checks(args.skill)
    except Exception as exc:
        problems = ["checker could not run: %s: %s" % (type(exc).__name__, exc)]
    for problem in problems:
        print("FAIL:", problem)
    if not problems:
        print("PASS: framework routing, ownership, source binding and run protocol")
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
