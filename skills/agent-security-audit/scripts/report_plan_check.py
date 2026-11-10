"""Source binding and structural counterexamples for model-authored report plans.

Only caller-owned temporary fixture workspaces are written. Each negative case
first proves its mutation occurred, then requires the public validator to reject
it. No rule here determines that two real findings share a defect.
"""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True


def unbound(plan):
    """An explicit author resubmission, never a production stale-plan repair."""
    result = deepcopy(plan)
    result.pop("source_digest", None)
    for key in ("groups", "scenarios", "chain_placements"):
        for row in result[key]:
            row.pop("source_digest", None)
    return result


def run_checks(skill_dir):
    from attribution import build_vulnerability_view, disposition_errors
    from report_fixtures import (build_case, _review, adjudicate_fixture,
                                 confirm_fixture_plan, change_one_finding)
    from report_plan import (bind_plan, plan_errors, build_report_view,
                             finding_objects, related_chains)
    import self_check
    problems = []
    if "report-plan" not in {name for name, _ in self_check.CHECKS}:
        problems.append("report-plan is not registered in the full suite")

    def test(name, fn):
        try:
            fn()
        except Exception as exc:
            problems.append(name + ": " + type(exc).__name__ + ": " + str(exc))

    def with_case(case, fn):
        with tempfile.TemporaryDirectory(prefix="report-plan-check-") as tmp:
            workspace, state, expected = build_case(tmp, case, skill_dir)
            assert not plan_errors(state), "positive plan fixture is invalid"
            return fn(workspace, state, expected)

    def reject_plan(name, mutation, case="grouped"):
        def check(workspace, state, expected):
            raw = unbound(state["report_plan"])
            before = deepcopy(raw)
            mutation(raw)
            assert raw != before, "negative fixture was not changed"
            try:
                bind_plan(state, raw)
            except ValueError:
                return
            raise AssertionError("invalid plan was accepted")
        test(name, lambda: with_case(case, check))

    def positive(workspace, state, expected):
        before = deepcopy(state)
        view = build_report_view(state)
        assert not view["errors"]
        ids = [vid for g in view["groups"] for vid in g["vulnerability_ids"]]
        assert sorted(ids) == sorted(expected["vulnerabilities"])
        assert len(ids) == len(set(ids)), "duplicate primary independent identity"
        assert view["statistics"]["independent_vulnerabilities"] == len(ids)
        assert view["statistics"]["report_tasks"] == len(expected["reports"])
        assert state == before, "reading a plan mutated audit state"
        assert bind_plan(state, unbound(state["report_plan"])) == state["report_plan"]
    for case in ("empty", "zero_current", "small", "mixed", "merged", "grouped",
                 "ext", "check_chain", "non_independent"):
        test("positive-" + case, lambda case=case: with_case(case, positive))

    def duplicate_owner(plan):
        plan["groups"][1]["vulnerability_ids"].append(plan["groups"][0]["vulnerability_ids"][0])
    reject_plan("one-identity-cannot-have-two-primary-reports", duplicate_owner)
    reject_plan("every-identity-needs-a-primary-report", lambda p: p["groups"].pop())
    reject_plan("report-member-is-an-independent-identity-not-a-finding",
                lambda p: p["groups"][0].update(vulnerability_ids=["F-AA01-01"]), "merged")
    reject_plan("unknown-identity-is-rejected",
                lambda p: p["groups"][0]["vulnerability_ids"].append("F-UNKNOWN-01"))
    reject_plan("duplicate-identity-inside-one-report-is-rejected",
                lambda p: p["groups"][0]["vulnerability_ids"].append(p["groups"][0]["vulnerability_ids"][0]))
    reject_plan("empty-reading-group-is-rejected", lambda p: p["groups"][0].update(vulnerability_ids=[]))
    reject_plan("blank-grouping-reason-is-rejected", lambda p: p["groups"][0].update(grouping_reason=" "))
    reject_plan("unsafe-report-path-identifier-is-rejected", lambda p: p["groups"][0].update(id="../escape"))
    reject_plan("duplicate-report-id-is-rejected", lambda p: p["groups"][1].update(id=p["groups"][0]["id"]))
    reject_plan("plan-cannot-copy-fact-or-severity-overrides",
                lambda p: p["groups"][0].update(severity="critical"))
    reject_plan("unsupported-plan-version-is-rejected", lambda p: p.update(version=999))
    reject_plan("bind-does-not-overwrite-stale-plan-digest", lambda p: p.update(source_digest="0" * 64))
    reject_plan("bind-does-not-overwrite-stale-group-digest",
                lambda p: p["groups"][0].update(source_digest="0" * 64))
    reject_plan("framework-label-needs-member-basis",
                lambda p: p["groups"][0].update(framework_object_ids=["UNMAPPED.OBJECT"]))

    def group_size_cap_holds_on_both_paths(workspace, state, expected):
        import report_plan
        plan = unbound(state["report_plan"])
        biggest = max(plan["groups"], key=lambda g: len(g["vulnerability_ids"]))
        original = report_plan.MAX_GROUP_IDENTITIES
        try:
            lowered = len(biggest["vulnerability_ids"]) - 1
            assert lowered >= 1, "fixture has no group big enough to exercise the cap"
            report_plan.MAX_GROUP_IDENTITIES = lowered
            try:
                bind_plan(state, plan)
                raise AssertionError("binding accepted a group over the cap")
            except ValueError as exc:
                assert "独立身份" in str(exc), "rejected for another reason: %s" % exc
            try:
                report_plan.validate_proposal(state, {"version": 1, "groups": plan["groups"]})
                raise AssertionError("the proposal path accepted a group over the cap")
            except ValueError as exc:
                assert "独立身份" in str(exc), "rejected for another reason: %s" % exc
            report_plan.MAX_GROUP_IDENTITIES = original
            assert not plan_errors(state), "the same plan does not pass at the real cap"
        finally:
            report_plan.MAX_GROUP_IDENTITIES = original
    test("report-group-size-cap-holds-on-both-paths",
         lambda: with_case("grouped", group_size_cap_holds_on_both_paths))

    def missing_or_empty_plan(workspace, state, expected):
        before = deepcopy(state)
        state["report_plan"] = None
        assert state != before
        if expected["vulnerabilities"] or state["chains"]:
            assert plan_errors(state)
        else:
            assert not plan_errors(state), "valid zero output must remain representable"
            assert build_report_view(state)["statistics"]["report_tasks"] == 0
    for case in ("empty", "small", "check_chain"):
        test("missing-plan-" + case, lambda case=case: with_case(case, missing_or_empty_plan))

    def fact_change(workspace, state, expected):
        old_plan = deepcopy(state["report_plan"])
        old_impact = state["findings"][0]["impact"]
        change_one_finding(workspace, state)
        assert state["findings"][0]["impact"] != old_impact
        assert state["report_plan"] == old_plan
        assert plan_errors(state), "fact change failed to invalidate plan"
        view = build_report_view(state)
        assert view["errors"] and not view["groups"]
        adjudicate_fixture(state)
        assert plan_errors(state), "re-attribution must not imply a new reading-group decision"
        raw = unbound(old_plan)
        state["report_plan"] = bind_plan(state, raw)
        assert not plan_errors(state)
        assert state["report_plan"] != old_plan
    test("fact-review-and-attribution-do-not-auto-refresh-reading-plan",
         lambda: with_case("grouped", fact_change))

    def withdrawal(workspace, state, expected):
        finding = state["findings"][0]
        assert finding["status"] == "current"
        finding["status"] = "withdrawn"
        assert finding["status"] == "withdrawn"
        assert plan_errors(state), "withdrawn member remained a valid report member"
        view = build_vulnerability_view(state)
        assert all(finding["id"] not in v["finding_ids"] for v in view["vulnerabilities"])
    test("withdrawn-source-invalidates-membership", lambda: with_case("grouped", withdrawal))

    def review_change(workspace, state, expected):
        row = next(r for r in state["reviews"] if r["finding_id"] == "F-AA01-01")
        old = row["rationale"]
        row["rationale"] = old + " 发现新的适用条件。"
        assert row["rationale"] != old
        assert plan_errors(state), "effective review changes were omitted from dependencies"
    test("effective-review-is-a-source-dependency", lambda: with_case("small", review_change))

    def change_chain(workspace, state, expected):
        chain = next(c for c in state["chains"] if c["id"] == "CHAIN-AA01-02")
        assert all("finding_id" not in s for s in chain["steps"])
        assert chain in related_chains(state, ["F-AA01-01"])
        assert chain in related_chains(state, ["F-CC01-01"])
        before = deepcopy(chain)
        chain["description"] += " 新增必要用户交互条件。"
        assert chain != before
        assert plan_errors(state), "check-only related chain did not stale dependent plans"
    test("chain-check-id-dependency-is-not-lost", lambda: with_case("check_chain", change_chain))

    def chain_check_evidence(workspace, state, expected):
        # This check has no finding. A chain's check_id still makes its evidence
        # relevant; a finding_id-only dependency traversal misses this mutation.
        evidence = deepcopy(next(e for e in state["evidence"] if e["id"] == "E-CC01-002"))
        evidence["id"] = "E-CC01-003"
        state["evidence"].append(evidence)
        check = deepcopy(next(c for c in state["checks"] if c["id"] == "CHK-CC01-0002"))
        check.update(id="CHK-CC01-0901", evidence_ids=[evidence["id"]])
        state["checks"].append(check)
        chain = next(c for c in state["chains"] if c["id"] == "CHAIN-AA01-02")
        chain["steps"].append({"check_id": check["id"], "note": "附加衔接控制证据。"})
        state["report_plan"] = bind_plan(state, unbound(state["report_plan"]))
        assert not plan_errors(state)
        assert all(check["id"] not in f["check_ids"] for f in state["findings"])
        original = evidence["observation"]
        evidence["observation"] += " 这道控制要求额外身份。"
        assert evidence["observation"] != original
        assert plan_errors(state), "evidence referenced only by a chain check was omitted"
    test("chain-only-check-evidence-invalidates-plan",
         lambda: with_case("check_chain", chain_check_evidence))

    def cross_theme(workspace, state, expected):
        instance = deepcopy(next(i for i in state["instances"] if i["id"] == "INST-AA01"))
        instance.update(id="INST-AA01-02", framework_object_ids=["X1.3"])
        state["instances"].append(instance)
        check = deepcopy(next(c for c in state["checks"] if c["id"] == "CHK-AA01-0001"))
        check.update(id="CHK-AA01-0002", failure_mode_id="FM-X1.3-03", instance_ids=[instance["id"]])
        state["checks"].append(check)
        state["findings"][0]["check_ids"].append(check["id"])
        _review(workspace, state)
        adjudicate_fixture(state)
        raw = unbound(state["report_plan"])
        first = next(g for g in raw["groups"] if g["id"] == "REPORT-ACCESS")
        first["framework_object_ids"] = ["A1.1", "X1.3"]
        state["report_plan"] = bind_plan(state, raw)
        assert finding_objects(state, ["F-AA01-01"]) == ["A1.1", "X1.3"]
        assert not plan_errors(state)
        view = build_report_view(state)
        assert view["finding_map"]["F-AA01-01"]["report_id"] == "REPORT-ACCESS"
        assert view["statistics"]["independent_vulnerabilities"] == 4
        assert view["statistics"]["report_tasks"] == 2
    test("all-checks-contribute-cross-theme-references-without-duplicate-ownership",
         lambda: with_case("grouped", cross_theme))

    reject_plan("every-chain-needs-a-main-placement", lambda p: p["chain_placements"].pop(), "check_chain")
    reject_plan("chain-cannot-belong-to-two-scenes",
                lambda p: p["scenarios"].append(dict(deepcopy(p["scenarios"][0]), id="SCENE-OTHER")), "check_chain")
    reject_plan("scene-and-placement-cannot-both-own-chain",
                lambda p: p["chain_placements"].append({"chain_id": "CHAIN-AA01-02", "kind": "boundary",
                                                       "target_id": None, "reason": "重复主去向。"}), "check_chain")
    reject_plan("report-chain-target-must-exist",
                lambda p: p["chain_placements"][0].update(kind="report", target_id="REPORT-MISSING"), "check_chain")
    reject_plan("boundary-location-is-derived-not-user-path",
                lambda p: p["chain_placements"][0].update(target_id="../outside.md"), "check_chain")
    reject_plan("scene-cannot-reference-unknown-independent-identity",
                lambda p: p["scenarios"][0]["vulnerability_ids"].append("F-UNKNOWN-01"), "check_chain")

    def candidates_and_non_independent(workspace, state, expected):
        before = deepcopy(state["chains"])
        view = build_report_view(state)
        assert state["chains"] == before, "presentation grouping changed chain state"
        candidate = next(c for c in state["chains"] if c["id"] == "CHAIN-AA01-02")
        assert candidate["status"] == "candidate"
        assert view["chain_locations"][candidate["id"]]["kind"] == "scenario"
    test("scenario-membership-does-not-promote-candidate",
         lambda: with_case("check_chain", candidates_and_non_independent))

    def observation(workspace, state, expected):
        view = build_report_view(state)
        assert view["statistics"]["observations"] == 1
        assert view["statistics"]["supplements"] == 1
        assert view["statistics"]["pending_findings"] == 1
        assert view["statistics"]["independent_vulnerabilities"] == 1
        assert view["finding_map"]["F-CC01-02"]["kind"] == "observation"
        assert view["finding_map"]["F-BB01-01"]["kind"] == "pending"
        assert view["finding_map"]["F-BB01-01"]["path"] == "summary.md#F-BB01-01"
        assert view["finding_map"]["F-CC01-01"]["report_id"] == "F-AA01-01"
        row = deepcopy(next(r for r in state["finding_dispositions"] if r["kind"] == "observation"))
        assert not disposition_errors(state, row)
        del row["evidence_ids"]
        assert "evidence_ids" not in row
        assert disposition_errors(state, row), "observation accepted without judgment evidence"
    test("observations-need-evidence-and-do-not-hide-pending", lambda: with_case("non_independent", observation))
    reject_plan("observation-cannot-be-a-report-vulnerability",
                lambda p: p["groups"][0]["vulnerability_ids"].append("F-CC01-02"), "non_independent")

    def supplement_target_withdrawn(workspace, state, expected):
        target = next(f for f in state["findings"] if f["id"] == "F-AA01-01")
        assert target["status"] == "current"
        target["status"] = "withdrawn"
        view = build_vulnerability_view(state)
        assert view["finding_map"]["F-CC01-01"]["kind"] == "pending"
        assert view["finding_map"]["F-BB01-01"]["kind"] == "pending"
        assert view["finding_map"]["F-CC01-02"]["kind"] == "observation"
        assert plan_errors(state), "withdrawn supplement target left report membership valid"
    test("withdrawn-supplement-target-stays-pending-not-observation",
         lambda: with_case("non_independent", supplement_target_withdrawn))

    def title_change_is_not_fact_change(workspace, state, expected):
        before_reviews = deepcopy(state["reviews"])
        old = state["report_plan"]["groups"][0]["title"]
        state["report_plan"]["groups"][0]["title"] = old + "（阅读标题）"
        assert not plan_errors(state), "title-only edit unnecessarily invalidated fact sources"
        assert state["reviews"] == before_reviews
    test("presentation-title-does-not-require-fact-review", lambda: with_case("small", title_change_is_not_fact_change))

    def read_only_and_deterministic(workspace, state, expected):
        before_state = deepcopy(state)
        before_files = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
        first = build_report_view(state)
        assert bind_plan(state, unbound(state["report_plan"])) == state["report_plan"]
        assert build_report_view(state) == first
        assert not plan_errors(state)
        after_files = {p.relative_to(workspace): p.read_bytes() for p in workspace.rglob("*") if p.is_file()}
        assert state == before_state and before_files == after_files, "pure plan APIs wrote files or records"
    test("plan-validation-is-read-only-idempotent-and-deterministic",
         lambda: with_case("grouped", read_only_and_deterministic))

    def serious_context_stays_visible(workspace, state, expected):
        import reporting
        from reporting_check import author_fixture, replace_once
        from attribution import decision_digest
        finding = next(f for f in state['findings'] if f['id'] == 'F-CC01-02')
        finding['severity'] = 'high'
        _review(workspace, state)
        # Explicit fixture-author reconfirmation, not automatic production repair.
        for row in state['finding_dispositions']:
            row['source_digest'] = decision_digest(state, row)
        confirm_fixture_plan(state)
        index = reporting.export_package(workspace, state)
        assert index['statistics']['attribution']['independent_vulnerabilities'] == 1
        assert index['finding_map']['F-CC01-02']['kind'] == 'observation'
        assert index['finding_map']['F-CC01-02']['path'] == 'summary.md#F-CC01-02'
        author_fixture(workspace, state, index)
        assert not reporting.validate_package(workspace, state)
        path = workspace / 'report/summary.md'
        replace_once(path, '<a id="F-CC01-02"></a>', '')
        assert any('严重非独立项' in e for e in reporting.validate_package(workspace, state))
    test('non-independent-label-cannot-hide-a-serious-source-claim',
         lambda: with_case('non_independent', serious_context_stays_visible))

    def writer_handoff(workspace, state, expected):
        import json
        import re
        import reporting
        from reporting_check import author_fixture
        index = reporting.export_package(workspace, state)
        author_fixture(workspace, state, index)
        assert not reporting.validate_package(workspace, state)
        task = index['tasks'][0]
        path = workspace / 'report' / task['handoff_path']
        meta = {'type': 'report_handoff', 'task_id': task['id'], 'source_digest': task['source_digest'],
                'finding_ids': task['finding_ids'], 'return_to': 'reviewer'}
        template = Path(skill_dir) / 'references/templates/report-handoff.md'
        assert template.is_file(), 'handoff has no cold-start template'
        assert re.findall(r'^## (.+)$', template.read_text(), re.M) == [
            '1. 无法成文的主张', '2. 支撑与冲突证据', '3. 回交范围'], 'handoff producer and validator contracts differ'
        body = '\n\n'.join(['## 1. 无法成文的主张', '当前材料不支持接口返回的范围。',
                             '## 2. 支撑与冲突证据', '回源发现与旧复核之间的具体冲突。',
                             '## 3. 回交范围', '先复核该事实，再生成新的写作输入。'])
        path.parent.mkdir(parents=True)
        path.write_text('<!-- audit-report: ' + json.dumps(meta, ensure_ascii=False) + ' -->\n' + body)
        assert path.exists(), 'handoff mutation did not happen'
        errors = reporting.validate_package(workspace, state)
        assert any('回交未闭合' in e for e in errors), errors
        updated = reporting.export_package(workspace, state)
        assert next(t for t in updated['tasks'] if t['id'] == task['id'])['writing_status'] == 'needs_review'
        assert not reporting.finalize_package(workspace, state)['valid']
        meta['source_digest'] = '0' * 64
        path.write_text('<!-- audit-report: ' + json.dumps(meta) + ' -->\n' + body)
        assert any('回交来源已变化' in e for e in reporting.validate_package(workspace, state)), 'changing a digest silently dismissed the handoff'
        meta['source_digest'] = task['source_digest']
        meta['return_to'] = 'unknown-role'
        path.write_text('<!-- audit-report: ' + json.dumps(meta) + ' -->\n' + body)
        assert any('回交内容契约无效' in e for e in reporting.validate_package(workspace, state))
        # Model review of the handoff is separate from structural validation.
        # A resolved handoff is archived, not made stale by editing its digest.
        archived = workspace / 'report/legacy/handoffs' / path.name
        archived.parent.mkdir(parents=True)
        path.rename(archived)
        assert archived.is_file() and not path.exists()
        assert not reporting.validate_package(workspace, state)
    test('unable-to-author-has-a-bound-handoff-and-cannot-pass-as-prose',
         lambda: with_case('grouped', writer_handoff))
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
        print("PASS: report plan source bindings and structural counterexamples")
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
