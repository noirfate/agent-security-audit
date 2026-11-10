# 两段式报告

<!-- report-index-version: 3 -->

事实和独立缺陷身份来自 audit.json 的有效归因；report_plan 只组织阅读。机械阶段导出完整记录、索引和写作任务，report_writer 直接撰写 Markdown。报告篇数、独立缺陷数和 finding 数分别统计。summary 面向 leader，问题报告面向开发者；两者均不要求修复方案。

## 目录与所有权

工作区路径相对审计工作区，机器索引路径相对 report/，Markdown 链接相对当前文件。

- report/index.json：机器维护的来源、统计、写作任务索引、high_vulnerabilities、scenarios、chain_locations 和 finding_map_index。high_findings/ext_chains 保留为原始记录查询入口，不决定正文行数。
- report/records/、record-index/、task-index/：完整机械材料与分片索引。记录和单条长字段不截断，历史重复 ID 用 aliases 保留全部版本。
- report/vulnerabilities/<报告ID>.md：按已确认 report_plan.groups 组织的开发者问题报告。一份报告可包含多个明确区分的独立缺陷，同源多路径集中呈现。
- report/summary.md：严重问题总览、攻击场景和决定结论的边界。
- report/handoffs/<报告ID或summary>.md：作者无法成文时的结构化回交，不是问题报告；由对应作者写，绑定当前任务来源。
- report/notes/<报告ID>.md：作者在写作中核到、但不属于本报告正文的事实；报告照常交付，不是回交，不阻止成文验收。
- report.md：导航。旧作者稿在不再对应任务时按内容指纹归档到 report/legacy/vulnerabilities/，不覆盖历史。

作者先落元数据与七个二级标题的骨架，再逐节增量补；不允许攒完整份再一次性落盘——实测四次一次性产出全部零产出，同一任务改为分段后完成并通过全部判据。骨架不等于交付，`writing_status` 仍由实际内容与指纹决定。

机器不覆盖作者正文。报告计划缺失或过期时不生成新写作任务、不据空清单归档旧稿；先重新比较并提交计划。来源改变的作者稿标 stale，不能只换 source_digest 续用。writing_status 来自实际文件与指纹，不代表语义验收通过。

## 写作输入

按 task_indexes 找任务，沿 input_refs 与各分类索引 locations/aliases 读取有关发现、处置、检查、证据、有效复核、控制、根因、实例、关联链及 report_todos。关联链同时通过 finding_id 和 check_id 检索，输入可能包含主成员之外的上下文；不要把只读上下文计入本报告的主成员。回源时核对实际材料与定位，必要时登记新证据并交事实复核。

每个写作任务另带三项已判好的结论，消费端不再重算：`member_dispositions`（成员处置）、`chain_ids` / `context_chain_ids`（本页呈现的链与仅供参考的链）、`todo_scope`（每条待办在本轮在场的成员，空表示本轮无落点）。另有 `excerpt_path`，指向按证据 locator 预先抽好的源码原文（`report/excerpts/<报告ID>.json`，带路径与 sha256）。作者优先用它，不必为已记录的证据重新读源文件；`unavailable` 与 `truncated_after` 如实标注。它不进 `source_digest`——材料的 sha256 已在包内，材料一变任务自然 stale。

summary 作者读取全部严重独立缺陷及其报告、场景分组、链证据状态和边界材料，以及 report/notes/ 下各作者留的正文外事实（终报复核者同读；需要改记录的由主代理转成 reviewer 的事实订正，`report --check` 的结果里列出当前有哪些）。链推导 run 的接边、无链理由和 pending 账本是论证输入，不能因未列在某个 finding 中而漏掉。不要让每个作者整读 audit.json；使用完整索引定位所需记录。

全部 current finding 有主呈现位置：defect/supplement 随主报告，chain/summary/observation/pending 按 finding_map_index 到相关说明或记录附录。仍为 High/Critical 的非独立处置（链、汇总、观察、待定）必须在 summary 明确解释其性质并保留发现锚点，可按相关问题合写说明，不额外计为漏洞。needs_review/withdrawn 保留历史及边界说明，不作为确认漏洞。

## 模板与元数据

| type | 技能模板 | 工作区输出 |
|---|---|---|
| summary | references/templates/summary.md | report/summary.md |
| vulnerability | references/templates/vulnerability.md | report/vulnerabilities/<报告ID>.md |
| report_handoff | references/templates/report-handoff.md | report/handoffs/<报告ID或summary>.md |

首行为单行 `<!-- audit-report: {JSON} -->`。summary 的 source_digest 取索引顶层；问题报告取 task.source_digest，report_id、finding_ids、vulnerability_ids、root_cause_id 与任务一致。todo_ids 只登记实际落实的待办。每个主 finding 保留 `<a id="发现ID"></a>`；报告计划指定落在详情的链保留 chain ID 锚点。**锚点是机器定位用的，正文叙述不写审计编号**（F- / RC- / CHK- / E- / SYN- / RT-）：编号是审计过程的内部标识，对开发者没有意义，集中放进文末追溯区。机器索引不得手改。回交文件按 report-handoff 模板填写 task_id/source_digest/finding_ids/return_to，活动回交存在即阻止成文验收；来源变化也须主代理核对问题是否已解决，再按内容指纹归档到 report/legacy/handoffs/ 并记录处置依据，不能只改指纹消除回交。

模板规定必答内容和二级章节顺序，章节内按问题因果组织。作者写完整正文，不把每个 finding 逐字段展开或截首句当作报告；脚本仅保存已经写好的文本、装配固定元数据和转义。

## 开发者报告

正文依次说明问题概述、组件与安全边界、触发条件与输入、漏洞机制与证据、受影响范围、验证与复现材料、结论边界与来源。

同一控制失效只解释一次共同机制，使用完整矩阵列出受影响路由、方法、工具或制品及各自条件与差异。独立子问题分别写清失效点，不将相似主题误写成同源，也不把组内最高等级及最宽入口套到所有成员。**后两句是对作者的写作纪律，不是要写进正文的内容**：读者要看的是每个子问题各自的位置、机制与影响，不是这些子问题为什么被分到一组。分组理由与独立性判断属归因记录，由 G9 核，不进开发者报告。必要代码片段、真实定位和可操作输入在本页展开，来源链接用于追溯，不能承担正文缺失的推理。

区分已证明的代码事实、未执行的复现步骤和实际观察。请求示例要包含正确的方法、参数、状态及身份前提，解释预期安全行为和源码支持的越界行为；不把格式错误当作安全对照。只具备静态核查材料时如实说明。模型服从、部署可达和接收方控制未验证时分别保留条件。每个子问题必须给出**定位加片段**：先写文件与位置（行号、符号、字节码偏移或可靠恢复视图），再摘出有问题的那几行代码，并指明问题在哪一行。只给位置不给片段，读者仍要自己去翻，不算讲清楚。摘录照抄原文不改写，不编造源码行号。CWE、CVSS 和版本范围不确定时不强填。

不生成修复方案。事实、影响、等级和可达性冲突交回 reviewer；归因或报告组织不当交回 rootcause_reviewer，经正式记录更新后再成文。

正文之后、`## 7` 之外的无标题尾块是**追溯区**，供回溯审计记录用，开发者定位问题不需要读。它以文件路径为主、编号为辅：先给一张路径前缀到绝对路径的映射（目标可能有多个根，只写相对路径读者拼不出来），再逐行列「正文章节 | 主要文件 | 审计发现编号」。只列编号不列路径等于没给参考。

## Leader 摘要

四节依次为审计对象与关键结论、全部严重问题、重要攻击场景、证据边界。总览覆盖 high_vulnerabilities 中全部有效 High/Critical 独立缺陷，不以 Top N 或篇幅限制省略；同一报告中不同严重子问题也要讲清。同源多路由不重复占行，底层逐 finding 清单留在记录索引。

summary 元数据的 summary_entries 是数组，每项只有 id、report_id、vulnerability_ids。每个有效严重身份恰属一个总览条目；条目引用其主报告，可在同一行明确多个相关子问题。第二节用四列表：问题、等级、原理与条件、影响。每条第一格为 `<a id="条目ID"></a> [问题名称](vulnerabilities/报告ID.md)`。等级填写所含身份的等级集合，按 Critical / High 排列；条件在原理或影响中完整表达。单元格的竖线写为 `\|`。零严重问题保留表头并明确零条。

重要攻击场景按 report_plan.scenarios 写成连贯因果叙述，每个场景保留其 ID 锚点。先解释攻击者最初控制什么和原本不能做什么，再写系统如何接入输入、哪处控制失效、获得什么能力、为何满足下一跳条件，最后写资产影响和限制。可合写共享主干的多条链，但分支条件必须兼容或分别说明；不以箭头串、函数名和编号代替解释。

chain_dispositions 必须覆盖全部登记 chains，取 static_trace/partial/needs_evidence；candidate 只能取后两者，缺少 status 不等于成立。所有入口类型的严重问题都要呈现；[攻击入口类型](method.md#attack-entry-types)中的 EXT 不等于匿名公网访问。其他链按 chain_locations 落到详情或记录边界索引，不要求每条 CHAIN-ID 独占章节。无链理由、接边论证、已撤销组合和阻断控制保持可追溯，不因场景合并升级验证状态。

## 执行与验收

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" gate --workspace "$AUDIT_WORKSPACE" --prepare
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" report --workspace "$AUDIT_WORKSPACE"
# report_writer 按确认的任务和模板撰写，交回实际落实的 report_todos。
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" report --workspace "$AUDIT_WORKSPACE" --check
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" gate --workspace "$AUDIT_WORKSPACE"
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" validate --workspace "$AUDIT_WORKSPACE"
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" snapshot --workspace "$AUDIT_WORKSPACE"
```

G9 核归因闭合，G10 核实际材料、报告计划、身份与成员映射、来源、链接、严重问题覆盖、场景和链去向。准备闸门仅延后报告待办与 G10。report --full 的完整记录与 coverage-details.md 是机械附录，不替代正文。snapshot 保存实际工作区，不重新生成作者稿。

机械通过不能证明文字正确。每份正文完成后，读者应能只靠本页说清前提、失效、影响面和证据边界；summary 应能解释每次能力变化及最终后果。首次读者复述不了的因果需要重写，不能用补关键词或增加字数代替。未闭合工作明确作为阶段范围，不宣称全量完成。
