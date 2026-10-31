# 两段式报告

报告由机械材料导出与模型撰写两段组成。审计事实仍以 `audit.json` 为准；最终叙述由 report_writer 直接写 Markdown，不把字段展开或截取首句当作成文。格式与检查由本技能维护，不调用其他报告技能。

## 目录与所有权

所有工作区路径相对审计工作区；所有机器 JSON 索引内的路径（包括任务分片的 task.path、分类索引的材料位置）均相对 `report/`；Markdown 链接相对当前文件。

- `report/index.json`：机器维护的来源指纹、统计、分类分片、记录位置、写作任务和报告映射。不内嵌长证据或机理。
- `report/records/<类别>/<单元或记录>-<分片>.md`：机械材料。保留每条记录完整 JSON 与稳定 ID 锚点；按类别和单元拆分，再按大小分片。单条超大记录单独成片，不截断。历史日志重复 ID 用定位后缀逐项保留，JSON 内的原 ID 不改写。原字段保持原义，未复核材料不会因导出而成为当前结论。
- `report/summary.md`：模型撰写的独立可读总览。
- `report/vulnerabilities/<根因或发现ID>.md`：模型撰写的独立漏洞报告。已裁决 merge 的当前成员同文，其余当前发现单独成文；每个成员保留位置、前提、影响差异与显式锚点。
- 工作区根 `report.md` 是机械导航；迁移时旧正文保存在 `report/legacy/report.md`。旧覆盖附录可以保留为历史，新的分类材料是本次写作入口。

机器只替换 `records/`、`record-index/`、`task-index/`、`index.json` 与根导航，不覆盖人工正文。重新导出后，正文依据未变则仍为草稿，依据变化则标记 stale；不能把 stale 文件当作本次交付。`writing_status` 来自文件与指纹检查，不表示语义审阅已通过。

## 写作输入与任务

先按需查询 `index.json` 的统计、high_findings、ext_chains 和索引目录，不把整份索引输出到上下文。`task_indexes` 指向按单元拆分的任务 JSON；`catalog` 指向各类别的 `record-index/*.json`，其中包含材料分片清单、locations 与 aliases。每个任务索引的条目给出 `id/path/finding_ids/root_cause_id/source_digest/todo_ids/input_refs`。分类索引中的 `locations` 把 input_refs 中的类别、ID 映射到材料文件与锚点；重复历史 ID 先查 `aliases` 取得全部定位键，再逐项读 locations，不能只读其中一条。作者只读当前任务的发现、根因、检查、证据、复核、防护反证与呈现待办；目标源码按需回读。不能要求每个作者通读整个 audit.json。

`summary_todo_ids` 是没有按发现 ID 路由的待办，由总览作者处理。自动路由只是检索帮助；涉及跨报告的要求由模型核查，必要时把相关资料一并读入。入口标签按[攻击入口类型](method.md#attack-entry-types)解释；索引按已登记值归类，不证明分类正确。发现标签与原始来源冲突或其他新矛盾时交回复核流程，不在报告里更改入口类型、等级、可达性或已复核主张。

全部 current 发现必须有报告映射，不仅生成高危报告。needs_review 和 withdrawn 只留在分类材料及总览的范围说明，不计入当前漏洞清单。根因分组改变阅读组织，不把展示组数宣称为独立漏洞数。

## 人工 Markdown 模板

每类人工 Markdown 都使用本技能模板：

| type | 模板（相对本技能） | 输出（相对工作区） |
|---|---|---|
| summary | `references/templates/summary.md` | `report/summary.md` |
| vulnerability | `references/templates/vulnerability.md` | `report/vulnerabilities/<ID>.md` |

模板固定必答问题与章节顺序，正文由作者按证据组织。新增人工文档类型时先给它模板及检查；检查、复核和方法过程已有分类材料承载，不另写无模板的补充散文。不要创建后处理脚本把解释拼回机械正文。

每份报告第一行是 `<!-- audit-report: {JSON} -->`。JSON 必须在一行，字段以模板为准。source_digest 从索引复制：summary 用索引顶层值，漏洞报告用对应 task 的值。漏洞报告的 finding_ids 和 root_cause_id 必须与 task 完全相同。todo_ids 记录实际落实的待办，不能只列编号而不落实要求。索引机器维护，作者不手改统计或 writing_status。

## Summary 内容契约

四节按模板顺序排列：主要发现概览、从 EXT 外部入口进入的攻击链、覆盖与结论边界、全部 Critical / High 漏洞。summary 不包含修复建议。读者仅读 summary 就能理解主要发现的入口前提、原理和影响；详情链接仅用于进一步核对。

EXT 链逐条呈现，包括未闭合候选的明确落点。每条以 `### CHAIN-ID 标题` 开头，写出外部主体、入口、必要身份/配置/用户交互、逐跳失效与能力变化、最终资产和影响。EXT 不等于公网匿名访问。元数据 chain_dispositions 必须覆盖索引全部 ext_chains，取 static_trace / partial / needs_evidence；这些值表达本次叙述的证据边界，不是运行时成功标记。原记录仍为 candidate 的链只能写 partial 或 needs_evidence。其他链是否闭合要读证据判断，缺少 status 不能机械判为成立。实测与静态走查分别说明，不因补齐叙述而宣称复现。

最后一节逐条列出全部 `current` 且 `severity` 为 `critical/high` 的发现。表格固定四列：编号、等级、漏洞原理、影响。编号使用指向该发现报告的 Markdown 链接，合并报告可带成员锚点；每个发现一行，同根因也不省略成员。等级先 critical 后 high，同等级按 EXT、ADJ、INT、未分类，再按 ID 排序，与 index.high_findings 一致。原理与影响各用简洁完整句子，保留决定成立的前提，不用标题或“见详情”代替解释。表格单元格中的竖线写成 `\|`。

末尾清单必须全量，没有 Top N 或全文字数上限。零高危时保留表头并明确零条。没有 EXT 链时明确记录不存在此类已登记链，不虚构路径。要核对主要结论的语义，不用机械关键词检查代替阅读。

## 执行与交付

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" gate --workspace "$AUDIT_WORKSPACE" --prepare
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" report --workspace "$AUDIT_WORKSPACE"
# report_writer 按索引和两个模板完成正文，落实 report_todos；写入者互斥保存 audit.json
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" report --workspace "$AUDIT_WORKSPACE" --check
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" gate --workspace "$AUDIT_WORKSPACE"
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" validate --workspace "$AUDIT_WORKSPACE"
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" snapshot --workspace "$AUDIT_WORKSPACE"
```

`report` 只完成机械导出，不代表人工段完成。`report --check` 核对全量映射、模板、来源指纹、链接、每个根因成员、高危表及 EXT 链落点，并刷新索引的检查状态。作者/复核者另行判断原理、影响与证据是否相符。准备 gate 仅延后报告待办和 G10 成文检查，不放宽其他审计要求；最终 gate 必须核对当前磁盘文件。

`report --full` 额外导出 `report/full-records.md` 与 `coverage-details.md` 供单文件记录查阅；它们是机械记录，不替代两段式交付，也不覆盖人工正文。`--full` 与 `--check` 不同时使用。snapshot 只归档实际工作区，不重新生成作者稿。
