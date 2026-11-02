# 目标知识库、查询与复审

## 文件与所有权

工作区包含`audit.json`（目标分析记录）、`report/`（机械材料、索引与按模板撰写的报告）、`report.md`（导航）、`baselines/<指纹>/`（只读引用知识）和`snapshots/`（只追加历史）。可选动态验证另外生成`dynamic/`固定会话配置与`observations/`观测文件。分单元执行时另有`units/<单元>/`（brief、断点、单元产物与跨范围观察）和可选`surface/`（检索位置与摘要）。合入被拒时原产物留在原路径，错误输出给出原因。初始化和续审都不向框架或安装的skill写入。

目标记录版本为`1.8`，与框架契约版本独立。更早的工作区先执行`refresh`：归档旧记录，新增空集合，不改写历史快照。`1.0`迁移会把发现标为待复核；`1.2`与`1.3`只增加调度集合，`1.4`把两阶段改成三阶段（单元的`stage`上移为`phase`，队列键改名），`1.5`移除读取回执集合`reads`（有界读取那条通路已撤，覆盖记录改为无条件写明`analysis_method`与`limitations`），迁移会丢弃旧回执并报出条数。这几步都保留原有发现状态。`1.6` 新增 `dismissed_candidates`、模型分片确认及 `cross_scope`。`1.7` 只增字段：`root_causes` 与发现上的 `root_cause_id`、覆盖条目的 `no_check_reason`、单元的 `wave`、队列的 `dispatch_capacity`；迁移不改历史判定，旧发现的 `root_cause_id` 为空，不自动归并，旧覆盖条目不因缺 `no_check_reason` 变成未完成。迁移保留旧事实、未知字段与冻结值，用 `legacy_schema_version` / `legacy_freeze_contract` 标记旧契约；不把历史 fp 补造成反证关联，不把旧冻结宣称为新验证。只有指纹未变的旧合入产物可沿用旧计数口径；新写产物必须满足新契约。真正让检查待复核的是材料变化与知识基线变化——**技能指纹只作记录，不参与判定**。

`1.8` 新增空的 finding_dispositions、attribution_history、attribution_commits 集合；保留事实、复核、旧根因和冻结值，不自动把未归组发现补成单例。新字段缺失的旧发现仍可参与比较。

工具只依赖Python 3标准库。完整查询用法可运行`scripts/knowledge.py --help`；状态工具用`scripts/audit.py --help`。所有路径参数加引号，名称或文档内容不得拼接成Shell代码。

`knowledge.py`提供`overview`、`object ID`、`mode ID`、`risk ID`、`case ID`、`joint`、`profile`、`schema`、`search 文本`和`verify`。全局选项放在子命令前：

```bash
python3 "$AUDIT_SKILL_DIR/scripts/knowledge.py" --workspace "$AUDIT_WORKSPACE" --limit 5 search 记忆
```

对象查询返回职责、命题、技术要求、联合检查及直接案例摘要；案例全文按ID再读。不从风险类别的关系自动推导新的对象关系。`sources/`路径指向框架发布包中的原件，独立包没有这些PDF；需要回查时明确区分已读取与仅引用的来源。

`procedures [对象ID]`查询专项方法索引，`procedure 方法ID`读取一份正文。它们随skill规程维护；`schema`返回的是框架发现契约，本文描述目标知识库的实际扩展字段。

## 编辑目标记录

`init`自动创建材料索引、画像维度和空集合。根据事实补充以下记录，及时保存。

**叙述字段用交付语言写**（默认中文）：`title`、`mechanism`、`impact`、`severity_reason`、`remediation`、`residual_risk`、`observation`、`explanation`、`reason`、`limitations` 这些给人读的字段，和它们汇成的报告保持同一种语言；代码、标识符、路径、配置键、报错与协议原文照原样引用，不翻译。记录是报告的唯一来源，某个单元用另一种语言写，交付物就会半中半英——实测出现过一次，一个扩展目录的执行者跟着所读代码的语言走，那一整片的发现与机理都是英文。

| 集合 | 必要信息 |
|---|---|
| `instances` | `id`、`name`、`framework_object_ids`、`material_ids`、`evidence_ids`；补充`responsibility`。未映射实例使用空对象数组和`mapping_gap` |
| `connections` | `id`、`from_instance`、`to_instance`、`description`、`evidence_ids`；在描述中说明数据、身份、控制和边界 |
| `assets`、`attackers`、`controls`、`hypotheses` | `id`、`description`、`instance_ids`、`evidence_ids`；控制描述含保证与限制，假设注明尚缺什么 |
| `profile` | 保留工具生成的维度，每项填写`value`、`evidence_ids`；未知保持`null`并填写`unknown_reason` |
| `coverage` | `id`、`material_ids`、`check_ids`、`status`、`reason`、`analysis_method`、`limitations`；状态为`not_started/in_progress/reviewed/excluded/needs_review`。`no_check_reason` 写「读过这些材料却不产生任何命题结论」的理由（例如纯二进制资源、只作预期参考的测试源码）；它与 `check_ids` 是这条覆盖的两种去向，不是 `limitations` 的同义改写。**判 `reviewed` 必须二者有一**，「逐行读过」本身不构成覆盖；1.7 之前写的条目按所属单元的 `legacy_schema_version` 保留原契约，不追溯 |
| `method_notes` | 方法、检索范围与证据限制的字符串列表 |
| `materials` | 工具生成的材料索引：目标别名、相对路径、大小、指纹、visibility 与 status。用于核对文件分区，不能证明覆盖语义 |
| `reviews` | 工具生成的发现复核账本；保留处置、理由、反证与被复核内容的指纹 |
| `root_causes` | 同源裁决：id（RC- 开头）、verdict（merge/distinct）、finding_ids、candidates、by、reason、evidence_ids；merge 另有 statement、fix_point（具体失效实现）及每成员一条 member_paths（finding_id/location/difference）。distinct 用 comparisons 逐项说明不同失效点。工具绑定 source_digest；retired 组只作历史。 |
| `finding_dispositions` | 每条发现的归因处置历史，最新条目生效；格式见下。由 rootcause --apply 写入，不来自单元 partial。 |
| `attribution_history`、`attribution_commits` | 工具维护旧根因版本和正式提交来源、内容指纹及回执依据；不手改，不参与事实复核。 |
| `observations`、`dynamic_sessions` | 独立动态工具生成的观测索引和固定会话配置引用；不手工伪造请求结果 |
| `units` | 候选目录分组经模型确认或 plan --apply 提交的划分；object_ids / exposure / depth 由模型决定，附理由；phase 为 2 或 3。`round` 记哪一轮派的，`wave` 记该轮的第几波（正整数或 null，由 `dispatch --wave` 写入）：波次是派单容量的记账单位，不改变单元边界与冻结。被宿主拒掉的派单把单元回滚成 `planned` 并清掉 `wave`，下一波优先派；`dispatch --status` 按轮次与波次对账 |
| `clusters` | 制品单元的相似性建议；`diff_files`逐条处置，`representative_unit_id`由裁决填写。制品边界以模型确认的 `units[kind=artifact]` 为准，能力和联系回查归属实例、材料及证据。旧 `artifacts` 仅作兼容数据，不再作为制品清单或覆盖分母 |
| `dismissed_candidates` | 撤下的候选：稳定 F-token ID、reason、非空 check_ids；检查须 complete / not_established 并带 counterevidence_ids。一候选可多检查，候选 ID 不得同时在 findings |
| `rounds` | 每轮派了哪些单元、各自的 return 行 |
| `chains` | 跨单元攻击链：`entry_exposure`、逐段`steps`（单元、原语、支撑的检查或发现）、终点资产 |
| `primitives` | 单元×攻击原语矩阵，每条带单元、证据与来源；取值见[分析方法](method.md)的能力组合一节 |
| `pending_decisions` | 机械算不出来、必须裁决的条目；未填`resolution`时`plan --freeze`拒绝冻结 |
| `scope_notes` | 残余前沿清单：观察 / 为什么不属于任何已有单元 / 建议下次怎么覆盖 |
| `crossleads`、`stale_notes` | 落在别单元的观察，以及被读到的过期事实 |
| `route_excluded` | 按画像裁剪出本轮计划的对象，连同维度与证据。它不是不适用判定 |
| `queue` | phase1_frozen、phase2_rows_frozen、phase3_rows_frozen、phase3_critic、census；partition_confirmed / partition_reason 记录采纳；cross_scope 按 joint / chain / goal / xartifact 保存 decision: needed|not_needed 及 reason。`dispatch_capacity` 记本次派单容量：`limit`（同时能跑的子代理上限）、`reserve`（留给复核侧再派子代理与单发角色的额度）、`wave_size`（按单元 kind 的分档）、`source` 取 `env` / `host_default` / `user` / `refusal_observed`。`limit` 的解析顺序是**记录里已有的值 → 环境变量 `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS` → 宿主默认 20**；上限属于宿主、会随其版本变化，撞到上限时宿主的拒绝信息里会报出生效值，据此改记 `refusal_observed` 与实际数字。`dispatch` 把解析到的容量写回记录，报告因此能说明本次在哪个上限下跑 |
| `object_scope` | **目标级**对象裁决：框架全集里每个没被任何单元声明的对象，逐个记 `decision`（`involved` / `not_involved`）与必填 `reason`。闸门 G8 核「已声明 ∪ 判过不涉及 = 框架全集」——纳入本来就有记录，而不涉及原先没有落点，于是「没人提」与「判过不涉及」无法区分 |
| `reconciliations` | 显式模型对账记录：failure_mode_id、check_ids、by；status=open 要 reason，status=complete 要 explanation。同一命题、检查集合、by 的最新状态生效，差异本身不构成任务 |
| `corrections` | 复核者当场改产物留下的变更日志：`target`、`field`、`before`、`after`、`reason`、`by`。before/after 保留原 JSON 类型，允许空数组、空对象、空串、0、false、null；缺键才算缺值。其余元数据须为非空文本；改前与改后相同也判错。条目数是变更日志数，不代表独立缺陷数 |
| `report_todos` | 报告呈现要求：`id`、`instruction`、`status`（`open` / `applied` / `dropped`）；`reason` 记录 applied 的呈现位置或 dropped 的未采用理由。`gate --prepare` 允许尚未呈现，最终闸门不放行 |
| `withdrawn_reviews` | 被撤销的复核账本，连 `withdrawn_at` 与 `withdrawn_reason` 一起留着。已登记复核的发现是冻结的，要改先 `review --withdraw` |
| `retired_unit_ids` | 被 `--split` 拆掉的单元编号，只增不减。编号**不回收**：裁决答案按「类型 + 单元编号」认，而父单元一拆就离开清单，「取第一个空闲编号」会把它的号发给另一个目录的子单元，答案于是静默挂错——`freeze` 只核「有答案」，查不出来 |
| `form_gaps` | 模型明确识别的检索形态缺口：id、form、where、reason，以及在明确模式与范围下统计的 files / lines_unmatched。统计不是覆盖结论，可不提交 |
| `target_patterns` | 可选目标模式；defined_at、reaches 或 gates 支持模型解释，call_sites 保存模型确认的位置。callers 为兼容旧自报字段，不由正则覆盖；文本 matches 不等于实际调用 |

`queue.object_scatter` 是当前二阶段单元 `object_ids` 的派生统计，正式保存（包括职责订正、refresh）时重算；决策读取实时统计。它不改写冻结来源，也不自动改变 `joint_objects` 或 `cross_scope` 的模型裁决。

材料ID由工具生成，包含目标别名和相对路径的稳定指纹。不要手改材料指纹以掩盖文件变化；先`refresh`，再复核依赖这些材料的记录。新增输入可在`targets`加入唯一`id`及绝对`path`后刷新。范围排除用绝对路径写入`exclusions`并在方法说明中解释；不要排除整个已声明目标。

## 单元产物与 ID 命名空间

分单元时执行者不写`audit.json`，只写`units/<单元>/partial.json`，由主代理用`audit.py merge --unit`合入。产物只允许这些顶层键：`unit_id`、`instances`、`connections`、`assets`、`attackers`、`controls`、`hypotheses`、`evidence`、`checks`、`findings`、`dismissed_candidates`、`coverage`、`primitives`、`method_notes`、`surface_dispositions`、`progress`、`return_line`、`crossleads`、`stale_notes`、`dimensions`、`schema_version`、`corrections`、`reconciliations`、`report_todos`、`chains`、`scope_notes`。

**多一个键整份产物被拒收。** 产物来自阅读攻击者可控的材料，一个预期之外的字段按缺陷处理，不按可以容忍的数据处理。同样拒收的还有三种：ID 不带本单元 token、非 cross 单元引用了本单元之外的材料、证据指纹与材料现盘不符（那说明结论建在已经变过的材料上）。cross 可引用本次工作区内实际读过的跨单元材料；仍须遵守派单主题、材料 ID、指纹和证据位置约束，不能由 `0/0` 推断无需取证。

ID 一律是`<前缀>-<单元token>-<序号>`，单元`U-SH03`的 token 是`SH03`：`INST-SH03-001`、`CONN-SH03-01`、`E-SH03-001`、`CHK-SH03-0001`、`F-SH03-01`、`COV-SH03-01`、`AST-SH03-01`、`CTL-SH03-01`、`ATK-SH03-01`、`HYP-SH03-01`、`PRIM-SH03-01`。这是两个单元同时在跑时不撞号的唯一办法，也让每条记录的归属可以机械反查。

合入是幂等的：记录按 ID 与内容指纹匹配，重复合入同一份产物不产生重复记录，中断的一轮可以直接重放。同一 ID 两次内容不同则判冲突并拒收，不做静默覆盖；该单元要重合入，先 `review --prepare --replace --unit`，再 `merge --replace --unit`。两者试算同一替换路径，拒绝时不撤回旧记录。已登记复核的发现及其支撑检查、证据不变时保留复核；要改变它们，先 `review --withdraw`。产物中的候选状态仍写 `needs_review`，不能为了试算通过复制共享记录的 `current`。

证据记录示例（替换为真实材料ID、指纹、位置与观察）：

```json
{
  "id": "E-<token>-001",
  "material_id": "材料索引中的ID",
  "sha256": "该材料当前的完整sha256",
  "kind": "code",
  "locator": {"lines": [12, 19]},
  "observation": "具体代码行为及其对安全要求的含义",
  "status": "current"
}
```

`kind`取`design/code/configuration/observed_records`。位置可以是`lines`（闭区间）、`section`、`page`或`json_pointer`。来源文章和通用案例不能伪装成目标实现证据。`needs_review`证据保留旧指纹，复核原件后才更新为`current`。

非UTF-8文本证据另写`encoding`；恢复视图另写`view: recovered`，行号只对应明确选定视图。PDF等材料用页码、章节，提取文本的行号不能冒充原PDF行号。直接动态观测使用`kind: runtime`、`observation_id`和JSON Pointer，详见[动态验证](dynamic.md)。

从 `materials` 确认实际路径后，用原生只读工具读取模型选定的区间；需要转换时记录视图、编码与局限。`coverage` 始终填写 `analysis_method` 和 `limitations`，说明实际看到、分析了什么。截断部分单独补读，或保留未完成范围；命令成功与行号合法不能证明引用支持断言。读取方法见 [材料指南](materials.md)。

产物中的 `chains` 与 `scope_notes` 按稳定 ID 合入，脚本补本单元 `unit_id`。重复合入相同内容不重复登记，不覆盖其他单元；替换时链由新产物重建，残余观察保留，明确提交的同 ID 残余订正可更新。

## 检查及判定

完成实例登记后执行`seed`，为每个实例的框架对象生成候选检查。重复运行不重复添加。直接在生成的记录中填写以下内容：

- FM 的 `statement` 确定检查问题；知识库中的前提、判据、取证要求和步骤仅供参考。模型决定命题在目标中怎么查，在 `explanation` 记录实际核查范围与结论依据。
- `prerequisites`和`criteria`是可选分析笔记，可省略或为空，也可由模型按目标增删改写；每行分别使用`condition`或`criterion`，`state`取`unknown/met/not_met`，已判定事实关联`evidence_ids`。脚本不比较知识库条件文本，也不从条件行推导命题结论。
- `applicability`取`unknown/applicable/not_applicable`，由模型结合目标职责与机制判断；控制有效不能据此判为不适用。
- `status`取`not_started/in_progress/complete/needs_review`。未完成检查的`verdict`为`null`；待复核可保留历史结论但不能当本轮有效结论。
- 检查的`scope`是证据类型数组，只取`design/code/configuration/observed_records/runtime`，例如`["code", "configuration"]`。文件、入口、身份、假设和版本限制写在`explanation`；`evidence_ids`与`counterevidence_ids`分别引用支持与反证；`missing_evidence`列具体缺口。它与控制条目用于文字说明保证范围的`scope`不同。除证据不足结论外，所声明的类型均须有同类型目标证据支持。

| `verdict` | 判定要求 |
|---|---|
| `confirmed` | 模型确认命题适用，目标证据支持所述失效机制与可达性；结论限定在证据范围 |
| `not_established` | 模型确认命题适用，目标反证否定所述失效机制；记录`counterevidence_ids`，不是整体安全证明 |
| `insufficient_evidence` | 已开展核查，但适用性、机制、可达性或效果仍缺必要材料；明确所缺内容 |
| `not_applicable` | 目标证据支持该命题在所述范围不适用；不能由控制有效推导 |

框架外机制、跨对象联合检查使用本地定义。创建与生成检查相同的结构：独立`id`，`failure_mode_id: null`，`baseline_id`仍记录本次参照版本，`local_definition`包含`statement`与`requirement`；可补参考条件或`reference`说明联合检查名称、目标安全要求。框架命题只是检查方法或参考条件不合目标时，继续使用原 FM 引用，不必改成本地检查。

脚本核对范围内实例与 FM 的检查任务是否齐全、显式状态是否完成，以及引用、证据指纹和结论字段是否完整；不能据此证明模型真的审过或推理正确。历史条件笔记继续保留；旧记录中`criteria[*].state == not_met`所引的反证仍可读取，新记录优先使用顶层`counterevidence_ids`。

本地命题只描述当前目标；没有框架映射不降低有充分证据发现的可信度。框架命题与目标事实矛盾时，保留适用性理由或本地命题，不修改随包原定义。

## 发现与报告

`findings`每项包含`id`、`check_ids`、`title`、`mechanism`、`evidence_ids`、`impact`、`severity`、`severity_reason`、`remediation`、`responsibility`、`validation`、`residual_risk`、`status`，可选`root_cause_id`指向`root_causes`中的一条；为空表示尚未归并，不表示独有根因。

### 入口类型字段

`exposure` 与 `entry_exposure` 共用[攻击入口类型](method.md#attack-entry-types)的定义，各自的判定对象不同：

- `units[].exposure` 是调度阶段对单元入口的分类，环境边界与位置依据写入 `exposure_reason`。初始 `unknown` 是待判定状态，需经现有 `decide` 流程裁决，不能作为已完成分类。
- `findings[].exposure` 描述本条发现实际分析的入口，起点环境、控制条件和路径依据写入机理；同一发现的不同入口分别说明，不从单元标签推导。
- `chains[].entry_exposure` 描述整条链的原始入口，各步保持实际环境与前提；不继承首个或末个组件的单元标签。不同入口需要独立走查时分别登记链。

起点环境未确定时保留待判定状态，并在机理、链描述或残余风险中说明缺口。入口已确定但后续链路缺证时保留该类型，在验证与复核中表达缺证；不靠改标签代替证据判断。

`severity`取`critical/high/medium/low/informational`，按实际影响和前提解释；`status`取`current/needs_review/withdrawn`。候选从`needs_review`开始。当前发现由已完成且`confirmed`的检查和有效复核支持，可引用本地检查。数据流问题说明链路，设计问题说明违反的假设与要求。`validation`区分静态走查、真实观测和仍缺的验证。

回源复核后，准备如下JSON文件。分单元产物先用 `merge --unit` 合入共享记录，再登记该发现的复核；合入只导入记录，不替代语义复核：

```json
{
  "reviewer": "本次执行者；同一模型回源复核",
  "decision": "retain",
  "rationale": "说明引用材料为何支持本次保留、撤销或证据不足的判断",
  "counterevidence_analysis": "说明重新核对了哪些上游控制、默认值与旁路，以及它们是否推翻候选",
  "evidence_ids": ["E-001"],
  "counterevidence_ids": []
}
```

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" review --workspace "$AUDIT_WORKSPACE" --finding F-实际编号 --review-file /path/to/review.json
```

`decision`取`retain/reject/needs_evidence`，分别产生`current/withdrawn/needs_review`状态。工具生成时间和复核指纹；不能手改指纹让过期复核通过。发现、检查或相关证据改变后需重新复核。撤销项保留历史；变化会使依赖归因和报告过期，不能只更新指纹。

## 控制有效性

`controls`可加`effectiveness`，取`unassessed/effective/limited/ineffective/unknown/needs_review`。缺省为未评估。

**方向只有一个**：`effective`与`limited`的依据只能是`not_established`检查里否定目标失效机制的反证；`confirmed`检查说明该失效成立，只能支撑`ineffective`。机制存在而无此类反证时写`unassessed`——框架允许未评估，不允许无反证的「有效」。

**`scope`在这里是散文**，写这个保证适用的入口、主体、配置、版本与证据范围；它与检查的`scope`（证据类型数组）同名不同义，`validate`会拒绝把证据类型数组写进控制的`scope`。

已作有效、部分有效或失效判断时同时填写：

- `check_ids`：支持本判断的检查。
- `evidence_ids`：支持控制结论的目标证据。
- `scope`：保证适用的入口、主体、配置、版本及证据范围。
- `limitations`：未覆盖情形；没有额外局限时也明确写已核对的范围限制。
- `rationale`：控制与目标失效机制的关系。
- `retest`：可复用的复测步骤或需要取得的证据。

`effective/limited`必须关联`not_established`检查中否定目标失效机制的反证；`effective`不能混入失败或未知检查。`ineffective`需要成立检查。材料变化会沿检查关联使控制评估待复核，不能把旧控制结论继续显示为有效。

## 输出

`report` 导出分类材料与 JSON 索引，人工成文按[两段式报告](report-format.md)执行，`report --check` 核对实际交付。`snapshot` 将完整工作区保存到快照 workspace/，包括未合入产物、复核、归因运行目录、基线与观测，排除根 snapshots/。格式 2 保留全部相对路径、空目录和哈希；旧快照中的历史 SARIF 按原清单读取，不生成或刷新该文件。

发现事实与状态只在 audit.json 维护；模型按模板撰写解释，索引核对来源与完整性。重新导出不覆盖作者稿。校验通过只说明结构和引用一致，语义仍需回源复核。报告显示未完成覆盖与证据缺口；零发现、零检查和全部通过不是同一件事。

## 复审与版本变化

1. 续审先运行`refresh`。工具比较文件内容，保留变化前快照；变更关联到证据、实例及连接组件时，相关检查和发现标为待复核。新增文件或归属未知时保守扩大复核范围。
2. 同一内容但行号变化不可能指纹相同；重新定位后核对语义，不能只搬行号。已移除材料保留索引状态供历史引用。
3. 已安装知识包变化时，刷新记录`pending_framework`，原基线继续可查询。开始按新版本复审时运行`refresh --adopt-framework`，再`seed --rebase`。工具保留旧快照，重置仍存在的命题；被移除命题保留旧基线且待复核，人工判断不适用、重新映射或本地定义，不能静默删除发现。
4. 工具不会更新安装的skill或知识包。技能指纹只标识执行版本，不触发复核；知识维护与安装新版由审计之外的流程完成。
5. 完成材料导出和人工撰写后运行 `report --check`、最终 `gate`、`validate`，再 `snapshot`。保存前让所有写入者落盘并暂停写入；符号链接、复制失败或复制期间内容变化会使本次快照失败，未完成目录不会作为完整快照发布。历史目录不覆盖，清单核验新增、缺失与内容变化。未完成审计也可保存，报告保留未完成状态。恢复时先校验快照，将格式 2 的 `workspace/` 复制到空工作区，再校验并核对目标 revision；旧格式只含共享记录与报告，恢复未合入工作仍需原单元目录。

快照记录审计当时的输入位置和指纹；目标材料若已移动或不可读，当前验证会失败，不能把旧路径缺失解释为安全。迁移目标位置后显式更新`targets`并重新核对材料。

## 发现粒度与归因

finding 记录具体观察，current 只表示事实复核保留，不代表全局独立。一个缺陷可以关联多项 check；多个独立控制缺陷应分别记录。mechanism 依次说明已有能力、必要配置或交互、输入到失效点的路径与越界；impact 说明由此新增的能力或损失。

可增量填写以下事实字段；它们进入事实复核指纹。缺字段的旧记录不自动失效，也不自动属于 chain/summary。

- failure_points：对象数组，每项含 evidence_ids、expected_control、observed_failure，可加 symbol。引用实际证据，缺失控制不能编造不存在代码的行号。
- related_findings：对象数组，每项含 finding_id、relation、reason、evidence_ids。relation 为 possible_same_defect/supplements/overlaps，均只是线索；目标须已存在，不确定时写 crosslead。

正式处置的最小输入为 finding_id、kind、by、reason；rootcause --apply 在当前 base_sha256 匹配后生成历史 ID、时间和 source_digest。不能通过单元 partial 写入处置。

| kind | 必需关联 | 计数与失效 |
|---|---|---|
| defect | comparison | 有效同源组计一次；未归组者还须 standalone 比较；标签本身不证明独立 |
| supplement | target_finding_id | 直接指向有效 defect，随其呈现；目标失效或变成 supplement 时待处理，不自动沿指针传递 |
| chain | finding_ids、chain_ids | 仅组合已有缺陷/能力；放入链叙述，不另计 |
| summary | finding_ids、todo_ids | 仅归纳已有发现；放入总览，不另计；呈现待办此时可 open |
| superseded | finding_ids | 只用于正式 withdrawn 的历史替代映射；替代目标失效需核查，不自动恢复原发现 |
| pending | reason 中的具体缺口及下一步 | 不计为已确认独立项，仍保留在 current 发现清单和阶段报告 |

comparison 包含 by、scope、reason、conclusion，以及实际比较的 finding_ids/evidence_ids/material_ids（至少一类非空）。conclusion 为 standalone/grouped；distinct 裁决中的 comparisons 使用 distinct。单例须核查有关组件、共享实现、副本、候选和显式关联；无候选不等于无需比较。distinct 的 comparisons 应覆盖全部裁决成员，写清具体差异，不能用同一句抽象契约替代比较。

归因依赖发现事实、检查、证据、材料与有效复核，纯 root_cause_id 更新不撤销事实复核。新增或恢复 current、输入变更、组成员改变会形成具体待处理项；查询只派生有效状态，不写盘。needs_evidence 是合法事实结论，不因没有归因就变成无人处理。所有 current 发现均须有有效处置或 pending；宣称归因完成时 pending 为零。

修改旧根因使用同一 ID；拆分或替代时在提交中列 retire_root_cause_ids，再提交新组及有关成员处置。历史根因、处置、发现与证据保留。旧裁决没有当前来源绑定时是待核线索，不自动变成已去重事实；按证据选择快速核对、补充比较或重新取证。

## 归因任务及提交

路径均相对审计工作区；run 位于 units/_reviews/rootcause/<run-id>/。source.json 是固定审计记录副本，manifest.json 是任务执行状态。每个 tasks/<task-id>/input.json 保存有关原始记录和候选；brief-<attempt>.md 是启动说明，result-<attempt>.json 是唯一临时结果文件。记录副本不冻结目标源码，回源时仍须核对材料指纹。

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" rootcause --workspace "$WS" --prepare
# --input 可给显式任务打包计划；--packet-bytes 控制默认打包目标，不截断记录
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" rootcause --workspace "$WS" --dispatch --run "$RUN" --task "$TASK" --capacity-file /path/to/capacity.json
# 主代理将返回的 prompt 交宿主子代理工具，启动 rootcause_reviewer
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" rootcause --workspace "$WS" --collect --run "$RUN" --returns-file /path/to/returns.json
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" rootcause --workspace "$WS" --status --run "$RUN"
```

capacity-file 为 `{"limit":实际宿主上限,"active_agent_ids":[实际在跑的代理ID]}`。列表包括其他角色；工具同时核对所有归因运行的活动尝试和预留名额，不重复计算同一代理。没有容量文件时不猜测宿主占用。所有主代理写操作串行，同一任务同时只有一个活动尝试。单执行者时顺序完成相同任务与结果契约。

returns-file 为 events 数组。每项给 task_id、attempt、event：started 还需 agent_id；completed 给指定 result_path；rejected/failed 给 reason，已 running 的失败还须 stopped=true，确认原执行者停止。dispatch 只记 dispatched，started 才记 running。重复事件不产生新尝试；未知启动状态先对账，不因没有结果文件自动重派。

临时结果必须覆盖输入 finding_ids，字段如下；列表无条目时用空数组。

```json
{
  "run_id": "实际运行ID", "task_id": "实际任务ID", "attempt": 1,
  "input_digest": "派单提供的完整指纹", "reviewer": "归因执行者",
  "assessments": [
    {"finding_id": "实际发现ID", "proposed_kind": "pending", "reason": "待核对的具体问题"}
  ],
  "group_proposals": [], "comparisons": [], "cross_file_leads": [],
  "fact_corrections": [], "open_items": [], "read_dependencies": [], "resolutions": []
}
```

group_proposals 每项给 finding_ids、reason 和具体失效证据及成员差异；它们使用任务内编号，不分配正式根因身份。comparisons 每项给 finding_ids、conclusion（same/distinct/grouped/standalone/unresolved）、reason 及 evidence_ids。cross_file_leads、fact_corrections、open_items 每项给 finding_ids、reason、证据引用及明确下一步。补读依据登记 read_dependencies：category、id、sha256；sha256 是 `attribution.fingerprint(attribution.dependency_value(state, ref))`，来源类别为 findings/checks/evidence/materials/reviews/chains/report_todos/root_causes/controls/instances。

collect 只校验、接收和汇总，不裁决语义。reconciliation/worklist.json 列出跨文件候选、重叠组、相反性质、merge/distinct 冲突及缺口，并为核对项生成 C- 开头的任务。按同一 dispatch/collect 协议完成；核对任务读取 input.issue、proposal_refs 及有关证据，仍逐条填写 assessments。文件组成员相同可复用输入，重叠不自动取并集。原始结果留在各自文件；后到结果不覆盖前一份判断。

全部任务完成后，由主代理派 rootcause_reviewer 读取 manifest、worklist 和必要结果，形成 adjudication.json。该文件含 base_sha256（rootcause 查询当前值）、by、run_id、run_digest（worklist JSON 的 attribution.fingerprint）、root_causes、finding_dispositions、resolutions，可有 retire_root_cause_ids。每条 resolution 给 issue_id、resolution（resolved/pending）及 reason；未完成事实订正的成员处置保持 pending。最终文件必须处置本轮全部 current 发现。

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" rootcause --workspace "$WS"
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" rootcause --workspace "$WS" --apply /path/to/adjudication.json
```

主代理为唯一正式写入者。apply 全批试算处置、引用、来源和唯一归属后一次保存 audit.json；成功提交由 attribution_commits 绑定内容，可恢复缺失回执。同一有效内容重复应用幂等，旧结果不能覆盖后续事实。小目标可直接提交同样的正式处置，不要求为了文件管理增加审计单元。仅有旧式 root_causes 的提交可留作历史线索，不满足新归因完成要求。

输入或复核变化后创建新 run，保留旧输入和结果；无变化结果可以按原输入和依赖指纹核对复用，不能只修改 digest。新 current 发现须进入增量比较，原范围未完成时如实保留 pending。临时结果永不直接进入漏洞视图；只有正式处置及有效同源/单例比较参与计数。

归因输入包只带按完整 finding ID 路由的 report_todos；未定向待办保留在 source.json，manifest.global_report_todo_ids 指向这些条目，收口角色统一核查。跨文件核对新发现的线索继续进入最终 worklist，由收口者裁决或保留 pending；不递归自动派出无限核对任务。

单元替换保留已经复核或归因的原 finding ID 及其支撑检查、证据；需要拆分时保留旧条目，经正式 reject 退出 current，再提交 superseded 映射。不能先从 partial 删除旧条目再补历史链接。合入工具从正式 root_causes 恢复归因回链，单元作者不负责分配根因编号。

rootcause 查询中的 candidate_coverage 仅说明候选应答情况，不能代替完整收口；有效计数和待处理项以 attribution.statistics/pending 为准。
