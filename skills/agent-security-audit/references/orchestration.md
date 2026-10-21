# 调度规程

本文件只给主代理读。worker、reviewer、merger、queue_critic、report_writer 读 `references/roles/` 下属于自己的那一份（reviewer 还会按需派 verify 子代理，契约同在该目录），不读本文件也不读 SKILL.md：编排协议对它们没有指导作用，只会让它们为不属于自己的机制分心。

单目标、小制品可以按 SKILL.md 顺序执行。是否分单元由模型根据职责、依赖与证据边界决定；字节、命中数和目录形状只供参考。

## 1 先确认划分，再并行

每个在范围内的材料恰属一个非 cross 单元。脚本校验无遗漏、无重复归属，不能根据词频或大小推断语义边界。

| kind | 用于 | 边界 |
|---|---|---|
| `repo_shard` | 仓库的一组职责 | 模型明确列出的材料 |
| `artifact` | MCP 服务端、Skill 包或插件 | 制品及其声明、实现 |
| `residual` | 其余范围内材料 | 明确归属，不能遗失 |
| `cross` | 三阶段跨单元分析 | 不拥有材料，以 `seed` 指定模型选择的任务 |

单元规模没有按命中数、字节或数量设定的硬阈值。模型依据调用关系、职责完整性和可处理上下文确定边界。分批落盘用于控制窗口；不要用检索噪音决定工作量。

## 2 `plan`：候选 → 模型决定 → 结构校验与冻结

脚本可以枚举、定位、哈希、比对显式字段和校验约束。相关性、实际调用、代表性、适用性、scope、证据充分性、反证关系、结论与定级都由模型判断。确定性算法产生同一输出，不等于该输出是语义事实。

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" plan --workspace "$WS"
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" decide --workspace "$WS"   --decision partition:queue --resolution accept --reason "已核对职责与调用关系，采用该划分"
# 需要调整时，由模型编写 plan.json 后应用：
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" plan --workspace "$WS" --apply /path/to/plan.json
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" plan --workspace "$WS" --freeze --phase 1
```

`plan` 输出 `base_plan_sha256` 和 `draft`，目录分组仅为候选。`plan --apply` 输入：

```json
{"base_plan_sha256":"<当前 plan 摘要>","reason":"职责边界与证据依据",
 "units":[{"id":"U-SH01","kind":"repo_shard","title":"明确职责",
           "material_ids":["<材料 ID>"]}]}
```

可带 `object_ids`、`mapping_note` / `mapping_reason`、`exposure` / `exposure_reason`、`depth` / `depth_reason`。脚本在写盘前核对全部引用和分区，摘要过期则拒绝；同一输入重放不产生新变化。边界未改的 ID、裁决与已有成果保持；边界改变要用新 ID，旧 ID 退休，不能把旧裁决自动继承给新边界。已有成果的单元不能被静默重写或删除。

`--pack` 已退役，只提示改用 `--apply`，不产生改动。显式 `--split U-SH01 --by file` 表示每文件一片；`--by directory` 按下一层目录分组，找不到边界便拒绝，不自动换规则。拆分不继承父单元的对象、暴露与深度判断。`--rebuild` 明确重建未开工的草案；不能清除已有成果。

`--group-depth`（默认 1）、`--artifact-depth`（默认 2）只控制候选分组。制品根标记也是候选信号，模型要核实其真实职责。

模型裁决通过 `decide --decision <kind>:<subject> --resolution … --reason …` 写入，原因不能空。也可用当前 `DEC-…` 编号，避免手改共享记录。

| kind | 要决定什么 |
|---|---|
| `partition` | `queue` 的候选边界是否可用；接受答 `accept`，否则提交 `--apply` |
| `out_of_scope_candidate` | 目录是否参与运行时加载；答 `in_scope` / `out_of_scope`，排除后 `refresh` |
| `object_mapping` | 单元承担哪些对象；答对象 ID 列表，或 `none` 并给 `mapping_note` |
| `exposure` | `EXT` / `ADJ` / `INT`；按入口和前提说明，脚本不从名称推断 |
| `depth` | `triage` / `standard` / `deep`；给依据 |
| `cluster_representative` | 代表是否足够；读差异后由模型选择成员 |
| `unassigned_material` | 用 `plan --apply` 补足归属，或有依据地排除 |
| `object_scope` | 未被声明的框架对象是否涉及；不涉及须记录依据，涉及须有承担单元 |
| `cross_cutting_objects` | 多单元声明的对象是否需 joint 整体核查；分布不能证明覆盖不全 |
| `cross_scope` | 三阶段每类明确答 `needed` / `not_needed` 和理由 |

一阶段冻结要求分区、对象映射和显式裁决完成，不要求运行检索、召回或逐命中处置。`surface` 重建不应改变已确认的职责边界。

## 3 聚类只给相似性建议

有明确的重复制品问题时再运行 `cluster --threshold 0.8`。指纹、minhash 和 diff 清单是定位信息，不能自动证明同义或代表性。模型决定代表、审计深度，以及哪些相同部分可复用；复用结论须有适用依据，差异部分仍需分析。`triage` / `standard` / `deep` 不按关键词数自动升降档。

## 4 可选检索：先有问题，再选范围和模式

只有需要定位某种形态时才运行 `surface --unit U-SH01`；省略 `--unit` 表示明确选择全工作区扫描。`surface/<单元>.json` 保留已扫描命中、候选聚合、截断和不可读项，`surface/_summary.md` 是摘要。`spots` 按文件和模式族聚合用于展示，不能证明同一问题；不同对象标签允许在同一位置同时出现。命中或零命中都不能证明覆盖，`blind_languages` 只表示某语言零匹配。

原始命中不要求处置，不进入 G3 或冻结条件。可选 `surface_dispositions` 只是模型注释；若提交，ID、枚举和引用仍须正确。模型采纳为实例、检查、发现或交接后，按正式记录规则闭合，不因来源是检索而豁免。

有明确的目标封装问题时再派 `recall`（契约 `roles/recall.md`），也可以完全不召回。空 `patterns` 合法。`recall --brief` 提供架构、实例及可选检索位置，不能把起点摘要当全部依据。

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" recall --workspace "$WS" --brief
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" recall --workspace "$WS" --matches authorize --unit U-SH01 --call-form 'authorize\s*\('
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" recall --workspace "$WS" --apply /path/to/patterns.json
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" recall --workspace "$WS" --status
```

`--matches` 仅返回文本匹配行及位置，包含定义、注释、字符串、测试与文档。模型确认的真实调用另记 `call_sites`；注册不覆盖模型提供的 `callers`，不因少于 2 或裸词模式拒收。`--apply` 按模式 ID 合并，`--replace-all` 显式整套替换。留存模式的 revision 漂移由 `--status` 提示；模型决定重核、停用或带限制使用，不作为冻结硬门槛。比不了不表示没变。

## 5 主循环

```
一阶段   init / refresh → plan → 模型确认 / --apply → freeze（surface / recall 按需）
二阶段   一轮对应一个类型段（repo_shard/artifact、residual；三阶段为 joint / chain / goal / xartifact）。
         按环境并发容量派单；已交付单元即可进入复核，其他单元继续执行。
  1  audit.py dispatch --unit … --round N 生成 brief，spawn worker（契约 roles/worker.md，给绝对路径）
  2  收 return 行，确认该 worker 已停止写入；不读候选正文
  3  audit.py review --prepare --unit …；机械项不过就交回修正，再交付
  4  为已交付且预检通过的单元启动或复用 reviewer（契约 roles/reviewer.md）
     给本批单元清单、已有判定摘要和未完成范围，主代理只读更新后的判定摘要
     其他 worker 可并行处理不同单元；同一产物一次只允许一个角色写入
     按判定处理：
       订正 -> reviewer 修改产物并留 corrections；已登记复核的发现先 review --withdraw，再修改
       交接 -> 写 crossleads，交给对应单元处理
       残余 -> 写 scope_notes，不新增单元
       过期 -> 写 stale_notes；对象映射等当前事实由主代理核对后用 decide 订正，技能问题留待审计外修复
     将已确认且适用于其他单元的执行修正及时传给仍在工作的 worker
     report_todos 保持 open，由 report_writer 实际呈现后闭合
  5  重复接收与复核，直到本段所有单元交付；同一段级 reviewer 核跨单元一致性并完成最终复核账本
  6  spawn merger（契约 roles/merger.md）→ 主代理读轮次摘要
  7  audit.py merge --unit … 逐单元合入；已有旧合入产物用 --replace，先处理需要撤回的旧复核
  8  audit.py review --finding <发现号> --review-file <该发现的账本> 逐条登记
     发现必须已存在于共享记录；账本绑定本次实际合入的发现、检查与证据。合入不等于已复核
  9  写入者落盘并暂停后 snapshot；保存已交付、已核与未完成清单，再释放上下文
闸门     gate（阶段适用的 G1、G2 与正式任务状态必过；G3 为参考信息）
三阶段   模型决定 cross_scope → queue_critic 质问 → freeze --phase 3 → 执行 needed 类型
收口     gate --prepare → report_writer 写终报并闭合 report_todos → gate（不带 --prepare）
         → 一名复核终报 → validate / report / sarif / snapshot
```

**目标专属模式留在工作区，不写技能。** 它是这次审计的记录（`target_patterns.json`），
不是技能的一部分：写进技能会让下一个目标继承上一个目标的猜测。终报交付之后，可以人工
挑选其中依据链扎实的若干条，提炼进技能的目标知识库 `knowledge/targets/<目标>_pattern.json`，
那份文件只在审计同名目标时加载——同一目标的二次审计因此能从积累的模式起步。这个动作
属于「技能可改的第二个时点」，不在审计过程中做。

**开始目标审计之后，这个技能就是只读的。** 这条现在**没有机械级联兜着**，是纪律：
技能指纹只作为记录（哪个版本产出了这份记录），不再触发复核——它逐文件哈希整个技能目录，
改一行散文就把全部已完成检查打回待复核，而真正保证结论还成立的是钉住的框架基线。
所以中途改技能不会有任何东西告警，后果是**同一轮里前后几个单元按不同规程产出**，
而记录上看不出来。技能的改动只在两个时点做：**开审之前**，以及**终报交付之后**
（`stale_notes` 里攒下的过期项正是在这时应用）。审计过程中发现技能有问题，写进
`stale_notes`，不要当场改。

主代理硬纪律，违反即上下文失控：**不读任何候选正文**（只读脚本输出、worker 的 return 行、reviewer 的判定摘要、merger 的摘要）；**不亲自建索引**；**不亲自写终报**；**每轮末 snapshot**，写完即可安全丢弃上下文。

每轮收口后继续执行剩余单元与跨域核查，直到完成终报交付。遇到执行失败或记录错误时，定位并修正原因，再继续对应步骤；保留未完成状态并推进不受影响的工作。

## 6 项集合冻结

二阶段、三阶段单元集合分别由 `plan --freeze --phase 2` 与 `plan --freeze --phase 3` 固定，冻结后保持集合与材料归属不变。对象职责的事实订正通过 `decide object_mapping:<单元>` 或 `decide object_scope:<对象>` 留理由更新；不改冻结基线，也不新增单元。新增职责由原单元补实例、检查与回源记录，移除职责须核对全段是否仍有其他承担单元。

**在这之前还有一次冻结**：`plan --freeze --phase 1` 收口模型确认的单元划分与对象裁决，记进 `queue.phase1_frozen`。历史 `spots` 字段只留作统计，不是冻结依据。一阶段没冻结，二阶段不许冻结。

三个冻结值分别记在 `queue.phase1_frozen`、`queue.phase2_rows_frozen`、`queue.phase3_rows_frozen`。G6 核对单元数量与阶段队列；`phase1_frozen.object_scope` 是冻结时的历史统计，当前对象裁决由 G8 与记录校验核对覆盖和理由，不要求条数不变。

「本该开新项」的东西有四个去向，不存在无去向的观察：

| 情形 | 去向 |
|---|---|
| 扩展出的本仓自有封装，命中落在**本单元** | 本单元当场审。这本来就是它的活 |
| 命中落在**别的单元**，那个单元还没跑 | 写 crosslead，定向到该单元 |
| 命中落在**已跑完**的单元 | 由该单元的复核者当场订正（留 `corrections` 条目），不新增行 |
| 落不进任何已有单元 | 进 `scope_notes` 残余前沿清单，逐条给：观察 / 为什么不属于任何已有单元 / 建议下次怎么覆盖 |

「禁止推卸到下轮」与本条并存不冲突：那条禁的是 worker 把**自己单元内**的活留给下轮，本条约束的是**单元的边界**不扩张。项内做完，项外记账。

## 7 三阶段：跨域主题

`cross` 仅注册模型明确选定的三阶段单元。二阶段冻结后，分别回答 `cross_scope:joint|chain|goal|xartifact`：`needed` 必须有对应单元，`not_needed` 必须有理由且不创建该类单元。四类均无需执行时，允许三阶段零单元冻结；仍须记录 `phase3_critic` 的核查结果。类型表帮助思考，不强迫凑任务：

| cross_type | 种子来源 | 要回答什么 |
|---|---|---|
| `joint` | 框架的 `cross_object_controls`（3 项：执行隔离与控制不可自改、累计预算事务与故障隔离、停止撤销与状态恢复），加上 `queue.joint_objects` 点名的横切对象及其命题 | 没有一片持有整体的那些性质：出口是否收敛、批准与最终动作是否绑定、身份代表链末端的有效主体是谁、加载时的来源校验链是否完整 |
| `chain` | 二阶段已冻结的 `confirmed` 加单元×原语矩阵 | 从某个 EXT 入口能否一路打到皇冠资产 |
| `goal` | 皇冠资产 × 攻击者，业务不变量取反 | 「读到 / 改写 / 绕过资产 X」能否达成 |
| `xartifact` | 当前 `kind=artifact` 单元、归属实例与材料、`clusters` | 工具名影子化、聚合致命三要素、共享凭据作用域并集、同簇批量缺陷、共享依赖、审批可满足性、制品间工具链路、同一制品被多个 Agent 复用 |

```bash
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" cross --workspace "$WS" --cross-type chain \
  --title "外部内容→工具调用→凭据外发" --seed-file /path/to/seed.json
```

`chain` 单元的 `seed.check_ids` **必须逐个指向 `verdict == confirmed` 的检查**，`freeze --phase 3` 会逐条核；种子取**已冻结的 confirmed 清单**，不靠逐轮摘要累加：摘要是给人看的轮次概览，高产轮次装不下全部 confirmed，被略去的那些既不会进 chain，也不会被 queue_critic 看见，而冻结之后没有第二次机会。

冻结三阶段之前必须派 `queue_critic`（契约见 `roles/queue_critic.md`）。主代理模型核对建议的证据与必要性，明确采纳后更新 `cross_scope` 并登记单元；这是冻结前最后一次补项。`queue.phase3_critic` 记录核查结果与采纳理由，可以补入零项，不能留空或省略核查。

## 8 闸门

```bash
# 写终报前：只延后 report_todos，其他检查照常
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" gate --workspace "$WS" --prepare
# 报告呈现与待办处理完成后：全部交付检查
python3 "$AUDIT_SKILL_DIR/scripts/audit.py" gate --workspace "$WS"
```

退出码分两个方向：**0 全过；1 读得了但内容没收口（去修记录）；2 读不到或读不懂（去修路径或格式）**。**原样跑，不要接管道**——接了管道退出码是末端命令的，闸门会无声放行。

八条：G1 分区；G2 文件与六维度的声明完成；G3 原始索引参考行（skip）；G4 EXT 单元与检查归属；G5 跨边界连接归属；G6 冻结与 cross_scope 一致；G7 正式检查、发现和显式对账任务闭合；G8 覆盖记录与材料分母一致。一阶段不要求索引；二阶段核对 G1、G2 与交接归属。`gate --prepare` 仅将尚未呈现的报告待办留给 report_writer，输出 `purpose: report_preparation` 和 `pending_report_todos`；报告完成后不带该选项运行最终 gate，全部适用项必须通过。

两条容易读错的：**G4 读的是单元的 `exposure`**（实例上没人填——契约要求填在发现上，单元的由裁决环节填；若按实例判，闸门会永远输出「EXT 实例 0 个」而通过）。**G7 接受带 `needs_evidence` 复核的 `needs_review` 发现**：那是正当判定，它的闭合形式就是「记录了缺什么」；只有毫无复核记录的发现才算悬空。G7 同时核订正条目是否带改前／改后／理由，以及 `report_todos` 是否全部闭合。

`validate` 核对记录内部一致；`gate` 核对声明的任务、范围和状态是否闭合。二者都不证明真实覆盖或语义正确。**脚本能核的只有「做没做、数对不对」，核不了「想得够不够」**；后者靠 queue_critic 的质问与 reviewer 的抽查，两件事不互相冒充。

六个分析维度在记录里的字段名：`bidirectional`（双向追踪）、`control_efficacy`（防护有效性）、`trust_model`（信任模型与平台承诺）、`lateral`（同类操作横向核查）、`capability_combo`（能力组合）、`asset_goal`（资产目标反查）。每个单元每个维度取 `pending` / `done` / `na`，判 `na` 要写理由。

## 9 并行能力不可用时

降级为单执行者按同一份单元清单顺序跑完：`plan` → 模型确认 / `--apply` → `freeze --phase 1` → `freeze --phase 2` → 逐单元 `dispatch` 并按 brief 审 → 预检与回源复核 → `merge` → 登记复核账本。继续完成需要的跨域核查，再按准备闸门、报告待办、最终闸门与快照的顺序交付。顺序执行保留相同记录与复核要求。
