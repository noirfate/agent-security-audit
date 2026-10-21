# AI Agent 安全审计图谱

把 AI Agent 系统拆成可逐项核查的架构对象，再把各家风险目录（OWASP、MITRE ATLAS）、防御条款（CIS、SAFE-AI）与公开案例挂到这些对象上，用于对具体 Agent 系统做安全审计。

版本 v1。

数据契约为3.0：命题中的旧`conditions`与重复的`applicability`已替换为`applicability_conditions`和`failure_criteria`。画像与发现记录契约为2.0；对象、命题及风险编号保持不变。

## 打开

双击 `AI-Agent安全审计图谱.html`。页面完全自包含、纯离线：数据、样式与脚本都已内联，不访问任何外部地址，不写浏览器存储。页面里「来源入口」的链接指向本目录下的 `data/` 与 `sources/`，本地打开时可直接点进去看原始 JSON 与参考源原件。

## 重新生成与校验

```
python3 scripts/build.py     # 由 data/ 与 ui/ 重建 explorer-data.json、页面与skill知识包
python3 scripts/verify.py    # 校验参考源指纹、计数，以及索引、页面和skill知识包的可重建性
```

只需要 Python 3，无第三方依赖。改了 `data/` 下的 JSON 之后跑一次 `build.py`，页面即同步；`verify.py` 的 PASS 表示这份页面确实是由这份数据生成的。

`build.py`还从同一数据生成`skills/agent-security-audit/knowledge/`。这是框架维护与发布步骤；运行审计不调用构建脚本。

本目录就是这份数据的本体，不是别处的导出副本：要改内容就改这里的 `data/`，改完跑 `build.py` 与 `verify.py`。

整个目录可以整体搬到任何路径：脚本按自身位置定位，数据与页面里没有绝对路径，搬动后重建的产物与搬动前逐字节一致。

## 目录

| 路径 | 内容 |
|---|---|
| `AI-Agent安全审计图谱.html` | 交互页面，自包含离线版 |
| `data/` | 规范数据，16 个 JSON，审计以此为准，也是唯一的修改入口 |
| `ui/` | 页面源码（模板、样式、脚本），构建时内联进 HTML |
| `scripts/` | 构建、知识包导出与发布校验 |
| `skills/agent-security-audit/` | 可独立分发的审计skill，含调度规程与角色契约、专项方法、界面模式族、只读知识包、目标知识库工具、技能自检与可选动态验证 |
| `tests/` | 静态夹具、记录与工具测试、可选浏览器验收 |
| `sources/` | 参考源原件，按来源方分目录，只读 |
| `data-contract.json` | 数据契约：各文件职责、建模规则与维护规程 |
| `expectations.json` | 本版本声明的各项计数 |
| `explorer-data.json` | 由 `data/` 编译出的索引，页面内联的就是它；不要手改 |

`data/audit-profile.json` 的维度可带 `affects_ids`，登记「哪个选项决定该组件在不在」。`seed --route` 据此裁剪本轮计划：某对象被某维度管辖、而该维度已有取值与证据且取值不含任何启用该对象的选项时，本轮不生成其命题检查，对象连同维度与证据记入 `route_excluded`。未取得取值或缺证据一律不裁剪——未知能力不能当作不存在，裁剪是计划范围而不是不适用判定。当前登记了四个维度（工具能力、外部内容来源、协作形态、扩展来源），对应 9 个对象、50 条命题；部署形态、自治度、数据范围与身份模型不做机械裁剪，它们改变的是取证责任与逐条判断，裁剪掉会丢失显式的「不适用」记录。

`data/` 里最常用的几个：

- `architecture.json` — 七层、36 个架构对象、4 个跨域主题与 15 个跨域安全对象
- `failure-modes.json` — **211 条检查命题**，分别记录适用前提与失效判据，并包含取证要求、技术要求、核查步骤与检测信号
- `risk-object-links.json` — 风险目录条目到对象命题的索引；同一风险在同一对象上可关联多个独立命题
- `cases.json` — 269 条案例记录，含对象挂载与逐条理由
- `case-object-review.json` — 每条案例对架构对象的定位结论
- `defense.json` — 51 组对象技术要求、9 项系统级联合核查、53 条 CIS 条款索引
- `audit-profile.json` / `finding-schema.json` — 审计开始前要确定的目标形态，与发现的记录形态

## 使用审计skill

入口为[SKILL.md](skills/agent-security-audit/SKILL.md)。一个skill直接审计设计文档、源码、配置和已有记录，按需要组合Skill、MCP、框架与业务系统指南。默认静态分析，不执行目标代码、测试或包内脚本；用户明确授权动态验证时，使用独立工具向指定 HTTP 接口发起受限请求，或导入已有运行观测。

是否分单元由模型根据职责、依赖和证据边界决定，见[调度规程](skills/agent-security-audit/references/orchestration.md)：

- `plan` 提供候选分组，模型确认或用 `plan --apply` 提交明确材料归属；脚本校验分区与引用，不按命中数或字节自动合并、拆分。
- `surface` / `recall` 按具体定位问题选用。文本匹配不等于实际调用或覆盖，不要求逐命中处置；模型确认的调用位置另记 `call_sites`。
- `dispatch` 预切框架知识；执行者写带单元 ID 的 `partial.json`，由 `merge` 幂等合入。结构、引用、证据指纹与行号仍严格校验。
- `review --prepare` 提供完整判据状态和原证据；模型负责适用性、反证关系、定级和语义分歧。撤下候选保留明确的 `dismissed_candidates` 关联。
- 三阶段由模型分别决定 `joint` / `chain` / `goal` / `xartifact` 是否需要，可零项。`gate` 核对正式任务与声明是否闭合；原始检索不构成闸门。脚本通过不证明语义正确。
- 目标记录 1.6 保留旧事实与旧冻结来源，历史调用数、fp 不自动升级为模型已核验结论。

角色契约在 `references/roles/`（worker、reviewer、merger、queue_critic、report_writer），各读属于自己的那一份。并行能力不可用时降级为顺序执行，记录、闸门与报告完全相同。

将整个`skills/agent-security-audit/`目录复制到Codex的`~/.codex/skills/`或Claude Code的`~/.claude/skills/`。保持目录完整，知识包和Python工具均按自身位置定位，不依赖本仓库、旧审计skill或元技能。可用的调用示例：

```text
使用 agent-security-audit 静态审计 /path/to/target，结合 /path/to/design.md，
将目标知识库和报告保存在 /path/to/output/agent_audit/example。
```

框架知识与目标知识分别维护：

| 管线 | 维护对象 | 输出 |
|---|---|---|
| 框架维护与发布 | 通用对象、命题、风险关联、控制与案例 | HTML、规范JSON与随包知识快照 |
| 目标审计 | 目标实例、关系、证据、假设、检查和发现 | `audit.json`、Markdown/SARIF报告、观测与历史快照 |

审计引用固定的框架基线，不修改通用框架、安装的skill或随包快照。FM命题确定审计问题，前提、判据、取证要求和步骤是非穷尽参考，具体怎么查由模型结合目标判断。`seed`只建立命题任务，条件笔记可为空或自定；脚本核对范围内命题的覆盖、显式状态与记录一致性，不要求条件列表匹配知识库或全部满足。框架尚未覆盖的问题可以建立目标本地检查，无须先补通用命题。报告区分成立、不成立、证据不足、不适用、尚未检查与待复核。

续审使用材料指纹定位变化，沿实例与连接标记需要复核的记录，并保留历史。框架版本变化时明确选择新的引用基线，不在运行中自动更新知识内容。具体命令和记录格式见[目标知识库说明](skills/agent-security-audit/references/records.md)。

独立知识包保留来源身份、链接与许可说明，不包含`sources/`原始PDF；其中原件路径需回到框架发布包查阅。通用案例是分析参考，不是待审目标的漏洞证据。

材料读取回执区分完整、部分、不可读与不透明制品；缓存和字节码也纳入清单。八份专项方法按对象按需装载，分别覆盖 Skill 完整性、MCP 边界、指令信任、动作授权、状态隔离、运行环境隔离、内容解析与渲染、控制评估。候选发现须经过带理由与反证的复核才能作为当前发现导出；有效控制也需要关联检查及反证。

动态验证的配置、预算、脱敏观测与错误状态单独保存，Canary 命中不会自动生成漏洞。内置 JSON HTTP 和 OpenAI 兼容聊天接口适配器，不包含 MCP、浏览器或多轮 Agent 的自动执行器；这些场景可导入独立工具取得的真实观测，模拟结果单独标识。用法见[动态验证说明](skills/agent-security-audit/references/dynamic.md)。

目标知识库升级为 `1.2`，新增单元划分、轮次、攻击链、原语矩阵、制品聚类、待裁决清单与残余前沿清单等调度集合。已有 `1.0` 与 `1.1` 工作区运行 `refresh` 后保留历史：`1.0` 的发现标为待复核，`1.1` 的发现保留原状态（真正触发复核的是材料变化与审计规程指纹变化）。框架数据与页面展示不受目标记录升级影响。

方法借鉴`agent-framework-security-audit`的架构侦察、暴露层级与范围覆盖，`generate-security-audit-skill`的双向追踪、防护有效性、信任模型、能力组合、攻击原语与资产分析，以及`generate-svc-audit-skill`的执行协议：角色分工与读取边界、项集合冻结、两个分母的机械对账、冻结前的对抗式质问。材料可见性、专项方法、发现复核和独立观测流程也参考了 [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) 的实现思路。这些项目不是运行依赖。

## 验证审计工具

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 skills/agent-security-audit/scripts/self_check.py
python3 tests/check_ui.py
```

第一条仅使用标准库，验证条件判定、材料读取、复核过期、控制反证、SARIF、版本迁移、快照、独立分发，以及调度层的单元分区、界面索引对账、产物拒收与隔离、幂等合入、冻结与闸门、画像路由与定级校准；动态工具测试仅向测试创建的本机 HTTP 服务发送请求。第二条是随技能分发的自检，核技能自身的一致性（schema 只钉一处、ID 前缀表与可合入集合对齐、模式族路由到存在的对象、单元 brief 预算、子命令都有文档、角色契约固定了 return 行、记录接受的取值与文档一致、闸门每一行都被发出），安装后的副本也能跑。第三条需要本机已有Playwright和Chromium，验证离线页面的选择与取消、命题展示及案例展开。夹具只作为材料读取，不执行其中代码或指令。

这些检查验证数据、工具和展示行为，不衡量模型在真实项目中的漏洞发现率或误报率。正式审计仍需逐项回源复核。

## 这一版有什么

| | |
|---|---:|
| 架构对象 | 36（七层）|
| 跨域主题 | 4：身份权限安全、数据安全、供应链安全、网络隔离安全 |
| 跨域安全对象 | 15 + 1 个共享视图 |
| 检查命题 | 211 |
| 活动风险目录 | 156（OWASP LLM 10 / ASI 10 / DSGAI 21 / AST 10 / MCP 10，MITRE ATLAS 95）|
| 风险—对象—命题关联 | 563（含视图投影）|
| 对象技术要求 | 51 组；系统级联合核查 9 项；CIS 条款 53 条 |
| 案例记录 | 269（Crosswalk 147 / MITRE ATLAS 73 / 人工采集 49）|
| 案例对象挂载 | 409，每条写明该案例的哪个环节落到该对象 |
| 案例引用 | 605，每条案例至少一条本案专属来源 |

## 几条读这份数据时要知道的事

**命题编号 `FM-<对象>-<序号>` 是本项目自定的**，不来自任何外部标准。外部编号是 `LLM01`/`ASI02`/`DSGAI01`/`AST06`/`MCP01`（OWASP）、`AML.T0051`/`AML.CS0059`（MITRE ATLAS）、`INC-001`（Crosswalk）。

**对象映射是项目解释，不是来源机构的官方映射。** 每条命题自带 `origin` 说明这一点。MITRE、OWASP 与 CIS 没有审核或认可本项目的映射。

**技术要求、核查步骤与检测信号是项目细化，未在任何目标系统上执行过**；`detectability` 是判断，需按目标的实际遥测核对。

**案例的对象挂载分两种依据**：`案例正文` 表示理由取自记录原文，可逐句核对；`项目推断` 表示该对象是所述机制的必经组件但记录未点名。当前 409 条挂载均已指向具体命题；缺少对应命题时，应显式记录 `fm_gap`，不能强行匹配。

**`data/` 与 `sources/` 的关系**：`sources/` 是参考源原件，只读，由 `data/metadata.json` 的 `source_hashes` 逐文件锁定 sha256；`data/` 是本项目自己的数据，审计以它为准。两者不一致之处逐条登记在 `data/source-corrections.json`，含字段、from/to、理由与证据链接。

**记录语言**：案例以中文呈现；英文措辞保留在同名原字段里供回查，原始出处回 `sources/` 查。产品名、CVE 与公告编号、文件路径、命令与攻击载荷按原样保留，攻击载荷一律不翻译。

## 来源与许可

OWASP MCP Top 10 使用 **2025 年版、beta / v0.1**，固定到提供的克隆提交 [165fe0f](https://github.com/owasp/www-project-mcp-top-10/tree/165fe0f78ef104459237b4a8e0f6e78db9b02391)（2026-07-29）；这不是 2025 年末的历史快照。十项正文、README、目录和许可原件保存在 `sources/owasp/mcp-top10-2025/`，逐文件锁定指纹。MCP06 采用正文现名 Intent Flow Subversion，旧目录标题差异登记在 `data/metadata.json`。MCP 风险分类与 CIS MCP Server Benchmark 防御条款分别保留其来源和版本。

- OWASP GenAI Crosswalk — CC BY-SA 4.0（内容），https://github.com/GenAI-Security-Project/crosswalk
- OWASP MCP Top 10 — 上游 `LICENSE.md` 声明 CC BY-SA 4.0，README/index 链接 CC BY-NC-SA 4.0；两种声明及原件均保留。中文内容与关联为本项目整理，详见 `data/metadata.json`。
- CIS Controls AI Agents Companion Guide — CC BY-NC-ND 4.0（原文），https://www.cisecurity.org/controls/
- MITRE ATLAS data (c)2021-2026 MITRE — Apache License 2.0，https://github.com/mitre-atlas/atlas-data/blob/v2026.09/LICENSE

ATLAS 许可全文在页面「署名与内容许可」一节，也在 `data/metadata.json` 的 `license_text` 里。本页面对来源内容做了中文整理并新增了对象与控制关联。
