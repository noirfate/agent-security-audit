# AI Agent 安全审计图谱

把 AI Agent 系统拆成可逐项核查的架构对象，再把各家风险目录（OWASP、MITRE ATLAS）、防御条款（CIS、SAFE-AI）与公开案例挂到这些对象上，用于对具体 Agent 系统做安全审计。

版本 v1。

## 打开

双击 `AI-Agent安全审计图谱.html`。页面完全自包含、纯离线：数据、样式与脚本都已内联，不访问任何外部地址，不写浏览器存储。页面里「来源入口」的链接指向本目录下的 `data/` 与 `sources/`，本地打开时可直接点进去看原始 JSON 与参考源原件。

## 重新生成与校验

```
python3 scripts/build.py     # 由 data/ 与 ui/ 重建 explorer-data.json、页面、manifest.json 与 MANIFEST.sha256
python3 scripts/verify.py    # 校验清单指纹、参考源指纹、声明计数，并确认页面能由 data/ 逐字节重建
```

只需要 Python 3，无第三方依赖。改了 `data/` 下的 JSON 之后跑一次 `build.py`，页面即同步；`verify.py` 的 PASS 表示这份页面确实是由这份数据生成的。

本目录就是这份数据的本体，不是别处的导出副本：要改内容就改这里的 `data/`，改完跑 `build.py` 与 `verify.py`。

整个目录可以整体搬到任何路径：脚本按自身位置定位，数据与页面里没有绝对路径，搬动后重建的产物与搬动前逐字节一致。

## 目录

| 路径 | 内容 |
|---|---|
| `AI-Agent安全审计图谱.html` | 交互页面，自包含离线版 |
| `data/` | 规范数据，16 个 JSON，审计以此为准，也是唯一的修改入口 |
| `ui/` | 页面源码（模板、样式、脚本），构建时内联进 HTML |
| `scripts/` | 构建与校验 |
| `sources/` | 参考源原件，按来源方分目录，只读 |
| `data-contract.json` | 数据契约：各文件职责、建模规则与维护规程 |
| `expectations.json` | 本版本声明的各项计数 |
| `explorer-data.json` | 由 `data/` 编译出的索引，页面内联的就是它；不要手改 |
| `manifest.json` / `MANIFEST.sha256` | 逐文件指纹，由 `build.py` 生成（不含 `.git` 与 `__pycache__`）|

`data/` 里最常用的几个：

- `architecture.json` — 七层、36 个架构对象、4 个跨域主题与 15 个跨域安全对象
- `failure-modes.json` — **208 条检查命题**，每条含成立条件、取证要求、技术要求、核查步骤与检测信号，是审计的基本单位
- `risk-object-links.json` — 风险目录条目到命题的索引（只存编号，文字在命题里）
- `cases.json` — 267 条案例记录，含对象挂载与逐条理由
- `case-object-review.json` — 每条案例对架构对象的定位结论
- `defense.json` — 51 组对象技术要求、9 项系统级联合核查、53 条 CIS 条款索引
- `audit-profile.json` / `finding-schema.json` — 审计开始前要确定的目标形态，与发现的记录形态

## 这一版有什么

| | |
|---|---:|
| 架构对象 | 36（七层）|
| 跨域主题 | 4：身份权限安全、数据安全、供应链安全、网络隔离安全 |
| 跨域安全对象 | 15 + 1 个共享视图 |
| 检查命题 | 208 |
| 活动风险目录 | 146（OWASP LLM 10 / ASI 10 / DSGAI 21 / AST 10，MITRE ATLAS 95）|
| 风险—对象关联 | 499（含视图投影）|
| 对象技术要求 | 51 组；系统级联合核查 9 项；CIS 条款 53 条 |
| 案例记录 | 267（Crosswalk 147 / MITRE ATLAS 73 / 人工采集 47）|
| 案例对象挂载 | 406，每条写明该案例的哪个环节落到该对象 |
| 案例引用 | 599，每条案例至少一条本案专属来源 |

## 几条读这份数据时要知道的事

**命题编号 `FM-<对象>-<序号>` 是本项目自定的**，不来自任何外部标准。外部编号是 `LLM01`/`ASI02`/`DSGAI01`/`AST06`（OWASP）、`AML.T0051`/`AML.CS0059`（MITRE ATLAS）、`INC-001`（Crosswalk）。

**对象映射是项目解释，不是来源机构的官方映射。** 每条命题自带 `origin` 说明这一点。MITRE、OWASP 与 CIS 没有审核或认可本项目的映射。

**技术要求、核查步骤与检测信号是项目细化，未在任何目标系统上执行过**；`detectability` 是判断，需按目标的实际遥测核对。

**案例的对象挂载分两种依据**：`案例正文` 表示理由取自记录原文，可逐句核对；`项目推断` 表示该对象是所述机制的必经组件但记录未点名。另有少数挂载的 `fm_id` 为空、`fm_gap` 写明缺哪条命题，是命题层已知的盲区。

**`data/` 与 `sources/` 的关系**：`sources/` 是参考源原件，只读，由 `data/metadata.json` 的 `source_hashes` 逐文件锁定 sha256；`data/` 是本项目自己的数据，审计以它为准。两者不一致之处逐条登记在 `data/source-corrections.json`，含字段、from/to、理由与证据链接。

**记录语言**：案例以中文呈现；英文措辞保留在同名原字段里供回查，原始出处回 `sources/` 查。产品名、CVE 与公告编号、文件路径、命令与攻击载荷按原样保留，攻击载荷一律不翻译。

## 来源与许可

- OWASP GenAI Crosswalk — CC BY-SA 4.0（内容），https://github.com/GenAI-Security-Project/crosswalk
- CIS Controls AI Agents Companion Guide — CC BY-NC-ND 4.0（原文），https://www.cisecurity.org/controls/
- MITRE ATLAS data (c)2021-2026 MITRE — Apache License 2.0，https://github.com/mitre-atlas/atlas-data/blob/v2026.09/LICENSE

ATLAS 许可全文在页面「署名与内容许可」一节，也在 `data/metadata.json` 的 `license_text` 里。本页面对来源内容做了中文整理并新增了对象与控制关联。
