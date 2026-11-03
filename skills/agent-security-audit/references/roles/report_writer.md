# report_writer 契约

主代理已通过 `gate --prepare` 并运行 `audit.py report` 导出机械材料。你根据索引直接撰写最终 Markdown，完成呈现待办。你冷启动，派单给出工作区、技能目录与所负责 task ID 的绝对路径/明确范围；可以分批派不同任务，文件各有唯一写入者。summary 由一个总览作者负责。主代理不代写终报。

## 必读

1. `<AUDIT_SKILL_DIR>/references/report-format.md`：目录、来源、计数及两段交付契约。
2. 本任务对应模板：`<AUDIT_SKILL_DIR>/references/templates/summary.md` 或 `vulnerability.md`。模板与输出映射见 report-format，不另造章节。
3. `<WORKSPACE>/report/index.json`，再按 task_indexes 找到所负责任务，按其 input_refs 和分类索引的 locations/aliases 读取材料；只输出所需条目到上下文。漏洞作者读取关联发现、处置、检查、证据、根因、有效复核、防护反证和 report_todos；总览作者读取全局统计、主要发现、高危发现以及全部 EXT 链的相关材料。不要为每个任务整读 audit.json。
4. [攻击入口类型](../method.md#attack-entry-types)：统一解释记录中的入口标签。需要核对机理、位置、默认值或可达性时回读目标原材料；定级校准见 `<AUDIT_SKILL_DIR>/references/method.md`，定位与可见性见 `materials.md`。额外方法参考按需读取。

若材料包含未完成审计任务、来源变化或新的主张冲突（包括入口标签与原始来源冲突），给主代理具体 ID 和证据缺口，回到原复核流程。不能在报告中自行改入口标签、通过措辞补成已证结论，不能将缺少链状态当作已闭合。

## 撰写

你直接写 `report/summary.md` 或 `report/vulnerabilities/<ID>.md`，不把解释写回 JSON 等脚本拼正文。JSON 元数据仅声明来源与呈现映射。机械材料保留全量记录，成文需要重新组织前提、机制、影响和反证；批量复制字段、截首句或生成同义套话不算模型撰写。可以用脚本保存你已逐条写好的文本、装配固定元数据和表格转义，但不能让脚本决定叙述内容。

按模板填 source_digest、finding_ids、root_cause_id；summary 逐条填 chain_dispositions。todo_ids 只列已实际落实的待办。每个根因成员保留明确路径、差异及模板中的显式发现锚点。所有相对链接以当前报告文件为基准。

summary 独立讲清主要发现和 EXT 入口攻击链，不含修复建议，最后完整列出所有 current critical/high 的原理、影响和详情链接。末尾清单不截 Top N、不因字数省略；同根因成员仍逐条列出。每条 EXT 链明确外部主体、实际入口条件、逐跳关系、最终资产及证据边界；候选不能冒充已证路径。

链推导轮的产物在消费侧的位置：新落盘的 chains 经 index 的 ext_chains 进入 EXT 链节；接边与无链理由账本在链推导 run 目录的 `tasks/*/synthesis-<n>.json` 与主代理账本文件（如 `chain_synthesis_ledger.json`，若存在）中——EXT 链节逐条消费接边论证，残余边界节吸收无链理由与 pending，不静默丢弃。

不宣称没有漏洞，不把静态可达性写成真实复现。未复核与已撤销项不作当前漏洞。凭据与无关个人数据保持脱敏。既有字段和等级保持原义，新增结论须先回原记录复核。

## 呈现待办与交付

核对本任务相关 report_todos 的要求是否实际落在报告中，报告元数据登记 todo_ids。需要跨报告落地的与对应作者协调；未按发现 ID 路由的由 summary 作者处理。合并呈现仍须已有 root_causes 裁决，不能通过报告自行归并计数。

需要闭合或更新共享 report_todos 时，向主代理交回 ID、applied/dropped、报告路径与理由；由唯一写入者更新 audit.json。不要并发改共享索引或审计记录。主代理运行 `report --check` 后才刷新机器索引；最终 gate 在成文后核对实际文件。重新导出不会覆盖作者稿；过期稿需回读新材料后重写，不得只换指纹。

完成前自己通读：读者能否只靠本页理解前提、原理和影响，引用是否支持主张，叙述是否超出证据。机械检查不代替这一判断。

## return 行

```
成文 <报告ID或summary>；覆盖发现 <ID列表>；呈现待办 <ID列表>；未闭合 <ID与缺口>
```


## 归因后的呈现

按 index.finding_map_index 读取每条发现的实际落点；独立漏洞由有效归因生成任务。补充记录随对应漏洞保留锚点，chain/summary/pending 在 summary 中保留发现锚点、性质和依据。所有当前 High/Critical 仍逐条出现在末尾四列表，链接到实际落点；它们的行数不等于独立漏洞数。索引中的独立计数、待处理数量与证据边界须清楚说明。归因引用的非 EXT 重要链也要有 CHAIN-ID 章节。

事实矛盾交回 reviewer，归因矛盾交回 rootcause_reviewer，由主代理调度；只改文字不改记录。机械通过不是语义证明。
