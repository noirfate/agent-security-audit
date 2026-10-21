# 独立动态验证

仅在用户要求动态验证且目标、发送方式、允许动作和观测方式明确时读取。本流程补充静态分析；已有明确授权直接沿用，缺少具体范围时只询问缺项。一次允许读取源码的请求不自动授权调用线上接口。

## 确定目标与观测

先写出：目标版本、攻击者可控制的输入、待验证边界、允许动作、受控数据、成功与失败的可观察判据。用临时资源或随机canary，避免真实秘密；明确允许的网络端点。为目标使用独立测试账号，权限与角色由配置或记录证明，不能只靠模型自述。

内置`dynamic.py`支持两种真实HTTP适配器：通用JSON POST与OpenAI兼容非流式聊天。它不启动目标、不执行Shell、不自动重试、不跟随重定向、不使用环境代理。需要MCP、浏览器、WebSocket、流式、多轮状态管理或工具副作用观测时，使用用户已有且在授权范围内的工具采集，然后导入记录。不要为了使用适配器改变目标语义。

## 准备与发送

先按主流程初始化工作区。只有接口配置而无源码时，可将该配置文件作为一个目标材料，明确它只支持配置范围分析，不虚构代码对象。

连接配置示例（文件位于工作区之外；凭据只从环境变量注入）：

```json
{
  "name": "staging-agent",
  "adapter": "http_json",
  "url": "http://127.0.0.1:18080/chat",
  "authorization": "用户明确授权测试此测试接口；引用本次任务范围",
  "allowed_actions": "使用受控canary进行只读问答，不调用有副作用工具",
  "target_version": "deployment-or-commit-id",
  "max_requests": 10,
  "timeout_seconds": 20,
  "max_response_bytes": 262144,
  "request": {
    "method": "POST",
    "headers_env": {"Authorization": "AUDIT_AUTH_HEADER"},
    "body": {"message": "{{prompt}}"}
  },
  "response_pointer": "/reply"
}
```

`AUDIT_AUTH_HEADER`为完整Header值，例如`Bearer ...`。无需凭据时删除`headers_env`。URL须精确到端点，不含查询参数、用户信息或片段。OpenAI兼容接口使用`adapter: openai_chat`并提供`model`；默认选取`/choices/0/message/content`，脚本构造单轮messages和`stream: false`。

```bash
python3 "$AUDIT_SKILL_DIR/scripts/dynamic.py" prepare --workspace /output/agent_audit/example --config /path/to/connection.json
python3 "$AUDIT_SKILL_DIR/scripts/dynamic.py" run --workspace /output/agent_audit/example --session DYN-实际编号 --prompt-file /path/to/probe.txt
```

`prepare`固定配置并生成随机canary；`probe.txt`可使用`{{canary}}`。每次`run`发送一个请求，预算在发送前记账，失败和中断也计入。会话默认10次，上限100次，可按实际测试目标设置；次数不能替代覆盖论证。配置变更须创建新会话。

一次只推进一个有明确边界与假设的验证，根据实际反馈决定是否继续。停止条件：达到预算、已取得所需证据、持续不可观测、目标行为超出授权范围或用户停止。超时、响应过大、空响应体、无效JSON及解析路径不匹配均记录为未成功观测，不记作安全通过。已采集到响应也不等于获得了足以判定安全性质的证据。

## 判定与证据

工具将脱敏请求与响应保存到`observations/`，并登记摘要和SHA-256。`canary_hit`只表示响应包含标记：直接要求回显已知标记不证明泄露。泄露测试需要攻击者原本不可见的canary；状态变更需要独立副作用记录；两种身份的权限测试需要各自有效身份和资源归属的证据。

判断仍使用对象命题或目标本地检查。HTTP回复仅支持所收到的内容，模型说“已执行”不能作为工具调用成功证明。复现、否证和失败均保留记录，不把模拟对话计入真实观测。不要根据一次被阻断的payload宣称整体安全。

运行时证据示例：

```json
{
  "id": "E-RUNTIME-1",
  "kind": "runtime",
  "observation_id": "OBS-实际编号",
  "sha256": "对应观测记录的文件指纹",
  "locator": {"json_pointer": "/response/body/reply"},
  "observation": "只描述本次请求、身份和响应实际支持的事实",
  "status": "current"
}
```

`runtime`证据只能引用成功采集的真实HTTP或已有运行记录，不能引用错误、截断或模拟记录。被引用的观测值不能为`null`、空字符串或空容器；`false`和`0`可以是有效观测，含义仍需结合机制判断。它不使用`material_id`；其他证据仍引用原材料。对HTTP未观察到的副作用填`missing_evidence`。

## 导入已有观测

导入文件必须包含`source`（采集工具与来源）、`target_version`、`captured_at`、`observation_mode`、结构化`request`与`response`。实际记录用`recorded_runtime`，推演用`simulation`；后者只供假设参考，校验器禁止它支持runtime证据。导入不会自动验证来源真实性，审计者须回查原始采集来源。

```bash
python3 "$AUDIT_SKILL_DIR/scripts/dynamic.py" import --workspace /output/agent_audit/example --input /path/to/observation.json
```

工具脱敏已知凭据环境变量、敏感JSON字段、Bearer token和私钥片段；可通过配置`redact_env`列出其他需屏蔽的环境变量名称。这不是通用敏感数据检测，导入前及交付前仍核对自由文本中的真实秘密与个人数据。观测文件固定后不直接编辑；需要补充或纠正时导入新记录并将旧证据标为待复核。

完成后复核发现、登记有效控制，再运行主流程的`validate/report/snapshot`。报告分别显示动态观测状态、模拟来源和证据局限，框架知识不回写。
