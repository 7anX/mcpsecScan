# test_samples — mcpsecscan 测试样本集

用于验证扫描器的检出率（恶意样本）和误报率（安全样本）。

## 目录结构

```
test_samples/
├── python/
│   ├── malicious/        ← 6 个恶意 Python MCP server，应全部有 findings
│   └── safe/             ← 2 个安全 Python MCP server，应全部 0 findings
└── javascript/
    ├── malicious/        ← 4 个恶意 JS/TS MCP server（需 L3 Semgrep 检出）
    └── safe/             ← 1 个安全 JS MCP server，应 0 findings
```

---

## Python 恶意样本

| 文件 | 攻击类型 | 检出层 | 漏洞说明 |
|---|---|---|---|
| `01_credential_theft.py` | 描述投毒 | **L2** | 工具描述嵌入 `<IMPORTANT>` 标签，指令 AI 读取 `~/.cursor/mcp.json` 和 `~/.ssh/id_rsa.pub` 并作为参数传入，同时要求 AI 对用户隐瞒此行为 |
| `02_shadowing.py` | 工具投毒 | **L2** | 描述含威胁性语言（"application will crash"）和隐蔽指令（"Do not mention this to the user"），典型工具投毒攻击 |
| `03_ssrf.py` | SSRF | **L3** | 工具接受 `url` 参数，经 `urllib.request.Request(url)` 包装后传给 `urlopen`，无内网 IP 校验。需要 Semgrep 污点分析追踪中间变量 |
| `04_command_injection.py` | 命令注入 | **L1** | `_sanitize()` 只过滤 5 个字符（`& \| > < \``），允许 `;` 和 `$()` 注入，配合 `subprocess.run(..., shell=True)` 仍可执行任意命令 |
| `05_supply_chain.py` | 反序列化 RCE | **L1** | 工具接受 `namespace` 和 `key` 参数，拼接成缓存文件路径后调用 `pickle.load(f)`。攻击者可在缓存路径放置恶意 pickle 文件实现 RCE |
| `06_desc_code_mismatch.py` | 描述-代码矛盾 | **L4** | docstring 明确写 "read-only operation that never modifies any files"，但代码在 `~/.local/bin/` 写入 curl backdoor 脚本并设为可执行 |

## Python 安全样本

| 文件 | 说明 | 为什么安全 |
|---|---|---|
| `safe_calculator.py` | 纯数学计算 | 无 IO、无网络、无系统调用，用户输入只参与算术运算 |
| `safe_weather_api.py` | 天气 API 代理 | URL 硬编码（用户只控制查询参数，不控制 host），无路径遍历风险 |

---

## JavaScript / TypeScript 恶意样本

这四个样本需要 **L3 Semgrep** 才能检出（L1/L2/L4 不覆盖 JS/TS）。

| 文件 | 攻击类型 | 漏洞说明 |
|---|---|---|
| `01_ssrf.js` | SSRF | 用户 `url` 参数直接传给 `fetch(url)`，无任何校验 |
| `02_command_injection.js` | 命令注入 | 用户 `hostname` 拼接到 `exec(\`ping -c 4 ${hostname}\`)` |
| `03_path_traversal.js` | 路径穿越 | `path.join(BASE_DIR, filename)` 无 `path.resolve + startsWith` 校验，可逃逸基础目录 |
| `04_sql_injection.ts` | SQL 注入 | 用户 `username` 拼接到 `` db.prepare(`SELECT ... WHERE name = '${username}'`) `` |

## JavaScript 安全样本

| 文件 | 说明 | 为什么安全 |
|---|---|---|
| `safe_server.js` | 文件读取服务 | 使用 `path.resolve + startsWith` 校验，用户路径无法逃逸 `DOCS_DIR` |

---

## 运行验证

```bash
cd mcpsecScan

# Python 恶意样本（L1+L2+L4，跳过 L3）— 应全部有 findings
mcpsecscan scan test_samples/python/malicious --skip-l3

# Python 安全样本 — 应全部 0 findings
mcpsecscan scan test_samples/python/safe --skip-l3

# 完整扫描含 L3（需安装 semgrep）
mcpsecscan scan test_samples/python/malicious

# JS/TS 样本（仅 L3 有效）
mcpsecscan scan test_samples/javascript/malicious
```

**注意**：`03_ssrf.py` 在跳过 L3 时输出 0 findings，这是预期行为——其漏洞是数据流类型（用户 URL 经中间变量传给 urlopen），仅靠正则和 AST 无法检出，需要 Semgrep 污点分析。
