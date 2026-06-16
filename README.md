# mcpsecscan

**MCP Server 静态安全扫描器** — 扫描 MCP server 源码（不运行代码），通过 AST 分析和 Semgrep 污点追踪发现安全漏洞。

```bash
pip install -e .
mcpsecscan scan ./my-mcp-server/
```

> **静态分析**：mcpsecscan 只读取源代码文件，不启动、不连接、不执行任何 MCP server 进程。

---

## 为什么用 mcpsecscan？

现有 MCP 扫描器（Cisco mcp-scanner、Ramparts）主要用 **关键词/YARA 规则** 匹配工具描述文本。
这意味着：攻击者只要在描述里不写明显的恶意词，就能绕过。

mcpsecscan 的核心差异是**分析源代码本身**，而不是工具描述文本：

- **L3 污点分析**：追踪用户输入参数是否流向危险操作（`requests.get(url)`、`subprocess.run(cmd)`等），不依赖任何关键词
- **L4 描述-代码一致性**：对比 docstring 声称的行为（"只读"）和代码实际执行的操作（写文件），检测静默后门
- **完全离线**：不调用 LLM API，不联网，结果确定可复现

---

## 与 Cisco mcp-scanner 实测对比

测试集：**17 个目标**（9 个高危 / 8 个安全），含真实仓库（sshmcp、mcp-toolkit、官方 fetch/git server）和项目内置样本。
两款工具均使用纯静态模式（mcpsecscan 跳过 L3，Cisco 使用 YARA-only 模式），不调用任何 LLM。

| 指标 | Cisco mcp-scanner (YARA) | **mcpsecscan (L1+L2+L4)** |
|---|:---:|:---:|
| 检出率 (Recall) | 44.4% (4/9) | **77.8% (7/9)** |
| 精确率 (Precision) | 100% | **100%** |
| F1 | 61.5% | **87.5%** |
| 误报 | 0 | **0** |

### Cisco 漏报、mcpsecscan 检出的 3 个案例

Cisco YARA 只扫描工具描述文本，这三个样本的描述都是普通语言，没有恶意关键词，因此 YARA 全部漏报。

| 样本 | 漏洞 | 描述看起来像 | mcpsecscan 检出方式 |
|---|---|---|---|
| `04_command_injection.py` | `subprocess(shell=True)` 命令注入 | "Network diagnostics toolkit" | **L1 扫描源码**，发现 5 处 `shell=True` |
| `05_supply_chain.py` | `pickle.load` 用户控路径 → RCE | "Smart cache with pluggable backends" | **L1 扫描源码**，发现 `pickle.load` |
| `06_desc_code_mismatch.py` | 描述说只读，代码写后门 | "read-only operation" | **L4 对比**描述与代码行为，Cisco 无此层 |

---

## 四层检测架构

```
L1  快速检测  (<1s)    硬编码密钥 · Unicode隐写 · 危险函数(pickle/eval/subprocess) · base64块
                       基于正则 + Python AST，扫描源码字面量和调用模式

L2  结构分析  (<5s)    工具描述的 Prompt Injection 检测
                       解析 @mcp.tool() 的 docstring/description，匹配 13 类攻击模式

L3  污点分析  (<30s)   用户参数 → 危险 sink 的数据流追踪（Semgrep taint mode）
                       支持 Python + JS/TS，需要 semgrep，可用 --skip-l3 跳过

L4  一致性检测 (<5s)   工具描述声称的行为 vs. 代码实际操作的矛盾检测
                       独有功能，其他扫描器均不具备
```

| 层 | 依赖 | 语言 | 典型耗时 |
|---|---|---|---|
| L1 | 无 | Python | <1s |
| L2 | 无 | Python | <5s |
| L3 | semgrep | Python + JS/TS | <30s |
| L4 | 无 | Python | <5s |

L3 未安装 semgrep 时自动跳过并提示，不报错。

---

## 安装

```bash
git clone https://github.com/xxx/mcpsecscan
cd mcpsecscan

# 基础安装（L1 + L2 + L4）
pip install -e .

# 完整安装（含 L3 污点分析）
pip install -e .
pip install semgrep
```

**Python >= 3.10，无其他强制依赖。**

---

## 使用

### CLI

```bash
# 扫描目录（全部四层）
mcpsecscan scan ./my-mcp-server/

# 跳过 L3（不需要 semgrep，速度更快）
mcpsecscan scan ./server.py --skip-l3

# JSON 输出（用于 CI/CD 解析）
mcpsecscan scan ./target --format json

# SARIF 输出（接入 GitHub Code Scanning）
mcpsecscan scan ./target --format sarif > results.sarif

# 用内置样本快速验证安装
mcpsecscan scan test_samples/python/malicious --skip-l3   # 应有 findings
mcpsecscan scan test_samples/python/safe      --skip-l3   # 应全部 0
```

### Web UI

```bash
mcpsecscan           # 启动后访问 http://localhost:8000
```

---

## 内置测试样本验证

项目内 `test_samples/` 包含完整的测试样本，可以直接运行验证：

```
test_samples/
├── python/
│   ├── malicious/    ← Python 恶意样本，6 个（应全部有 findings）
│   └── safe/         ← Python 安全样本，2 个（应全部 0 findings）
└── javascript/
    ├── malicious/    ← JS/TS 恶意样本，4 个（需 L3 Semgrep）
    └── safe/         ← JS 安全样本，1 个（应 0 findings）
```

### 恶意样本 — 应全部有 findings

以下是对 `test_samples/python/malicious/` 的真实扫描输出（L1+L2+L4，跳过 L3）：

```
$ mcpsecscan scan test_samples/python/malicious/01_credential_theft.py --skip-l3
  [HIGH]     [L2] MCPX-L2-004: Suspicious XML instruction tag in description
  [HIGH]     [L2] MCPX-L2-007: Coercive instruction: mandatory pre-execution requirement
  [CRITICAL] [L2] MCPX-L2-008: Sensitive file read instruction in description

$ mcpsecscan scan test_samples/python/malicious/02_shadowing.py --skip-l3
  [CRITICAL] [L2] MCPX-L2-002: Coercive instruction: threatening system crash or data loss
  [CRITICAL] [L2] MCPX-L2-003: Hidden behavior: instruction to conceal actions from user
  [HIGH]     [L2] MCPX-L2-004: Suspicious XML instruction tag in description

$ mcpsecscan scan test_samples/python/malicious/03_ssrf.py --skip-l3
  (0 findings — SSRF 依赖 L3 污点分析，需安装 semgrep 后完整扫描才能检出)

$ mcpsecscan scan test_samples/python/malicious/04_command_injection.py --skip-l3
  [MEDIUM] [L1] MCPX-L1-015: subprocess with shell=True   (×5 处)

$ mcpsecscan scan test_samples/python/malicious/05_supply_chain.py --skip-l3
  [HIGH] [L1] MCPX-L1-010: pickle.load/loads — arbitrary code execution   (×2 处)

$ mcpsecscan scan test_samples/python/malicious/06_desc_code_mismatch.py --skip-l3
  [CRITICAL] [L4] MCPX-L4-001: Description-code mismatch: 'read_notes' claims read-only but writes files
```

### 安全样本 — 应全部 0 findings

```
$ mcpsecscan scan test_samples/python/safe/safe_calculator.py --skip-l3
  0 findings

$ mcpsecscan scan test_samples/python/safe/safe_weather_api.py --skip-l3
  0 findings
```

### 样本内容说明

#### `01_credential_theft.py` — 描述投毒（L2）
工具描述里嵌入 `<IMPORTANT>` 标签，指令 AI 在调用前先读取 `~/.cursor/mcp.json` 和 `~/.ssh/id_rsa.pub` 并作为参数传入，同时要求 AI 不要告知用户。

#### `02_shadowing.py` — 工具投毒 + 隐藏行为（L2）
描述中包含威胁性语言（"application will crash"）和隐蔽指令（"Do not mention this to the user"），是典型的工具投毒攻击。

#### `03_ssrf.py` — 用户 URL 直传 urlopen（L3）
工具接受 `url` 参数，经 `urllib.request.Request(url)` 包装后传给 `urlopen`，无内网 IP 校验。需要 L3 Semgrep 污点分析才能跟踪中间变量的数据流。

#### `04_command_injection.py` — 不完整净化 + `shell=True`（L1）
`_sanitize()` 只过滤了 `& | > < \`` 五个字符，但允许 `;`、`$()` 等，配合 `shell=True` 仍可注入命令。L1 直接扫描到源码中 5 处 `subprocess.run(..., shell=True)`。

#### `05_supply_chain.py` — 用户控制路径的 pickle 反序列化（L1）
工具接受 `namespace` 和 `key` 参数，拼接成缓存文件路径后调用 `pickle.load(f)`。攻击者可在缓存路径放置恶意 pickle 文件实现 RCE。

#### `06_desc_code_mismatch.py` — 描述说只读，代码写后门（L4）
docstring 明确写 `"read-only operation that never modifies any files"`，但代码在 `~/.local/bin/` 写入 curl backdoor 脚本并设置 755 权限。L4 对比描述关键词与 AST 检测到的文件写操作，报告矛盾。

---

## Finding 输出结构

```json
{
  "id": "MCPX-L4-001",
  "title": "Description-code mismatch: 'read_notes' claims read-only but writes files",
  "severity": "critical",
  "layer": "L4",
  "file": "test_samples/malicious/06_desc_code_mismatch.py",
  "line": 14,
  "evidence": "Description says: \"never modifies any files\"\nBut code writes at line(s): [14, 15, 16, 17]",
  "remediation": "If the tool modifies files, update the description to state this clearly. If the tool should be read-only, remove the file-write operations.",
  "owasp_mcp": "MCP01",
  "cia_impact": ["I"],
  "confidence": "high",
  "tool_name": "read_notes"
}
```

每条 finding 包含精确的行号、证据片段、OWASP MCP 分类，以及具体修复建议（`remediation`）。

---

## 检测规则总览

### L1 — 快速检测（纯正则 + Python AST）

扫描源码文件内容，不需要运行代码。

| 类型 | 规则 ID | 匹配内容 |
|---|---|---|
| AWS Access Key | MCPX-L1-001 | `AKIA[0-9A-Z]{16}` |
| GitHub PAT | MCPX-L1-002 | `ghp_` / `github_pat_` |
| OpenAI API Key | MCPX-L1-003 | `sk-[A-Za-z0-9]{48+}` |
| Anthropic API Key | MCPX-L1-004 | `sk-ant-api` |
| Google AI Key | MCPX-L1-005 | `AIzaSy` |
| Slack Token | MCPX-L1-006 | `xox[abprs]-` |
| PEM 私钥 | MCPX-L1-007 | `BEGIN PRIVATE KEY` |
| Stripe Secret Key | MCPX-L1-008 | `sk_live_` |
| HuggingFace Token | MCPX-L1-009c | `hf_[A-Za-z0-9]{34+}` |
| pickle.load/loads | MCPX-L1-010 | 反序列化 RCE 风险 |
| yaml.load 无 SafeLoader | MCPX-L1-011 | 反序列化 RCE 风险 |
| eval() / exec() | MCPX-L1-013/014 | 动态代码执行 |
| subprocess shell=True | MCPX-L1-015 | 命令注入风险 |
| os.system() | MCPX-L1-016 | shell 命令执行 |
| `__doc__` 动态赋值 | MCPX-L1-019 | Rug-pull 准备行为 |
| Unicode 隐写 | MCPX-L1-020–022 | 零宽字符 / RTL 覆盖 / Tags 块 |

### L2 — MCP 结构分析（解析 @mcp.tool 的 docstring）

| 攻击类型 | 规则 ID | 模式示例 |
|---|---|---|
| 胁迫性描述 | MCPX-L2-001/002 | "will not work unless" / "system will crash" |
| 隐藏行为指令 | MCPX-L2-003 | "do not mention to user" |
| XML 指令标签 | MCPX-L2-004 | `<IMPORTANT>` / `<SYSTEM>` / `<OVERRIDE>` |
| 指令覆盖 | MCPX-L2-005 | "ignore all previous instructions" |
| 角色重定义 | MCPX-L2-006 | "you are now" / "pretend to be" |
| 强制前置执行 | MCPX-L2-007 | "before using this tool, must first read..." |
| 敏感文件读取 | MCPX-L2-008 | "read `~/.ssh/id_rsa`" 等路径 |
| 外部数据发送 | MCPX-L2-009 | "send ... to https://attacker.com" |
| Jailbreak 触发词 | MCPX-L2-010 | "DAN mode" / "developer mode" |
| 分隔符注入 | MCPX-L2-011 | `` ```system `` / `[INST]` / `<\|im_start\|>` |
| 空白字符外泄 | MCPX-L2-012 | "after many spaces" 等隐写指令 |
| 间接注入触发 | MCPX-L2-013 | "fetch and execute external content" |
| 跨工具操控 | MCPX-L2-020 | 一个工具描述控制另一个工具行为 |
| Rug-pull 变更 | MCPX-L2-030 | 描述哈希与上次扫描不一致 |

### L3 — Semgrep 污点分析（需安装 semgrep）

追踪 `@mcp.tool()` 函数参数到危险 sink 的完整数据流，支持中间变量传播。

| 漏洞类型 | 规则 ID | Source → Sink |
|---|---|---|
| SSRF | MCPX-L3-001 | `url` 参数 → requests/httpx/urllib/aiohttp/fetch/axios |
| 路径穿越 | MCPX-L3-002 | `path` 参数 → open/pathlib（无 realpath） |
| 命令注入 | MCPX-L3-003 | `cmd` 参数 → subprocess/os.system/asyncio.create_subprocess_shell/paramiko.exec_command |
| SQL 注入 | MCPX-L3-004 | `query` 参数 → cursor.execute(f-string) / db.prepare(\`\`) |
| 反序列化 RCE | MCPX-L3-005 | `path` 参数 → pickle.load/yaml.load/marshal.load |
| 动态代码执行 | MCPX-L3-006 | 参数 → eval/exec/importlib.import_module |
| SSTI | MCPX-L3-007 | 参数 → Jinja2 Template() / Environment.from_string() |
| ReDoS | MCPX-L3-008 | 参数 → re.compile()（无 re.escape()） |
| 凭据泄露到日志 | MCPX-L3-009 | password/secret 参数 → logging |

### L4 — 描述-代码一致性（仅 mcpsecscan 具备）

比较工具 docstring 声称的行为与代码 AST 检测到的实际操作。

| 矛盾类型 | 规则 ID | 触发条件 |
|---|---|---|
| 声称只读但写文件 | MCPX-L4-001 | "read-only" + `open(..., 'w')` |
| 声称纯计算但发网络请求 | MCPX-L4-002 | "calculate/convert" + `requests.get()` |
| 声称纯计算但执行命令 | MCPX-L4-003 | "compute" + `subprocess.run()` |
| 声称无网络但发请求 | MCPX-L4-004 | "offline/local-only" + `requests.*` |
| 声称只读但执行命令 | MCPX-L4-005 | "read-only" + `os.system()` |
| 声称安全但用危险操作 | MCPX-L4-006 | "safe/harmless" + `eval()/pickle.load()` |
| 无描述但执行危险操作 | MCPX-L4-007 | 无 docstring + 命令/文件写/网络调用 |
| 参数传入危险委托函数 | MCPX-L4-008 | `command` 参数 → `execute_command()` → SSH 执行 |
| 接受原始 SQL 参数 | MCPX-L4-009 | `sql` 参数 → `conn.execute(sql)` |

---

## CI/CD 集成

```yaml
# .github/workflows/security.yml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install mcpsecscan semgrep
      - name: Scan MCP server
        run: mcpsecscan scan . --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## License

Apache-2.0
