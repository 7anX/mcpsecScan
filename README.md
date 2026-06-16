# mcpsec-scan

**MCP Server 静态安全扫描器** — 通过污点分析和描述-代码一致性检测，发现其他工具找不到的漏洞。

```bash
pip install -e .
mcpsec-scan scan ./my-mcp-server/
```

---

## 为什么用 mcpsec-scan？

现有 MCP 扫描器（Cisco mcp-scanner、Ramparts）用 **关键词/正则匹配** 检测漏洞。
当攻击者**不写明显的恶意关键词**（真实攻击者当然不会写 `evil.com`），它们全部失效。

mcpsec-scan 不同：它追踪**数据流**——"用户输入是否流向了危险操作"，不依赖字面量。

### 实测对比

用 10 个恶意样本（含无恶意字面量的高质量 PoC）+ 3 个安全样本测试：

| 指标 | Cisco mcp-scanner | Ramparts | **mcpsec-scan** |
|---|:---:|:---:|:---:|
| **检出率** | 8/10 | 7/10 | **10/10** |
| **误报数** | 2 | 1 | **0** |
| **精确分类** | ❌ 泛泛 (ReDoS→script_injection) | ❌ 泛泛 | **✅ 精确到漏洞类型** |
| **JS/TS 支持** | ⚠️ 文本匹配 | ⚠️ 文本匹配 | **✅ taint analysis** |
| **数据流分析** | ❌ | ❌ | **✅ Semgrep taint** |
| **描述-代码矛盾** | ❌ | ❌ | **✅ L4 独有** |
| **需要 LLM/API** | ✅ 需要 | ❌ | **❌ 完全离线** |
| **结果可复现** | ❌ (LLM 不确定) | ✅ | **✅** |

### 关键差异：同一个 SSRF 漏洞

```python
@mcp.tool()
def preview(url: str) -> str:
    """Preview a URL."""
    resp = urllib.request.urlopen(url)  # ← 用户 URL 直传，SSRF！
    return resp.read()
```

| 工具 | 检出？ | 报告内容 |
|---|---|---|
| Cisco | ⚠️ 报了 `script_injection`（不是 SSRF） | 匹配了 `urllib` 关键词,但分类错误 |
| Ramparts | ⚠️ 报了 `CrossOriginEscalation`（不是 SSRF） | 匹配了 URL 字面量,分类不精确 |
| **mcpsec-scan** | **✅ 4 条 HIGH: SSRF** | "User-controlled URL flows to urlopen without IP validation" at line 29,37,100,102 |

**区别**：竞品靠关键词碰巧"报了"，但报的不是 SSRF——对修复毫无指导。mcpsec-scan 精确追踪数据流，准确告诉你"哪个参数流向了哪个危险函数"。

---

## 四层检测架构

```
L1  快速检测 (<1s)       硬编码密钥 · Unicode隐写 · 危险函数调用 · base64编码块
L2  MCP结构分析 (<5s)    描述投毒 · 胁迫指令 · 跨工具操控 · rug-pull变更检测
L3  污点分析 (<30s)      用户输入 → 危险sink 数据流追踪 (Semgrep taint)
L4  描述-代码一致性       "描述说只读，代码写文件" 矛盾检测
```

- **L1+L2+L4**：零依赖，纯 Python AST，毫秒级
- **L3**：需安装 Semgrep（`pip install semgrep`），秒级，支持 Python + JS/TS

---

## 安装

```bash
git clone https://github.com/xxx/mcpsec-scan
cd mcpsec-scan
pip install -e .

# 推荐：安装 semgrep 启用 L3 深度分析
pip install semgrep
```

### 完全离线运行

mcpsec-scan **不需要任何网络连接**：

- ❌ 不调用 LLM API（不需要 OpenAI/Anthropic key）
- ❌ 不上传代码到云端（所有分析在本地完成）
- ❌ 不依赖在线规则库（规则随包安装）
- ✅ 适用于内网/隔离环境/企业审计场景
- ✅ 每次运行结果完全一致（确定性分析，无随机因素）

> 与 Cisco mcp-scanner（需 LLM API）、AI-Infra-Guard（需 Docker + LLM）不同，
> mcpsec-scan 从安装到扫描全程无需联网。代码不离开你的机器。

## 使用

### CLI 扫描（主要用法）

```bash
# 扫描目录
mcpsec-scan scan ./my-mcp-server/

# 扫描单文件
mcpsec-scan scan ./server.py

# 跳过 L3（无需 semgrep，更快）
mcpsec-scan scan ./target --skip-l3

# JSON 输出（CI/CD 集成）
mcpsec-scan scan ./target --format json

# SARIF 输出（GitHub Code Scanning）
mcpsec-scan scan ./target --format sarif > results.sarif
```

### Web UI（可视化演示）

```bash
mcpsec-scan
# 浏览器打开 http://localhost:8000
# 输入源码路径，点击扫描
```

---

## 检测能力

### Python

| 漏洞类型 | 检测层 | 说明 |
|---|---|---|
| SSRF | L3 taint | 用户 URL → urlopen/requests 无 IP 校验 |
| 路径穿越 | L3 taint | 用户路径 → open/pathlib 无 realpath |
| 命令注入 | L1 + L3 | subprocess(shell=True) + 用户输入拼接 |
| SQL 注入 | L3 taint | 用户输入 → cursor.execute(f"...") |
| 反序列化 RCE | L1 + L3 | pickle.load / yaml.load(无 SafeLoader) |
| 动态代码执行 | L3 taint | 用户输入 → importlib / eval / exec |
| SSTI 模板注入 | L3 taint | 用户输入 → Jinja2 Template() |
| ReDoS | L3 taint | 用户输入 → re.compile() |
| 描述投毒 | L2 | `<IMPORTANT>` / 胁迫 / 隐藏行为 |
| 跨工具操控 | L2 | 一个 tool 描述控制另一个 tool |
| Rug-pull | L2 | 描述哈希变更检测 |
| 描述-代码矛盾 | L4 | "声称只读"但代码写文件/联网/执行命令 |
| 硬编码密钥 | L1 | AWS/GitHub/OpenAI/Anthropic 精确格式 |
| Unicode 隐写 | L1 | 零宽字符 / RTL覆盖 / Tags块 |

### JavaScript / TypeScript

| 漏洞类型 | 检测层 | 说明 |
|---|---|---|
| SSRF | L3 taint | 用户参数 → fetch/axios/got |
| 命令注入 | L3 taint | 用户参数 → exec/execSync/spawn(shell) |
| 路径穿越 | L3 taint | 用户参数 → fs.readFile 无 path.resolve |
| SQL 注入 | L3 taint | 用户参数 → db.prepare(模板字符串) |

---

## 使用场景

### 1. 安装前审计
```bash
git clone https://github.com/someone/cool-mcp-server
mcpsec-scan scan ./cool-mcp-server/
# 有 HIGH？→ 不装 / 报给作者
```

### 2. CI/CD PR Gate
```yaml
# .github/workflows/security.yml
- run: mcpsec-scan scan . --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### 3. Web 可视化审计
```bash
mcpsec-scan  # 启动 Web UI
# 团队成员在浏览器里提交扫描，查看报告
```

---

## 测试样本

`test_samples/` 目录包含验证用的恶意和安全 MCP server：

```
test_samples/
├── malicious/           # Python 恶意样本 (6个)
├── malicious_js/        # JS/TS 恶意样本 (4个)
├── safe/                # Python 安全样本 (2个)
├── safe_js/             # JS 安全样本 (1个)
└── real_world/          # 官方 MCP servers (21个，测试零误报)
```

运行验证：
```bash
mcpsec-scan scan test_samples/malicious      # 应有 findings
mcpsec-scan scan test_samples/safe           # 应为 0
```

---

## 与竞品的定位差异

| | Cisco mcp-scanner | Ramparts | AI-Infra-Guard | **mcpsec-scan** |
|---|---|---|---|---|
| 核心方法 | YARA + LLM | YARA-X + LLM | LLM 读代码 | **Semgrep taint + AST** |
| 需要 API key | ✅ | ❌ | ✅ | **❌** |
| 确定性/可复现 | ❌ | ✅ | ❌ | **✅** |
| 数据流追踪 | ❌ | ❌ | ⚠️ LLM 猜 | **✅ 精确** |
| 描述-代码矛盾 | ❌ | ❌ | ❌ | **✅ 独有** |
| 部署复杂度 | pip | cargo | Docker+LLM | **pip** |
| 扫描速度 | ~10s | <1s | 3-25min | **<30s** |

**mcpsec-scan 的定位**：不是"大而全"的平台,而是**专注代码行为分析**的确定性扫描器。做一件事,做到最好。

---

## License

Apache-2.0
