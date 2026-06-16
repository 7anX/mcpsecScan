# 测试样本 — 用于验证 mcpsec-scan 的检测能力

## 使用方法

在 Web UI 里输入路径进行扫描：
- 扫描所有恶意样本：输入 `test_samples/malicious`
- 扫描安全样本：输入 `test_samples/safe`
- 扫描单个文件：输入 `test_samples/malicious/01_credential_theft.py`

## 恶意样本（应检出）

| 文件 | 漏洞类型 | 预期检出层 |
|---|---|---|
| 01_credential_theft.py | Tool 描述投毒，偷取 SSH 密钥 | L2 |
| 02_ssrf.py | 用户 URL 直传 urlopen，无校验 | L3 |
| 03_command_injection.py | 用户输入拼接到 shell 命令 | L1 + L3 |
| 04_desc_code_mismatch.py | 描述说只读，代码写后门 | L4 |
| 05_pickle_rce.py | 用户路径传给 pickle.load | L1 + L3 |
| 06_shadowing.py | 跨工具操控，劫持邮件 | L2 |

## 安全样本（应零报）

| 文件 | 说明 |
|---|---|
| safe_calculator.py | 纯计算，无 IO |
| safe_weather_api.py | 有网络请求但 URL 硬编码 |
