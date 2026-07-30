# Sanhuo trusted Q7 verifier

这个小仓库只做一件事：为 `Glimmer2077/sanhuo-robot` 的四个固定候选
`MF-P2 / MF-T0 / MF-T1 / MF-T2` 生成和验证离线 Q7 双审查证据。

它不是通用审查平台，也不授予刷写、RESET、串口或动作权限。

## 最短流程

1. 生成两份审查提示：

   ```bash
   python3 verifier.py prepare \
     --target-commit <三火仓库的40位提交> \
     --tool-workspace "/Users/glimmer/Documents/三火机器人" \
     --output-directory /tmp/sanhuo-q7-prompts
   ```

2. 把 `primary-prompt.md` 和 `verifier-prompt.md` 分别发给两个全新 ChatGPT
   对话。将返回的纯 JSON 分别保存为：

   - `primary-review.json`
   - `verifier-review.json`

3. 收回报告并生成一个四候选共同结论：

   ```bash
   python3 verifier.py verify \
     --target-commit <同一个40位提交> \
     --tool-workspace "/Users/glimmer/Documents/三火机器人" \
     --review-directory /tmp/sanhuo-q7-reviews \
     --output /tmp/sanhuo-q7-result.json
   ```

## 固定边界

- 从 GitHub 获取精确提交到一次性目录，禁用 Git replace 和继承配置。
- `verify` 在运行被审代码前先读取、限制、解析并哈希两份报告。
- 被审代码只会在 macOS `sandbox-exec` 中运行；没有网络、设备树、宿主
  凭证或报告目录访问权。
- 每次原子重跑四候选的 `build / qualify / audit`，共 12 个固定命令。
- 当前 ELF 的原始哈希、去符号语义哈希和能力由本仓库代码重新计算。
- 任何一项漂移都不产生结果文件；通过结果也始终保持所有硬件权限为
  `false`，命令列表为空。

运行要求：macOS、现有三火项目的锁定离线构建缓存和工具链。代码只使用
Python 标准库。
