# Sanhuo trusted Q7 verifier

这个小仓库只做一件事：为 `Glimmer2077/sanhuo-robot` 的四个固定候选
`MF-P2 / MF-T0 / MF-T1 / MF-T2` 生成和验证离线 Q7 双审查证据。

它不是通用审查平台，也不授予刷写、RESET、串口或动作权限。

## 最短流程

1. 生成两份审查提示：

   ```bash
   /usr/bin/python3 -I verifier.py prepare \
     --target-commit <三火仓库的40位提交> \
     --tool-workspace "/Users/glimmer/Documents/三火机器人" \
     --output-directory /tmp/sanhuo-q7-prompts
   ```

2. 把 `primary-prompt.md` 和 `verifier-prompt.md` 分别发给两个全新 ChatGPT
   对话。将返回的纯 JSON 保存回同一个 `/tmp/sanhuo-q7-prompts` 目录：

   - `primary-review.json`
   - `verifier-review.json`

3. 收回报告并生成一个四候选共同结论：

   ```bash
   /usr/bin/python3 -I verifier.py verify \
     --target-commit <同一个40位提交> \
     --tool-workspace "/Users/glimmer/Documents/三火机器人" \
     --review-directory /tmp/sanhuo-q7-prompts \
     --output /tmp/sanhuo-q7-result.json
   ```

## 固定边界

- 从 `--tool-workspace` 的本机 Git 对象库复制指定的精确提交到一次性目录；
  不读取当前工作区文件，不带入未提交改动，并禁用 Git replace 和继承配置。
- 同时只复制构建源码差异审计所需的固定冻结基线
  `8ae75f9a4082094784ac4b8f466d1466dd5ab5f2`，不复制任意额外引用。
- 操作者在运行前单独确认该提交已经推送到 GitHub；验证器和沙箱都不读取
  GitHub 登录凭证。
- 本机 Git 元数据属于操作者控制的可信输入；指定提交中的仓库内容仍按
  不可信对象处理，只能在沙箱中执行。
- `verify` 在运行被审代码前先读取、限制、解析并哈希两份报告。
- 外层验证器只接受 Apple Xcode 自带的隔离 Python；并在任何被审 Python、
  构建器或 ELF 工具运行前，独立核对固定工具链清单和全部目录闭包。
- 被审代码只会在 macOS `sandbox-exec` 中运行；没有网络、设备树、宿主
  凭证或报告目录访问权。
- 四候选的 `build / qualify / audit` 共 12 个固定命令，每个命令使用新的
  可写隔离区；可信层只把上一命令的普通文件快照交给下一命令，旧后台进程
  无法修改后续状态或最终证据。
- 锁定 PlatformIO 平台和包始终只读，不在可写目录中建立工具链软链接；
  只对原始根目录下 PlatformIO 自身的 `platforms.lock`、`packages.lock`
  两个临时并发锁开放精确写权限。这两个文件不是构建输入，也不进入工具链闭包
  或最终证据。
- 当前 ELF 的原始哈希、去符号语义哈希和能力，在最终只读快照上由本仓库
  代码重新计算。
- 每次 `prepare` 都生成新的随机审查挑战；两份报告必须与同目录提示包一致，
  且一次通过预检的 `verify` 尝试会原子消费该挑战。
- 任何一项漂移都不产生结果文件；通过结果也始终保持所有硬件权限为
  `false`，命令列表为空。

运行要求：macOS、现有三火项目的锁定离线构建缓存和工具链。代码只使用
Python 标准库。
