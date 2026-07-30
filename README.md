# Sanhuo trusted Q7 verifier

这个小仓库只做一件事：为 `Glimmer2077/sanhuo-robot` 的四个固定候选
`MF-P2 / MF-T0 / MF-T1 / MF-T2` 生成和验证离线 Q7 双审查证据。

它不是通用审查平台，也不授予刷写、RESET、串口或动作权限。

## 最短流程

0. 从要审查的精确验证器提交下载启动器。不要从本地验证器工作区直接运行
   `verifier.py`：

   ```bash
   /usr/bin/curl --proto '=https' --tlsv1.2 --fail --location \
     --output /private/tmp/sanhuo-q7-bootstrap.py \
     https://raw.githubusercontent.com/Glimmer2077/sanhuo-q7-verifier/<验证器40位提交>/bootstrap.py
   ```

1. 通过启动器生成两份审查提示：

   ```bash
   /usr/bin/python3 -I /private/tmp/sanhuo-q7-bootstrap.py \
     --verifier-commit <同一个验证器40位提交> prepare \
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
   /usr/bin/python3 -I /private/tmp/sanhuo-q7-bootstrap.py \
     --verifier-commit <同一个验证器40位提交> verify \
     --target-commit <同一个40位提交> \
     --tool-workspace "/Users/glimmer/Documents/三火机器人" \
     --review-directory /tmp/sanhuo-q7-prompts \
     --output /tmp/sanhuo-q7-result.json
   ```

## 固定边界

- 启动器只从 GitHub 的精确 40 位提交下载封闭文件集，拒绝额外文件、Python
  缓存、符号链接和特殊文件；只把 `verifier.py`、`isolated_driver.py`
  与沙箱规则复制到新的只读临时快照，运行结束后再次核对其完整闭包。
- 验证器拒绝从任意本地 worktree 直接启动；它只接受上述精确提交启动器
  设置的提交、只读快照和 Apple 隔离 Python 身份。
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
  凭证或报告目录访问权。macOS 系统解析所需的只读命名空间保留，但
  `/Users`、`/Volumes`、`/Network`、`/Applications`、`/Library`、
  `/opt`、`/private` 和 `/dev` 全部重新关闭，只按精确工具链、checkout、
  缓存、输出、macOS 固定 `/private/etc/paths{,.d}` 与
  `/private/var/db/timezone` 等系统输入逐项重开；
  Xcode 位置由验证器固定设置 `DEVELOPER_DIR`，不读取系统选择数据库，只
  额外读取 Xcode 固定的 `Frameworks/SharedFrameworks` 运行时目录。
- 四候选的 `build / qualify / audit` 共 12 个固定命令，每个命令使用新的
  可写隔离区；构建只能写首次为空的当前候选目录，后续步骤只能写本步规定的
  精确文件，可信层还会核对“原有证据字节不变，且只新增本步规定文件”的
  精确差量。旧后台进程最多影响当前步骤或让其失败，不能修改已封存证据、
  其他候选或后续状态。
- 沙箱中的子进程只能从 Apple 系统/Xcode 根目录、预先核验过的精确工具链
  闭包，以及当前一次性隔离区启动；后者只用于执行本步刚编译出的测试程序，
  并继承相同的无网络、无设备、无凭证边界。被审仓库、构建缓存和无关
  Homebrew 内容不可作为程序执行。
- 锁定 PlatformIO 平台和包始终只读，不在可写目录中建立工具链软链接；
  只对原始根目录下 PlatformIO 自身的 `platforms.lock`、`packages.lock`
  两个临时并发锁开放精确写权限。这两个文件不是构建输入，也不进入工具链闭包
  或最终证据。
- ESP-IDF 不再直接使用可能含忽略文件的本机 worktree；外层从锁定提交和
  递归子模块 Git 对象重建只读快照，逐 blob 核对身份，并在 12 个动作结束
  后复核完整闭包。
- 当前 ELF 的原始哈希、去符号语义哈希和能力，在最终只读快照上由本仓库
  代码重新计算。Q0～Q6 七份原始报告也由可信层重算哈希并逐门验收安全语义，
  不接受被审代码自己声明的 `passed` 摘要代替原始事实。
- 每次 `prepare` 都生成新的随机审查挑战；两份报告必须与同目录提示包中的
  目标提交、验证器提交和证据完全一致。`verify` 会重建整个 JSON 提示包并
  逐字节核对两份 Markdown 提示；矩阵结束后再次核对提示和报告快照。同一组
  不可变输入可以重复验证并得到同一结论，但报告不能挪用于不同提交、不同
  验证器或不同证据。
- 任何一项漂移都不产生结果文件；通过结果也始终保持所有硬件权限为
  `false`，命令列表为空。

运行要求：macOS、现有三火项目的锁定离线构建缓存和工具链。代码只使用
Python 标准库。
