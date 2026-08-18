# ClaudeGuard 防封策略更新任务

你是 ClaudeGuard（macOS 菜单栏防封守护 app）的维护者。你的任务是：**核对最新的 Claude 账号风控信号，把新增的可自动检测项落进 ClaudeGuard 的检测逻辑，并保证改动能编译通过。**

## 背景

ClaudeGuard 是一个 Swift 菜单栏常驻 app，实时守护本机代理环境，一旦"失守"（TUN 关闭 / 出口进受限地区 / Anthropic 拒绝 / 指纹异常）就立即强行断开 Claude 桌面端并自动重试恢复代理。它的判据必须是"可本地自动检测的硬信号"，不是主观建议。

- 源码：`~/ClaudeGuard/main.swift`（单文件，~950 行）
- 编译：`cd ~/ClaudeGuard && xcrun swiftc -O -o ClaudeGuardBin main.swift -framework AppKit -framework SwiftUI`
- 安装：编译产物拷进 `~/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard` 后 ad-hoc 签名
- 日志：`~/ClaudeGuard/guard.log`

## 现有检测项（`checkTemplate` 数组）

1. Claude 应用存在 · 2. Clash Verge 应用存在 · 3. Clash 内核接口 · 4. **TUN 模式（硬门槛，关闭即失守）** · 5. 出口·Cloudflare · 6. 出口复核·ipinfo · 7. IPv6 泄漏 · 8. WebRTC/UDP 泄漏 · 9. Anthropic 放行 · 10. 指纹·时区/语言

`pass = appsOK && tunOK && egressOK && egress2OK && v6OK && stunOK && apiOK`

## 你要做的事

### 1. 重新核对风控信号
读这两个参考源（用 WebFetch 或联网），对比 ClaudeGuard 现有检测项，找出**新增的、可本地自动检测的**风控信号：
- https://fuck-claude.vercel.app/zh/
- https://fuck-claude.vercel.app/zh/guides/

参考站的十项加权指纹模型：时区(24) > 浏览器语言(18) > 中文字体(14) > 国产厂商字体(10) > WebRTC泄露(10) > 国产浏览器(8) > 国产设备(6) > Intl(4) > 时区偏移(3) > Emoji渲染(3)。

**判断标准**：只落"能在 macOS 本地用 shell / 系统 API 自动判定"的信号。例如：
- ✅ 可做：系统字体清单探测（`fc-list` 或 system_profiler 查是否装了微软雅黑/苹方/MiSans）、Accept-Language 请求头、DNS 泄漏、中转 hostname 中性性检查
- ❌ 不做：需要浏览器 canvas 指纹、需要人工判断的主观项、IP 信誉/支付卡 BIN（app 看不到）

### 2. 落地实现
- 在 `main.swift` 的 `checkTemplate` 加对应 `CheckItem`
- 写对应的 `probeXxx()` 探针函数（参考现有 `probeFingerprint()` `probeEgress()` 的写法：用 `sh()` 跑 shell，`.fail` 表示硬失守、`.warn` 表示提醒不拦截）
- 把新的硬信号加进 `pass` 判定和 `quickPass()`（实时守护快检）
- 保持风格：中文注释、`set(id, state, detail)` 更新 UI

### 3. 验证
- 编译必须 exit 0：`cd ~/ClaudeGuard && xcrun swiftc -O -o ClaudeGuardBin main.swift -framework AppKit -framework SwiftUI`
- 如果装了 app，重新拷贝签名部署
- 简述你新增/修改了哪些检测项、为什么，以及哪些参考站信号你判断"无法本地自动检测"故跳过

## 约束
- **不要**破坏现有 10 项检测和实时守护 / 自动重试逻辑
- **不要**加需要用户手动操作的"一键修复"式交互——刷新即自动修复是既定设计
- 改动要小而准，宁可少加一个可靠信号，不要加一堆误报项
- 全程中文回复
