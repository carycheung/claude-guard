# ClaudeGuard 🛡️

> A macOS menu-bar guardian that keeps your Claude traffic behind a proxy — and hard-cuts Claude the instant the tunnel drops.
>
> 一个常驻 macOS 菜单栏的守护小工具：**只在「流量确实走代理」时才让 Claude 运行,一旦隧道掉了立刻掐断 Claude**,避免真实 IP 裸奔。

本仓库是**开源版**,记录整个应用的制作逻辑与一套 Claude 防封号心得。防封号的策略与取舍单独写在 [`ANTI-BAN.md`](./ANTI-BAN.md)。

⚠️ **免责声明**:本项目用于保护自己账号的网络环境卫生(避免真实 IP / 泄漏导致的风控),不含任何绕过实名、伪造身份、批量注册等内容。请遵守 Anthropic 服务条款。

---

## 它解决什么问题

如果你在受限网络环境用代理访问 Claude,最怕的不是「连不上」,而是**代理悄悄掉线而你不知道**——TUN 关了、节点断了、DNS/WebRTC 泄漏,流量从真实 IP 出去,风控立刻记一笔。人眼根本盯不过来。

ClaudeGuard 把这件事自动化成一个**硬闸门**:

- 启动和每次全检先检查内核 socket、TUN、代理模式、IPv4/IPv6 路由和 Fake-IP DNS。本地检查失败时先退出受管进程，确认退出后才允许修复。公网探测只在本地检查通过后开始，结束时还会复核隧道和受管进程。
- 开启守护时，合盖休眠前同步退出正在运行的 Claude。唤醒立即做本地检查并安排全检。Claude 原本已退出时，休眠回调保持静默。
- 网卡或路由变化立即触发进程内本地隧道检查；本地通过且物理网卡、隧道、DNS 与生效节点签名未变（如 iOS 模拟器虚拟网桥、AirDrop 抖动）时静默忽略，真实网络/节点变更防抖 0.4 秒后并发复检。平时保留 5 秒纯本地心跳（零子进程、零公网轮询）；直连模式暂停事件守护。受管路径包括当前用户的 ShipIt 更新缓存和临时解包目录。
- 掐断后自动尝试修复(拉起代理内核 / 开 TUN / 验证当前线路 / 必要时切节点),最多重试 3 次;失败后冷却 5 分钟,期间仍检测和拦截;
- 菜单栏图标一眼看状态:绿盾=安全守护中,红盾=已失守并掐断,灰=检测中。

## 检测项(硬闸门)

通过需要本地隧道、出口地区、IPv6 和 API 检查达标。复核源不可达、两源 IP 不同，或 UDP 出口不一致且未判定为受限地区时，只给出提醒。

| 检测项 | 说明 |
|---|---|
| Claude / 代理应用存在 | 基本前提 |
| 代理内核接口响应 | 通过 mihomo 的 unix socket 通信 |
| **TUN 模式(硬门槛)** | 最关键——流量必须真的进隧道,不是「设了系统代理但没接管」 |
| 出口 · Cloudflare trace | 拿到出口国家 + IP,拒绝受限地区 |
| 出口复核 · ipinfo | 复核地区，来源不可达或 IP 不一致时提醒 |
| IPv6 泄漏 | `Network.framework` 强制直连公网 IPv6 字面量探测出口,防 Fake-IPv4 映射假阳性 |
| WebRTC / UDP 泄漏 | 用 STUN 比较 UDP 和 HTTP 出口，发现不同出口时再查 UDP 出口地区 |
| Anthropic 放行 | 空 POST `api.anthropic.com`,返回 `authentication_error` = 通 |
| 指纹 · 时区/语言 | 读系统时区 + 首选语言,中文环境给出告警(见 ANTI-BAN.md) |

## 制作逻辑(架构)

单文件 SwiftUI + AppKit,菜单栏常驻(`LSUIElement`),没有主窗口。几个关键设计决策,踩过坑才定下来的:

- **判据是「出口国家 + API 放行」,不是「能不能 ping 通」。** 受限地区的线路往往 ping 得通但一样被风控,连通性是假信号。
- **实时守护必须查 TUN,而且 TUN 是 pass 的硬条件。** 早期版本快速体检只查出口和 API、TUN 只做告警不进判定,结果手动关掉 TUN 仍显示 PASS——这是最严重的 bug。现在快检第一行就是 `TUN != on → 立即失守`。
- **失守 = 先掐断,再修复。** 通过 AppKit 请求 Claude 退出,同时向当前用户的受管 Claude 进程(含官方 Claude Code CLI)发送 `SIGTERM`,宽限期后强制终止残留进程,再同步重试修复最多 3 次。切直连前确认 App 和受管进程全部退出,超时则保留代理和 TUN。
- **单一控制面。** 用户只碰 ClaudeGuard,不碰底层代理 GUI。改 TUN 时同步把配置文件也写一遍,避免「内核开了但 GUI 还显示关」的漂移困惑。
- **全链路零子进程（Zero-Subprocess）与高负载防误杀。** 内核接口走原生非阻塞 `AF_UNIX` socket（兼容 `Content-Length` 与 `chunked`），路由检查走内核 `SOCK_DGRAM` 选路表并校验目标 `utun` 设备一致，DNS 检查直连 `mDNSResponder`（`dnssd` + `poll`），系统 DNS 与网关复用常驻 `SCDynamicStore`，公网探测走 `URLSession` + `NWConnection` 五路并发（全检约 1 秒完成）。后台队列通过 `OSAllocatedUnfairLock` 同步状态机，零 `DispatchQueue.main.sync` 阻塞；当内核 `utun` 路由确认在位时，对交换内存（Swap）或瞬时丢包导致的单次超时自动做即时复核，而对真实失守或 `403` 地区封锁零重试立即断连。
- **自动识别内核接口。** 优先当前 UID 的 service socket,兼容旧版 `/tmp/verge/verge-mihomo.sock`;候选接口先通过 `/configs` 验证,缓存失效后重新发现。前门脚本复用 `--check-gate` 同一套进程内并发闸门,常驻进程以内核文件锁保证单实例。
- **状态未知与 TUN 关闭分别显示。** 无法读取接口时仍不放行 Claude,但提示真实原因,不宣称 TUN 已关闭。
- **快检纯本地、全检并发复核。** 5 秒心跳复用单次本地快照校验隧道与代理生效节点链（节点未变时零主线程唤醒），节点变更立即触发并发全检，稳态每 5 分钟静默复核；远端线路异常时按 5 分钟冷却自动自愈并优先恢复 `Auto/Fallback` 组。面板按需懒加载并同步读取 `fittingSize` 精确定位。
- **菜单栏面板手动定位。** `NSPopover` 锚定不可靠,改成手动 `NSPanel` 按屏幕坐标钉在图标正下方。
- **通知用应用自身投递**,这样通知有正确的 app 图标、点击能直接打开面板(用 `osascript` 发的通知会被归到「脚本编辑器」名下,点了跳到别的地方)。

## 配套脚本

| 脚本 | 作用 |
|---|---|
| `deploy.sh` | 编译 `main.swift` → 拷进 `.app` bundle → ad-hoc 签名 |
| `install-launchagent.sh` | 管理登录自启与崩溃重启，支持 `install`、`uninstall`、`status` |
| `install-shim.sh` | **替身拦截**:把真 Claude 藏起来,原位放一个同名同图标的替身,点击时先过守护检查、通过才拉起真身——堵住「没开 ClaudeGuard 就直接点 Claude」的裸奔缺口 |
| `subscribe.sh` | 装一个每周自动跑的 LaunchAgent,让 AI 定期重核防封信号并更新检测逻辑 |
| `update.sh` + `UPDATE_PROMPT.md` | 把 prompt 喂给 `claude` 或 `codex` CLI,让 AI 自主重读风控信号→更新代码→编译验证→通过才提交 |

全检查找 Claude 真身时依次检查 `~/Library/ClaudeGuard/Claude.app`、`/Applications/Claude.app` 和 LaunchServices。前门脚本检查前两个路径，并在本次检查和常驻实例均确认成功后打开 Claude。显式传入 `--force` 可跳过检查。

## 构建 & 运行

```bash
# 依赖: macOS + Xcode command line tools + Clash Verge Rev (mihomo 内核)
git clone <this-repo> && cd claude-guard
./deploy.sh                       # 编译 + 部署到 ~/Applications/ClaudeGuard.app
open ~/Applications/ClaudeGuard.app

# 可选：由 launchd 登录自启，并在异常退出时重启
./install-launchagent.sh install

# 可选：装替身拦截 / 每周自动更新
./install-shim.sh install
./subscribe.sh install
```

LaunchAgent 安装时会移除旧的 ClaudeGuard 登录项。异常退出由 launchd 重启，重启节流间隔为 2 秒；菜单栏正常退出后保持退出。重复启动会在创建菜单栏图标前结束，诊断命令仍可单独运行。更新时先签名新版，再替换应用并重新加载之前正在运行的 LaunchAgent。首次构建所需的应用元数据来自仓库内的 `Info.plist`。

二进制不入库(可从源码复现),clone 后跑 `./deploy.sh` 现编即可。

## 依赖

- macOS + Xcode command line tools(`swiftc`)
- [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev)(mihomo 内核;自动识别 `/var/run/clash-verge-service/users/<UID>/verge-mihomo.sock`,兼容旧路径)
- 仅「定期更新」功能需要 `claude` 或 `codex` CLI

## 验证与排障

```bash
python3 -B -m unittest discover -s tests -v  # 临时 Unix socket 与假进程回归测试
~/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard --check-core
~/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard --check-gate
./launch-claude.sh --check-only    # 只读检查 TUN、路由、Fake-IP、出口、IPv6、STUN、API,不打开 Claude
```

`--check-core` 输出 JSON: `tun=true` 表示开启,`false` 表示关闭,`null` 表示未知;关闭或未知返回非零退出码。`--check-gate` 执行完整无界面并发硬闸门自检。诊断命令均不启动 UI、不自动修复、不改变代理。日志记录选中的 socket 和检查未通过的原因。

## License

MIT — 见 [LICENSE](./LICENSE)。
