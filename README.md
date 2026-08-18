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

- 后台每 5 秒实时体检,任何一项不达标 → **立即 terminate 掉 Claude 进程**,不给裸奔的窗口;
- 掐断后自动尝试修复(拉起代理内核 / 开 TUN / 切节点 / 验证出口),最多重试 3 次;
- 菜单栏图标一眼看状态:绿盾=安全守护中,红盾=已失守并掐断,灰=检测中。

## 检测项(硬闸门)

`PASS = 应用在 && TUN开 && 出口非受限地区 && 双源出口一致 && 无 IPv6 泄漏 && 无 WebRTC/UDP 泄漏 && Anthropic API 放行`

| 检测项 | 说明 |
|---|---|
| Claude / 代理应用存在 | 基本前提 |
| 代理内核接口响应 | 通过 mihomo 的 unix socket 通信 |
| **TUN 模式(硬门槛)** | 最关键——流量必须真的进隧道,不是「设了系统代理但没接管」 |
| 出口 · Cloudflare trace | 拿到出口国家 + IP,拒绝受限地区 |
| 出口复核 · ipinfo | 第二个源交叉验证(复核源宕机只告警不误杀) |
| IPv6 泄漏 | `curl -6` 看有没有从真实 v6 出口漏出去 |
| WebRTC / UDP 泄漏 | 自写 STUN 探针,UDP 出口 IP 必须 == HTTP 出口 IP |
| Anthropic 放行 | 空 POST `api.anthropic.com`,返回 `authentication_error` = 通 |
| 指纹 · 时区/语言 | 读系统时区 + 首选语言,中文环境给出告警(见 ANTI-BAN.md) |

## 制作逻辑(架构)

单文件 SwiftUI + AppKit,菜单栏常驻(`LSUIElement`),没有主窗口。几个关键设计决策,踩过坑才定下来的:

- **判据是「出口国家 + API 放行」,不是「能不能 ping 通」。** 受限地区的线路往往 ping 得通但一样被风控,连通性是假信号。
- **实时守护必须查 TUN,而且 TUN 是 pass 的硬条件。** 早期版本快速体检只查出口和 API、TUN 只做告警不进判定,结果手动关掉 TUN 仍显示 PASS——这是最严重的 bug。现在快检第一行就是 `TUN != on → 立即失守`。
- **失守 = 先掐断,再修复。** 用 `NSRunningApplication.terminate/forceTerminate` 秒杀 Claude 进程;然后同步重试修复最多 3 次,而不是「修一次就算了」。
- **单一控制面。** 用户只碰 ClaudeGuard,不碰底层代理 GUI。改 TUN 时同步把配置文件也写一遍,避免「内核开了但 GUI 还显示关」的漂移困惑。
- **大输出要先读完再等进程退出。** 读代理的 `/proxies`(几十 KB)时,必须先 `readDataToEndOfFile` 再 `waitUntilExit`,否则 64KB 管道缓冲会死锁。
- **菜单栏面板手动定位。** `NSPopover` 锚定不可靠,改成手动 `NSPanel` 按屏幕坐标钉在图标正下方。
- **通知用应用自身投递**,这样通知有正确的 app 图标、点击能直接打开面板(用 `osascript` 发的通知会被归到「脚本编辑器」名下,点了跳到别的地方)。

## 三个配套脚本

| 脚本 | 作用 |
|---|---|
| `deploy.sh` | 编译 `main.swift` → 拷进 `.app` bundle → ad-hoc 签名 |
| `install-shim.sh` | **替身拦截**:把真 Claude 藏起来,原位放一个同名同图标的替身,点击时先过守护检查、通过才拉起真身——堵住「没开 ClaudeGuard 就直接点 Claude」的裸奔缺口 |
| `subscribe.sh` | 装一个每周自动跑的 LaunchAgent,让 AI 定期重核防封信号并更新检测逻辑 |
| `update.sh` + `UPDATE_PROMPT.md` | 把 prompt 喂给 `claude` 或 `codex` CLI,让 AI 自主重读风控信号→更新代码→编译验证→通过才提交 |

替身方案的巧思:真身用 Electron 的 Squirrel 就地更新机制,藏到 `~/Library` 后照常能自动更新;删掉替身不影响真身;替身有独立 bundle ID,不会和真身冲突或递归。`launch-claude.sh` 是 **fail-closed** 的——检查出错默认**不**放行。

## 构建 & 运行

```bash
# 依赖: macOS + Xcode command line tools + Clash Verge Rev (mihomo 内核)
git clone <this-repo> && cd claude-guard
./deploy.sh                       # 编译 + 部署到 ~/Applications/ClaudeGuard.app
open ~/Applications/ClaudeGuard.app

# 可选: 装替身拦截 / 每周自动更新
./install-shim.sh install
./subscribe.sh install
```

二进制不入库(可从源码复现),clone 后跑 `./deploy.sh` 现编即可。

## 依赖

- macOS + Xcode command line tools(`swiftc`)
- [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev)(mihomo 内核,unix socket `/tmp/verge/verge-mihomo.sock`)
- 仅「定期更新」功能需要 `claude` 或 `codex` CLI

## License

MIT — 见 [LICENSE](./LICENSE)。
