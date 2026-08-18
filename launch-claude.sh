#!/bin/bash
# Claude 前门：先确保 ClaudeGuard 在守护且环境 PASS，再放行打开 Claude
# 把它设成你打开 Claude 的唯一入口（Dock 替身 / 快捷指令 / alias），堵住"直接点 Claude 裸奔"
#
#   ./launch-claude.sh          # 检查通过才开 Claude
#   ./launch-claude.sh --force  # 跳过检查强开（应急用）

set -o pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HOME/Applications/ClaudeGuard.app"
GUARD_BIN="$APP/Contents/MacOS/ClaudeGuard"
CLAUDE_BUNDLE="com.anthropic.claudefordesktop"
SOCK="/tmp/verge/verge-mihomo.sock"
BLOCKED="CN HK MO RU"

# 真身位置：装了替身后真 Claude 被藏到这里；否则回退原位
HIDDEN_CLAUDE="$HOME/Library/ClaudeGuard/Claude.app"
if [[ -d "$HIDDEN_CLAUDE" ]]; then
  REAL_CLAUDE="$HIDDEN_CLAUDE"
else
  REAL_CLAUDE="/Applications/Claude.app"
fi

open_claude() { open "$REAL_CLAUDE"; }

if [[ "${1:-}" == "--force" ]]; then
  echo "⚠️  跳过检查，强制打开 Claude"; open_claude; exit 0
fi

# 1) 确保 ClaudeGuard 在跑（没跑就拉起）
if ! pgrep -f "ClaudeGuard.app/Contents/MacOS/ClaudeGuard" >/dev/null 2>&1; then
  echo "▶ ClaudeGuard 未运行，正在启动守护…"
  [[ -x "$GUARD_BIN" ]] && open "$APP" || { echo "❌ 找不到 ClaudeGuard.app，先跑 ./deploy.sh"; exit 1; }
  sleep 4
fi

# 2) 即时环境自检（不依赖 app 心跳，前门自己查一遍硬信号）
fail() { echo "❌ 环境未通过：$1"; echo "   打开 ClaudeGuard 面板点刷新自动修复，或 --force 强开（不建议）"; open "$APP"; exit 1; }

# TUN 必须开
tun=$(curl -s --max-time 5 --unix-socket "$SOCK" http://localhost/configs 2>/dev/null \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('tun',{}).get('enable',False))" 2>/dev/null)
tun="${tun:-}"
[[ "$tun" == "True" ]] || fail "TUN 未开启（流量可能裸奔）"

# 出口非受限地区
loc=$(curl -s --max-time 6 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | sed -n 's/^loc=//p' | tr -cd 'A-Za-z')
loc="${loc:-}"
[[ -n "$loc" ]] || fail "无法获取出口信息"
for b in $BLOCKED; do [[ "$loc" == "$b" ]] && fail "出口 $loc 属受限地区"; done

# Anthropic 放行（空 POST 返回 authentication_error 即地区可用）
resp=$(curl -s --max-time 8 -X POST https://api.anthropic.com/v1/messages -H 'content-type: application/json' -d '{}' 2>/dev/null)
resp="${resp:-}"
echo "$resp" | grep -q "authentication_error" || fail "Anthropic 未放行（可能被地区拦截）"

echo "✅ 环境通过（出口 $loc，TUN 开，API 放行），打开 Claude"
open_claude
