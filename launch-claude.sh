#!/bin/bash
# Claude 前门：先确保 ClaudeGuard 在守护且环境 PASS，再放行打开 Claude
# 把它设成你打开 Claude 的唯一入口（Dock 替身 / 快捷指令 / alias），堵住"直接点 Claude 裸奔"
#
#   ./launch-claude.sh          # 检查通过才开 Claude
#   ./launch-claude.sh --force  # 跳过检查强开（应急用）
#   ./launch-claude.sh --check-only  # 只读自检，不启动任何应用

set -o pipefail
APP="$HOME/Applications/ClaudeGuard.app"
GUARD_BIN="$APP/Contents/MacOS/ClaudeGuard"
CHECK_ONLY=false
[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=true

# 真身位置：装了替身后真 Claude 被藏到这里；否则回退原位
HIDDEN_CLAUDE="$HOME/Library/ClaudeGuard/Claude.app"
if [[ -d "$HIDDEN_CLAUDE" ]]; then
  REAL_CLAUDE="$HIDDEN_CLAUDE"
else
  REAL_CLAUDE="/Applications/Claude.app"
fi

open_claude() {
  if /usr/libexec/PlistBuddy -c "Print :ClaudeGuardShim" "$REAL_CLAUDE/Contents/Info.plist" >/dev/null 2>&1; then
    echo "❌ 找不到真实的 Claude.app（$REAL_CLAUDE 是守护替身）" >&2
    exit 1
  fi
  open "$REAL_CLAUDE"
}

if [[ "${1:-}" == "--force" ]]; then
  echo "⚠️  跳过检查，强制打开 Claude"; open_claude; exit 0
fi

fail() {
  echo "$1"
  if ! $CHECK_ONLY && [[ -d "$APP" ]]; then
    echo "   打开 ClaudeGuard 面板点刷新自动修复"
    open "$APP"
  fi
  exit 1
}

[[ -x "$GUARD_BIN" ]] || fail "❌ 环境未通过：找不到 ClaudeGuard.app，请先部署"

guard_daemon_running() {
  ps -axww -o uid=,command= | awk -v uid="$(id -u)" -v bin="$GUARD_BIN" '
    $1 == uid {
      sub(/^ *[0-9]+ +/, "")
      if ($0 == bin || (index($0, bin " ") == 1 && $0 !~ / --(check-core|check-gate|help)( |$)/)) {
        found = 1; exit 0
      }
    }
    END { exit(found ? 0 : 1) }'
}

# 1) 确保 ClaudeGuard 常驻实例在跑（排除并发的 --check-gate / --check-core 诊断子进程）
if ! $CHECK_ONLY && ! guard_daemon_running; then
  echo "▶ ClaudeGuard 未运行，正在启动守护…"
  open "$APP" || fail "❌ 环境未通过：无法启动 ClaudeGuard"
  for ((i=0; i<30; i++)); do
    guard_daemon_running && break
    sleep 0.1
  done
fi

# 2) 即时环境自检（复用 ClaudeGuard 进程内并发硬闸门：TUN + 路由 + Fake-IP + 出口 + IPv6 + STUN + API）
gate_out=$("$GUARD_BIN" --check-gate 2>&1)
if [[ $? -ne 0 ]]; then
  fail "${gate_out:-❌ 环境未通过：未知错误}"
fi

echo "$gate_out"
if ! $CHECK_ONLY; then
  guard_daemon_running || fail "❌ 环境未通过：ClaudeGuard 未处于常驻运行状态"
  open_claude
fi
