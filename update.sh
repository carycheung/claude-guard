#!/bin/bash
# ClaudeGuard 防封策略一键更新
# 把 UPDATE_PROMPT.md 喂给 claude 或 codex，让 AI 重新核对风控信号并更新检测逻辑
#
# 用法:
#   ./update.sh          # 自动选可用的 CLI（优先 claude）
#   ./update.sh codex    # 强制用 codex
#   ./update.sh claude   # 强制用 claude

set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_FILE="$DIR/UPDATE_PROMPT.md"

if [[ ! -f "$PROMPT_FILE" ]]; then
  echo "❌ 找不到 prompt 文件: $PROMPT_FILE"; exit 1
fi

# 选 CLI
PICK="${1:-auto}"
run_claude() { command -v claude >/dev/null 2>&1; }
run_codex()  { command -v codex  >/dev/null 2>&1; }

TOOL=""
case "$PICK" in
  claude) run_claude && TOOL=claude || { echo "❌ 未找到 claude CLI"; exit 1; } ;;
  codex)  run_codex  && TOOL=codex  || { echo "❌ 未找到 codex CLI";  exit 1; } ;;
  auto)
    if run_claude; then TOOL=claude
    elif run_codex; then TOOL=codex
    else echo "❌ claude 和 codex 都没装，装一个再来"; exit 1; fi ;;
  *) echo "用法: $0 [auto|claude|codex]"; exit 1 ;;
esac

echo "▶ 用 $TOOL 更新 ClaudeGuard 防封策略…"
echo "  prompt: $PROMPT_FILE"
echo "───────────────────────────────────────────"

PROMPT_TEXT="$(cat "$PROMPT_FILE")"

case "$TOOL" in
  claude)
    # claude CLI 非交互模式，允许它读写文件+联网+编译
    claude --permission-mode acceptEdits "$PROMPT_TEXT"
    ;;
  codex)
    # codex 非交互执行；--full-auto 放开文件与命令
    codex exec --full-auto "$PROMPT_TEXT"
    ;;
esac

echo "───────────────────────────────────────────"
echo "✅ AI 更新流程结束"

# 更新后自动收尾：编译验证 → 通过才 commit+push（编译失败绝不推坏代码）
cd "$DIR"
if [[ -d .git ]]; then
  if git diff --quiet && git diff --cached --quiet; then
    echo "ℹ️  无改动，跳过提交"
    exit 0
  fi
  echo "▶ 编译验证改动…"
  if xcrun swiftc -O -o ClaudeGuardBin main.swift -framework AppKit -framework SwiftUI 2>/tmp/cg_build.log; then
    echo "✅ 编译通过，提交并推送到 GitHub"
    STAMP="$(date '+%Y-%m-%d %H:%M')"
    git add -A
    git commit -q -m "auto: 防封策略定期更新 ($STAMP)

由 update.sh 自动跑 AI 更新 + 编译验证通过后提交。" || true
    if git push -q origin main 2>/tmp/cg_push.log; then
      echo "✅ 已推送到 origin/main"
    else
      echo "⚠️  push 失败（可能无网络/凭证），改动已本地提交。详见 /tmp/cg_push.log"
    fi
    echo "▶ 部署新版…"; bash "$DIR/deploy.sh" >/dev/null 2>&1 && echo "✅ 已部署" || echo "⚠️ 部署失败，手动跑 ./deploy.sh"
  else
    echo "❌ 编译失败，不提交不推送（保护仓库）。错误详见 /tmp/cg_build.log"
    echo "   本地改动保留，可人工修复后手动提交"
    exit 1
  fi
else
  echo "ℹ️  未启用 git，跳过自动推送"
fi

