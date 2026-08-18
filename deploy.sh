#!/bin/bash
# ClaudeGuard 编译 + 部署到 ~/Applications/ClaudeGuard.app
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HOME/Applications/ClaudeGuard.app"

echo "▶ 编译…"
cd "$DIR"
xcrun swiftc -O -o ClaudeGuardBin main.swift -framework AppKit -framework SwiftUI

echo "▶ 部署到 $APP …"
# 若 app 在运行先退出
pkill -f "ClaudeGuard.app/Contents/MacOS/ClaudeGuard" 2>/dev/null || true
sleep 1
cp ClaudeGuardBin "$APP/Contents/MacOS/ClaudeGuard"

echo "▶ ad-hoc 签名…"
codesign --force --deep -s - "$APP"

echo "✅ 部署完成。启动: open \"$APP\""
echo "   查看 UI: \"$APP/Contents/MacOS/ClaudeGuard\" --show"
