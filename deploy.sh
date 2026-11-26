#!/bin/bash
# ClaudeGuard 编译 + 部署到 ~/Applications/ClaudeGuard.app
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/install-launchagent.sh"

# 在同一文件系统准备并签名新版，旧版在此期间继续守护。
mkdir -p "$HOME/Applications"
stage=$(mktemp -d "$HOME/Applications/.ClaudeGuard.XXXXXX")
new="$stage/ClaudeGuard.app"
old="$stage/previous.app"
rollback=false
restore_agent=false
new_installed=false
finish() {
  local status=$?
  if $rollback; then
    if $new_installed; then mv "$APP" "$stage/failed.app" || return 1; fi
    if [[ -d "$old" ]]; then mv "$old" "$APP" || return 1; fi
    if $restore_agent && ! launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
      launchctl bootstrap "$DOMAIN" "$PLIST" || echo "旧版已保留，服务恢复失败。" >&2
    fi
  fi
  rm -rf "$stage"
  return "$status"
}
trap finish EXIT
if [[ -d "$APP" ]]; then
  ditto "$APP" "$new"
else
  mkdir -p "$new/Contents/MacOS"
  cp "$DIR/Info.plist" "$new/Contents/Info.plist"
fi

echo "▶ 编译…"
xcrun swiftc -O -o "$new/Contents/MacOS/ClaudeGuard" "$DIR/main.swift" -framework AppKit -framework SwiftUI
codesign --force -s - "$new"
codesign --verify --strict "$new"

if [[ -f "$PLIST" ]] && launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
  restore_agent=true
fi
rollback=true
stop_guard
if [[ -d "$APP" ]]; then mv "$APP" "$old"; fi
mv "$new" "$APP"
new_installed=true
if $restore_agent; then
  launchctl bootstrap "$DOMAIN" "$PLIST"
  echo "✅ 部署完成，LaunchAgent 已重新加载。"
else
  echo "✅ 部署完成。启动: open \"$APP\""
fi
rollback=false
