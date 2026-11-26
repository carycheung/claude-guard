#!/bin/bash
set -euo pipefail
LABEL=com.claudeguard.app
DOMAIN="gui/$(id -u)"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
APP="$HOME/Applications/ClaudeGuard.app"
BIN="$APP/Contents/MacOS/ClaudeGuard"

# bootout 后也可能有 Login Item 或手动启动的实例。只匹配本用户的已部署可执行文件。
guard_pids() {
  ps -axww -o uid=,pid=,comm= | awk -v uid="$(id -u)" -v exe="$BIN" '
    $1 == uid { pid=$2; sub(/^ *[0-9]+ +[0-9]+ +/, ""); if ($0 == exe) print pid }'
}

stop_guard() {
  local pid i
  if launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
    launchctl bootout "$DOMAIN/$LABEL"
  fi
  for pid in $(guard_pids); do kill -TERM "$pid" 2>/dev/null || true; done
  for ((i=0; i<50; i++)); do
    [[ -n "$(guard_pids)" ]] || return 0
    sleep 0.1
  done
  echo "ClaudeGuard 仍在运行，已中止操作。" >&2
  return 1
}

write_plist() {
  cat > "$1" <<'PLIST_XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.claudeguard.app</string>
  <key>ProgramArguments</key><array/>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>2</integer>
</dict></plist>
PLIST_XML
  /usr/bin/plutil -insert ProgramArguments.0 -string "$BIN" "$1"
  /usr/bin/plutil -lint "$1" >/dev/null
}

install_agent() (
  [[ -x "$BIN" ]] || { echo "找不到已部署的 $BIN" >&2; exit 1; }
  mkdir -p "$(dirname "$PLIST")"
  local tmp
  tmp=$(mktemp "${PLIST}.XXXXXX")
  trap 'rm -f "$tmp"' EXIT
  write_plist "$tmp"
  osascript <<'APPLESCRIPT'
tell application "System Events"
    if exists login item "ClaudeGuard" then delete login item "ClaudeGuard"
end tell
APPLESCRIPT
  stop_guard
  mv -f "$tmp" "$PLIST"
  launchctl bootstrap "$DOMAIN" "$PLIST"
  echo "已安装 ClaudeGuard 登录自启与崩溃重启。"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    install) install_agent ;;
    uninstall)
      if launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
        launchctl bootout "$DOMAIN/$LABEL"
      fi
      rm -f "$PLIST"
      echo "已卸载 ClaudeGuard LaunchAgent。"
      ;;
    status)
      if [[ -f "$PLIST" ]]; then echo "配置已安装：$PLIST"; else echo "配置未安装"; fi
      if ! launchctl print "$DOMAIN/$LABEL"; then echo "服务未加载"; fi
      ;;
    *) echo "用法: $0 {install|uninstall|status}" >&2; exit 2 ;;
  esac
fi
