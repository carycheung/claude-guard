#!/bin/bash
# 安装/卸载「定期防封策略更新」的 LaunchAgent
# 每周一次自动跑 update.sh，把最新风控信号更新进 ClaudeGuard
#
#   ./subscribe.sh install    # 安装（默认每周一 10:00）
#   ./subscribe.sh uninstall  # 卸载
#   ./subscribe.sh status     # 查看状态
#   ./subscribe.sh run-now     # 立即手动跑一次

set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="com.claudeguard.update"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$DIR/update.log"

install_agent() {
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$DIR/update.sh</string>
        <string>auto</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>HOME</key>
        <string>$HOME</string>
    </dict>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key><integer>1</integer>
        <key>Hour</key><integer>10</integer>
        <key>Minute</key><integer>17</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>$LOG</string>
    <key>StandardErrorPath</key>
    <string>$LOG</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
EOF
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST"
  echo "✅ 已安装定期更新：每周一 10:17 自动跑一次"
  echo "   plist: $PLIST"
  echo "   日志:  $LOG"
}

case "${1:-}" in
  install)   install_agent ;;
  uninstall) launchctl unload "$PLIST" 2>/dev/null || true; rm -f "$PLIST"; echo "✅ 已卸载定期更新" ;;
  status)
    if [[ -f "$PLIST" ]]; then
      echo "已安装: $PLIST"
      launchctl list | grep "$LABEL" || echo "（未加载，重新 install）"
    else echo "未安装"; fi ;;
  run-now)   echo "▶ 立即跑一次…"; bash "$DIR/update.sh" auto ;;
  *) echo "用法: $0 {install|uninstall|status|run-now}"; exit 1 ;;
esac
