#!/bin/bash
# 「偷梁换柱」：把真 Claude 藏起来，原位放一个同名同图标的替身
# 你（和 Dock）点 Claude 时先过 ClaudeGuard 检查，通过才拉起真身
#
#   ./install-shim.sh install    # 装替身（真身移到 ~/Library/ClaudeGuard/Claude.app）
#   ./install-shim.sh uninstall  # 还原真身到 /Applications
#   ./install-shim.sh status

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_PATH="/Applications/Claude.app"
HIDDEN_DIR="$HOME/Library/ClaudeGuard"
HIDDEN_PATH="$HIDDEN_DIR/Claude.app"
LAUNCHER="$DIR/launch-claude.sh"

is_shim() {
  # 替身的 Info.plist 带自定义标记
  [[ -f "$REAL_PATH/Contents/Info.plist" ]] && \
    /usr/libexec/PlistBuddy -c "Print :ClaudeGuardShim" "$REAL_PATH/Contents/Info.plist" >/dev/null 2>&1
}

install_shim() {
  local lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  if is_shim; then
    "$lsregister" -f "$HIDDEN_PATH" 2>/dev/null || true
    echo "✅ 替身已安装"
    return
  fi
  if [[ ! -d "$REAL_PATH" ]]; then echo "❌ 找不到 $REAL_PATH"; exit 1; fi

  echo "▶ 藏起真身 → $HIDDEN_PATH"
  mkdir -p "$HIDDEN_DIR"
  rm -rf "$HIDDEN_PATH"
  mv "$REAL_PATH" "$HIDDEN_PATH"

  echo "▶ 生成替身 app…"
  local C="$REAL_PATH/Contents"
  mkdir -p "$C/MacOS" "$C/Resources"
  # 复制真身图标，保证外观一模一样
  cp "$HIDDEN_PATH/Contents/Resources/electron.icns" "$C/Resources/electron.icns"

  # 替身 Info.plist（自己的 bundle id，避免与真身 id 冲突/递归）
  cat > "$C/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Claude</string>
    <key>CFBundleDisplayName</key><string>Claude</string>
    <key>CFBundleExecutable</key><string>ClaudeShim</string>
    <key>CFBundleIconFile</key><string>electron.icns</string>
    <key>CFBundleIdentifier</key><string>com.claudeguard.shim</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>LSUIElement</key><false/>
    <key>ClaudeGuardShim</key><true/>
</dict>
</plist>
EOF

  # 替身可执行体：调用前门脚本
  cat > "$C/MacOS/ClaudeShim" <<EOF
#!/bin/bash
exec "$LAUNCHER"
EOF
  chmod +x "$C/MacOS/ClaudeShim"

  # 刷新 Launch Services + 图标缓存
  "$lsregister" -f "$HIDDEN_PATH" 2>/dev/null || true
  "$lsregister" -f "$REAL_PATH" 2>/dev/null || true
  touch "$REAL_PATH"
  echo "✅ 替身已就位。以后点 Dock/启动台的 Claude = 先过守护检查再放行真身"
  echo "   真身: $HIDDEN_PATH"
  echo "   ⚠️ Dock 里的旧图标可能需右键移除后从 /Applications 重新拖入以刷新指向"
}

uninstall_shim() {
  if ! is_shim; then echo "当前 $REAL_PATH 不是替身，无需还原"; exit 0; fi
  if [[ ! -d "$HIDDEN_PATH" ]]; then echo "❌ 找不到真身 $HIDDEN_PATH，无法还原"; exit 1; fi
  echo "▶ 删除替身，还原真身…"
  rm -rf "$REAL_PATH"
  mv "$HIDDEN_PATH" "$REAL_PATH"
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$REAL_PATH" 2>/dev/null || true
  echo "✅ 已还原真 Claude 到 $REAL_PATH"
}

case "${1:-}" in
  install)   install_shim ;;
  uninstall) uninstall_shim ;;
  status)
    if is_shim; then echo "替身已装：/Applications/Claude.app 是守护替身，真身在 $HIDDEN_PATH"
    else echo "未安装替身：/Applications/Claude.app 是原版"; fi ;;
  *) echo "用法: $0 {install|uninstall|status}"; exit 1 ;;
esac
