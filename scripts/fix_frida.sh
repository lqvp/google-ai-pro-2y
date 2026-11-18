#!/usr/bin/env bash
# frida クライアント(17.x)と端末側 frida-server の不一致を直す。
# 端末の /data/local/tmp/frida-server を退避し、次回実行時に 17.22.2 を自動配置させる。
set -euo pipefail
ADB_BIN="${ADB_PATH:-$(command -v adb || echo "$(cd "$(dirname "$0")/.." && pwd)/tools/platform-tools/adb")}"

echo "▶ 現在の frida-server"
"$ADB_BIN" shell 'ls -l /data/local/tmp/frida-server 2>/dev/null || echo none'
"$ADB_BIN" shell 'pidof frida-server >/dev/null && /proc/$(pidof frida-server)/exe --version 2>/dev/null || true'

echo "▶ 停止して退避"
"$ADB_BIN" shell 'pkill -x frida-server 2>/dev/null || true'
"$ADB_BIN" shell 'mv /data/local/tmp/frida-server /data/local/tmp/frida-server.bak.$(date +%s) 2>/dev/null || true'
"$ADB_BIN" shell 'ls /data/local/tmp/ | grep frida || echo "(frida-server なし = 次回自動ダウンロード)"'

cat <<'EOS'

KernelSU/Magisk モジュール（magisk-frida 等）が起動時に別バージョンを
起動している場合は、そのモジュールの bin/ を 17.22.2 に差し替えるか
モジュールを無効化してください（/data/adb/modules/magisk-frida）。
EOS
