#!/usr/bin/env bash
# 環境構築（Linux / macOS）。Windows は docs/SETUP.md の frida16 手順を参照。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FRIDA_VERSION="17.22.2"

log() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
ok()  { printf '   ✅ %s\n' "$*"; }
warn(){ printf '   ⚠️  %s\n' "$*"; }
die() { printf '\n❌ %s\n' "$*" >&2; exit 1; }

log "Python 仮想環境"
if command -v uv >/dev/null 2>&1; then
  uv venv --python 3.12 .venv >/dev/null 2>&1 || uv venv .venv
  uv pip install -p .venv/bin/python -q "frida==${FRIDA_VERSION}"
else
  PY=$(command -v python3 || true)
  [ -n "$PY" ] || die "python3 が見つかりません（3.9+）"
  "$PY" -m venv .venv
  .venv/bin/python -m pip install -q --upgrade pip
  .venv/bin/python -m pip install -q "frida==${FRIDA_VERSION}"
fi
.venv/bin/python -c "import frida; print('   frida', frida.__version__)"
ok "frida ${FRIDA_VERSION} (client)"

log "Frida エージェント"
# 実績のあるバンドルを同梱しているので、通常はそれを使う。
# injected.js を編集したときだけ `./scripts/setup.sh --rebuild` でビルドし直す。
if [ -f agent/agent.iife.js ] && [ "${1:-}" != "--rebuild" ]; then
  ok "同梱の agent/agent.iife.js を使用（再ビルドは ./scripts/setup.sh --rebuild）"
else
  command -v npm >/dev/null 2>&1 || die "--rebuild には npm が必要です"
  ( cd agent && npm install --no-audit --no-fund --silent )
  .venv/bin/python scripts/apply_bridge_patch.py
  .venv/bin/python scripts/build_agent.py
fi
[ -f agent/agent.iife.js ] || die "agent/agent.iife.js がありません"

log "adb"
if [ -n "${ADB_PATH:-}" ] || command -v adb >/dev/null 2>&1; then
  ok "adb: $(command -v adb || echo "$ADB_PATH")"
else
  warn "adb が無いので platform-tools を tools/ に取得します"
  mkdir -p tools
  curl -sSL -o /tmp/platform-tools.zip https://dl.google.com/android/repository/platform-tools-latest-linux.zip
  ( cd tools && rm -rf platform-tools && unzip -q /tmp/platform-tools.zip )
  ok "tools/platform-tools/adb"
fi

log "端末の確認"
ADB_BIN="${ADB_PATH:-$(command -v adb || echo "$ROOT/tools/platform-tools/adb")}"
if "$ADB_BIN" devices | tail -n +2 | grep -q "device"; then
  ok "端末接続済み"
  "$ADB_BIN" shell id | grep -q "uid=0" \
    && ok "adb shell は root（KernelSU / Magisk）" \
    || warn "adb shell が root ではありません。ensure_root で失敗する可能性"
else
  warn "端末が見つかりません。USB デバッグを許可するか、adb connect <ip>:5555 で接続してください"
fi

cat <<'EOS'

────────────────────────────────────────
 セットアップ完了

  ./scripts/run.sh check     # 環境自検
  ./scripts/run.sh list      # offer 一覧（課金しない）
  ./scripts/run.sh step1     # 12ヶ月トライアル
  ./scripts/run.sh step2     # +6ヶ月
  ./scripts/run.sh step3     # +6ヶ月
  ./scripts/run.sh step4     # 予備 +6ヶ月
────────────────────────────────────────
EOS
