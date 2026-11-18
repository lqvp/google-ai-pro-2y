#!/usr/bin/env bash
# 使い方: ./scripts/run.sh <command>
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ -x .venv/bin/python ] || { echo "先に ./scripts/setup.sh を実行してください" >&2; exit 1; }
PY=.venv/bin/python

if [ -z "${ADB_PATH:-}" ]; then
  if [ -x "$ROOT/tools/platform-tools/adb" ]; then
    export ADB_PATH="$ROOT/tools/platform-tools/adb"
  elif command -v adb >/dev/null 2>&1; then
    export ADB_PATH="$(command -v adb)"
  fi
fi
export PYTHONIOENCODING=utf-8

ACC=("--account" "current@device" "--no-add" "--force")
run17() { exec "$PY" scripts/ultra0-17.py "${ACC[@]}" "$@"; }

case "${1:-}" in
  check)  exec "$PY" scripts/ultra0-17.py --check ;;
  list)   run17 --list --plan pro12 ;;
  step1)  run17 --plan pro12 ;;
  step2)  run17 --stack --plan pro6 ;;
  step3)  run17 --stack --plan pro6b ;;
  step4)  run17 --stack --plan pro6c ;;
  build-agent) exec "$PY" scripts/build_agent.py ;;
  fix-frida)   exec ./scripts/fix_frida.sh ;;
  setup)  exec ./scripts/setup.sh ;;
  *)
    cat <<'EOS'
使い方: ./scripts/run.sh <command>

  setup        環境構築（初回のみ）
  check        環境自検（端末/root/frida/課金モジュール）
  list         offer 一覧を表示（課金しない・ゼロリスク）
  step1        12ヶ月無料トライアル
  step2        +6ヶ月（step1 成功後）
  step3        +6ヶ月（step2 成功後）
  step4        予備 +6ヶ月（エラーになる場合あり）
  build-agent  エージェント再ビルド
  fix-frida    frida-server のバージョン不一致を解消
EOS
    exit 1 ;;
esac
