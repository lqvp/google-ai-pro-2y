#!/usr/bin/env python3
"""agent/iife バンドルをビルドする。

- agent/injected.js（元 FRIDA_JS に skipInterfaceExpansion を足したもの）
- frida-java-bridge を import して globalThis.Java に載せる
- Frida の独自パッケージ形式ではなく IIFE で出力する
  （esm 形式だと Script.create_script() が "malformed package" で失敗する）
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent"


def main() -> int:
    injected = (AGENT / "injected.js").read_text(encoding="utf-8")
    entry = (
        "// 自動生成: scripts/build_agent.py（直接編集しない。agent/injected.js を編集する）\n"
        "import Java from 'frida-java-bridge';\n"
        "globalThis.Java = Java;\n\n"
        + injected
    )
    (AGENT / "agent.js").write_text(entry, encoding="utf-8")

    try:
        import frida
    except ImportError:
        print("frida (python) がありません。scripts/setup.sh を先に実行してください", file=sys.stderr)
        return 1

    if not (AGENT / "node_modules" / "frida-java-bridge").is_dir():
        print("agent/node_modules がありません。agent/ で `npm install` を実行してください", file=sys.stderr)
        return 1

    compiler = frida.Compiler()
    bundle = compiler.build("agent.js", project_root=str(AGENT), bundle_format="iife")
    out = AGENT / "agent.iife.js"
    out.write_text(bundle, encoding="utf-8", newline="")
    print(f"built {out.relative_to(ROOT)} ({len(bundle)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
