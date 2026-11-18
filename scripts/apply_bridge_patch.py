#!/usr/bin/env python3
"""frida-java-bridge に「基底インターフェース展開のスキップ」パッチを当てる。

Android 16 では Class.getInterfaces() など Object[] を返す JNI 呼び出しが
ブロックし、Java.registerClass() が永久にハングする。
Billing のリスナー（PurchasesUpdatedListener など）は基底インターフェースを
持たないので、この展開をスキップしても実害がない。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "agent" / "node_modules" / "frida-java-bridge" / "lib" / "class-factory.js"

ORIGINAL = """      const allInterfaces = interfaces.slice();
      interfaces.forEach(iface => {
        Array.prototype.slice.call(iface.class.getInterfaces())
          .forEach(baseIface => {
            const baseIfaceName = this.cast(baseIface, Class).getCanonicalName();
            allInterfaces.push(this.use(baseIfaceName));
          });
      });"""

PATCHED = """      const allInterfaces = interfaces.slice();
      // --- patch: skipInterfaceExpansion ---
      // Android 16 では Class.getInterfaces() がブロックするため、
      // spec.skipInterfaceExpansion === true のとき展開しない。
      if (spec.skipInterfaceExpansion !== true) {
        interfaces.forEach(iface => {
          Array.prototype.slice.call(iface.class.getInterfaces())
            .forEach(baseIface => {
              const baseIfaceName = this.cast(baseIface, Class).getCanonicalName();
              allInterfaces.push(this.use(baseIfaceName));
            });
        });
      }"""


def main() -> int:
    if not TARGET.exists():
        print(f"not found: {TARGET}（先に agent/ で npm install）", file=sys.stderr)
        return 1
    src = TARGET.read_text(encoding="utf-8")
    if "skipInterfaceExpansion" in src:
        print("already patched")
        return 0
    if ORIGINAL not in src:
        print("patch target not found (frida-java-bridge のバージョン違い？)", file=sys.stderr)
        return 1
    TARGET.write_text(src.replace(ORIGINAL, PATCHED, 1), encoding="utf-8")
    print(f"patched {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
