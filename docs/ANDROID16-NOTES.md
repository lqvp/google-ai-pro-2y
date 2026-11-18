# Android 16 / frida 17 で動かすために直したこと

元の `ultra0.py` は「Android 12/13 のエミュレータ + root + frida 16.5.9」を前提に書かれています。
Android 16 の実機（Pixel 7a, KernelSU, frida 17.22.2）では次の 5 点で詰まったので、`ultra0-17.py` と
`agent/` で回避しています。元ファイル `scripts/ultra0.py` は無改変です。

---

## 1. frida 16 系が Android 16 で実用にならない

観測したこと:

- frida-server 16.5.9 / 16.7.19 を起動しても、`device.spawn()` が
  `TimedOutError: unexpectedly timed out while waiting for signal from process` になる
- `device.enumerate_processes()` が `ProcessNotFoundError: unable to find process with name 'system_server'` になる
- 端末側には `magisk-frida` モジュールが 17.22.2 を常駐させており、client 16 とはメジャー不一致

frida 17 の変更点（公式リリースノート）:

- `frida-java-bridge` / `frida-objc-bridge` が GumJS から分離され、**同梱されなくなった**
  → 生の JS を `create_script()` に渡すと `ReferenceError: 'Java' is not defined`
- 対策として REPL/frida-trace は bridge を同梱するが、Python API から使うには自前でバンドルする必要がある

### 対策: bridge を同梱した IIFE エージェントをビルド

```js
// agent/agent.js（自動生成）
import Java from 'frida-java-bridge';
globalThis.Java = Java;
// 以下、元 FRIDA_JS のコード
```

```python
# scripts/build_agent.py
bundle = frida.Compiler().build("agent.js", project_root=AGENT, bundle_format="iife")
```

**`bundle_format="iife"` が必須**です。既定の `esm` は Frida 独自のパッケージ形式
（`📦 ... ✄` ヘッダ付き）になり、Python から文字列で渡すと
`frida.InvalidArgumentError: malformed package` になります。

---

## 2. Android 16 では「Object[] を返す JNI 呼び出し」がブロックする

症状: 注入自体は成功するが、`Java.registerClass()` から戻ってこない（フリーズ）。

切り分け結果（同一プロセスで個別に呼び出し）:

| 呼び出し | 戻り型 | 結果 |
|---|---|---|
| `Class.getName()` | String | OK |
| `Class.isInterface()` | boolean | OK |
| `Class.getSuperclass()` | Class | OK |
| `String.toCharArray()` | char[]（primitive） | OK |
| **`Class.getInterfaces()`** | **Class[]** | **ハング** |
| **`ArrayList.toArray()`** | **Object[]** | **ハング** |
| **`Class.getDeclaredMethods()`** | **Method[]** | **ハング** |

つまり **参照型の配列を返す JNI 呼び出しだけ**が返ってきません
（primitive 配列は OK）。frida-java-bridge は `GetArrayLength` / `GetObjectArrayElement`
（JNIEnv テーブル 171 / 173）を使って配列を JS 配列に変換するため、
ここが Android 16 の ART と噛み合っていないようです。

### 対策: `Java.registerClass` の基底インターフェース展開をスキップ

`registerClass` は生成クラスの前に、実装するインターフェースの **親インターフェースを
`Class.getInterfaces()` で展開**します。Billing のリスナー
（`PurchasesUpdatedListener` / `BillingClientStateListener` / `ProductDetailsResponseListener` /
`PurchasesResponseListener`）は基底インターフェースを持たないので、この展開は不要です。

`agent/injected.js` 側で `skipInterfaceExpansion: true` を渡し、
ブリッジ側（`agent/node_modules/frida-java-bridge/lib/class-factory.js`）でスキップします:

```js
      const allInterfaces = interfaces.slice();
      if (spec.skipInterfaceExpansion !== true) {
        interfaces.forEach(iface => { ... });   // ここだけ従来通り
      }
```

パッチは `scripts/apply_bridge_patch.py` が冪等に適用します
（バージョンは `agent/package.json` で `7.1.0` に固定）。

---

## 3. Android 14+ は「書き込み可能な dex ファイル」を拒否する

```
java.lang.SecurityException: Writable dex file '/data/local/tmp/module_521.apk' is not allowed.
```

`DexClassLoader` に渡す計費モジュール APK が書き込み可能だと弾かれます。
`adb push` 直後は 0666 なので、**444 に落とす**必要があります。

`ultra0-17.py` では `ensure_module_apk()` で push 後に自動で `chmod 444` します。

---

## 4. 收銀台の UI 文言が日本語だと判定できない

元の `confirm_zero()` は中国語（`订阅` / `免费试用`）と英語（`Subscribe`）だけを見ていました。
日本語ロケールでは:

- ボタン: 「定期購入」「登録する」
- 通貨: `￥0` / `JP¥0`（元の正規表現は `$` `€` `£` などで `¥` が無い）
- 期間: 「12か月間の無料トライアル」

`ultra0-17.py` では判定を ja/en/zh のニードル + `¥` 対応に拡張し、
`Button` クラスを優先してタップする `tap_button()` を追加しています。
また失敗時に画面テキストをログへ出すようにしました。

---

## 5. その他の実務的な修正

- **アプリ起動待ち**: 7 秒固定 → `pidof` を 20 秒ポーリング（`app_not_started` 対策）
- **メッセージ型ガード**: ブリッジのデバッグ `send("reg:...")` のような文字列 payload で
  `AttributeError: 'str' object has no attribute 'get'` にならないよう `on_msg` をガード
- **frida-server のバージョン整合**: クライアント 17.22.2 に合わせる。
  モジュール常駐と衝突する場合は `scripts/fix_frida.sh`

---

## 端末側で観測した副作用

- KernelSU + LSPosed + Android 16 の実機で、Frida 注入を何度も繰り返すと
  **ブートアニメーションで止まる**ことが数回ありました（電源長押しで復帰、サブスク状態は無事）
- USB 接続が時々落ちる（ハブ経由）。Wi-Fi ADB（`adb tcpip 5555`）を併用すると安定

再現性のため、必要な作業が終わったら `pkill -x frida-server` と
`magisk-frida` モジュールの無効化を推奨します。
