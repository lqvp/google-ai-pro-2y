# トラブルシューティング

実際に踏んだエラーを中心にまとめています。

## 環境・接続

### `没有检测到设备` / `adb devices` が空

- USB デバッグの許可ダイアログを端末で押したか
- ケーブルが充電専用でないか
- ハブ経由だと不安定なことがある → 直挿し、または Wi-Fi ADB:
  ```bash
  adb tcpip 5555
  adb connect <端末IP>:5555
  ```

### `设备没有 root 权限`

- KernelSU / Magisk / APatch のいずれかが必要
- `adb shell id` が `uid=0` か確認
- エミュレータなら「ROOT 権限」を ON にして再起動、または `adb root`

### 端末がブートアニメーションで止まる（実機）

Frida を長時間/連続で動かした後に入ることがありました。

1. 電源 10 秒長押しで強制再起動
2. それでもループする場合: 電源 + 音量下げ で fastboot → Start
3. セーフモード（Google ロゴで音量下げ長押し）でモジュールを無効化して復帰

サブスク状態はサーバー側に残るので、購入済みなら失われません。

## Frida

### `unable to communicate with remote frida-server; please ensure that major versions match`

client と端末側 frida-server のメジャー不一致。

```bash
./scripts/run.sh fix-frida
```

`/data/local/tmp/frida-server` を退避します。次回実行時に 17.22.2 を自動取得します。
`magisk-frida` モジュールが常駐している場合は、その `bin/frida-server` を 17.x に
差し替えるか、モジュールを無効化してください。

### `malformed package`

`Script.create_script()` に渡すバンドルが Frida の `esm` 形式になっている。
`scripts/build_agent.py` は `bundle_format="iife"` を使います。再ビルドしてください。

### `ReferenceError: 'Java' is not defined`

frida 17 は Java bridge を同梱しません。`agent/agent.iife.js`（bridge 同梱）を使ってください。
`agent/agent.js` を直接注入していないか確認。

### 注入後に何も起きない（`boot_start` だけ出て止まる）

Android 16 の `Java.registerClass` ハング。`agent/injected.js` の各 `Java.registerClass` に
`skipInterfaceExpansion: true` を付けてエージェントを再ビルドしてください。

### `Writable dex file '/data/local/tmp/module_521.apk' is not allowed.`

```bash
adb shell chmod 444 /data/local/tmp/module_521.apk
```

`ultra0-17.py` は push 後に自動で実行します。手動で push した場合は個別に。

## 課金・オファー

### `app_not_started`

Google One が 7 秒以内に起動しなかった。`ultra0-17.py` は 20 秒ポーリングで改善済み。
それでも出る場合は端末が重い/ダイアログが残っているので、`adb shell input keyevent BACK` で
前面のダイアログを閉じてから再実行。

### `收銀台が検出できませんでした`（收銀台の文字が取れない）

- 端末の言語が想定外 → `ultra0-17.py` は ja/en/zh に対応。それ以外の言語なら
  `SUB_NEEDLES` / `INELIGIBLE_NEEDLES` / `PRICE_PAT` に追記
- シートがアニメーション中で `uiautomator dump` が空になることがある → 数秒後に再試行
- 既に登録済みの場合はシートが開かない

### `Play：このアカウントは無料トライアル対象外です`

アカウントがすでに trial を使ったことがある、または対象外。
`--list` で offer が出ているかを先に確認してください。

### 4 回目の重ね掛け（`6months-eft-ss-2026`）で「エラーが発生しました」

Play 側が即エラーを返すケース。今回の アカウントではこの offer だけアップグレード不可でした。
1〜3 回目が通っていれば 24 ヶ月は確保できているので、必須ではありません（予備扱い）。

### 購入後に日付が動かない

- サブスクが「有効（自動更新オン）」か確認（解約済みだと trial が付かない）
- 収銀台の表示が「開始日 = 現在の期限日」になっていたら、subscription upgrade になっていない
  → `--stack` を付けて再実行

## 結果の確認

```bash
# Play の画面
adb shell "am start -a android.intent.action.VIEW -d 'https://play.google.com/store/account/subscriptions'"
adb shell uiautomator dump /sdcard/s.xml && adb shell cat /sdcard/s.xml | grep -o 'text="[^"]*"'

# 内部 DB（root 必要）
adb shell "cp /data/data/com.android.vending/databases/library.db /data/local/tmp/lib.db; chmod 666 /data/local/tmp/lib.db"
adb pull /data/local/tmp/lib.db /tmp/lib.db
sqlite3 /tmp/lib.db "select doc_id, datetime(subs_valid_until_time/1000,'unixepoch') from ownership where doc_id like 'subs:%'"
```
