# セットアップ

## 1. ホスト（PC）側

| 必要なもの | 用途 | 確認 |
|---|---|---|
| Python 3.9+ | スクリプト実行 | `python3 -V` |
| adb (platform-tools) | 端末操作 | `adb version` |
| node / npm（任意） | Frida エージェントのビルド | `node -v` |
| uv（任意） | venv 作成の高速化 | `uv --version` |

adb が無い場合は `./scripts/setup.sh` が `tools/platform-tools/` に自動取得します
（Linux 版。macOS は https://developer.android.com/tools/releases/platform-tools から取得）。

## 2. 端末側

### 2-1. 必須

```bash
adb devices                     # 端末が見える
adb shell id                    # uid=0(root) であること
adb shell getprop ro.product.cpu.abi   # arm64-v8a / x86_64
adb shell getprop ro.build.version.release
```

root は **KernelSU / Magisk / APatch** のいずれでも可。
`adb shell id` が `shell` の場合は以下を試す:

```bash
adb root                        # エミュレータ系
adb shell su -c id              # 実機（KernelSU は adb shell が最初から root のことが多い）
```

### 2-2. Google Play 側

- Play ストアに **対象アカウントでログイン済み**
- **支払い方法（カード等）が登録済み**
- Google One（`com.google.android.apps.subscriptions.red`）がインストール済み
- サブスクの状態:
  - 新規で 12 ヶ月 trial を取るなら「サブスクなし」でも可
  - **重ね掛け（step2〜）をするにはサブスクが有効（自動更新オン）であること**
  - 解約済みだと新しい購入が「期限後転換」になり trial が付かないことがある

### 2-3. frida-server

経路 B（frida 17）ではクライアント 17.22.2 と **同じメジャー** の frida-server が必要です。

- 端末に `/data/local/tmp/frida-server` が無ければ、`ultra0-17.py` が
  17.22.2 を自動ダウンロードして起動します
- KernelSU/Magisk の `magisk-frida` モジュール等が起動時に別バージョンを起動している場合は、
  **そのモジュールの `bin/frida-server` を 17.x に差し替える**か、モジュールを無効化してください
- 不一致が出たら:

```bash
./scripts/run.sh fix-frida
```

## 3. 接続（USB / Wi-Fi）

USB が安定しない環境では Wi-Fi ADB を併用できます。

```bash
adb tcpip 5555
adb connect <端末のIP>:5555     # 端末: 設定 > ネットワーク > IP
adb devices                     # 2 行出ても OK（先頭が使われる）
```

`ultra0-17.py` は adb の先頭デバイスを使います。特定端末を指定したい場合:

```bash
python scripts/ultra0-17.py --check --serial <serial>
```

## 4. 経路 A: Android 12/13 エミュレータ（MuMu など / frida 16.5.9）

Windows 前提。元 zip の手順そのままです。

```bat
pip install frida==16.5.9
python scripts\setup_env_frida16.py
windows\frida16\0_環境自検.bat
windows\frida16\1_offer一覧.bat
```

エミュレータ側で「ROOT 権限」を ON、ADB デバッグを有効にしてください。
MuMu の ADB ポートは 16384 / 7555 など。`setup_env_frida16.py` が自動で `adb connect` します。

## 5. 経路 B: Android 14+ 実機（このリポジトリの追加分）

```bash
./scripts/setup.sh
```

やっていること:

1. `.venv` を作り `frida==17.22.2` をインストール
2. 同梱の `agent/agent.iife.js` を使う（実績のあるバンドル）
3. adb が無ければ `tools/` に platform-tools を取得
4. 端末の接続・root を確認

`agent/injected.js` を編集した場合だけ再ビルドします:

```bash
./scripts/setup.sh --rebuild   # npm install → patch → build
```

（バンドルは Frida のコンパイラ設定に依存するため、`agent/package.json` の
`"type": "commonjs"` を変えないでください。`esm` 形式だと `malformed package` になります）

```bash
./scripts/run.sh check    # 環境自検
./scripts/run.sh list     # offer 一覧（課金しない）
```

`check` の最後に `✅ 环境自检通过` が出れば OK。

## 6. 実行順序

```bash
./scripts/run.sh step1    # 12ヶ月無料（offer: 12months-eft）
./scripts/run.sh step2    # +6ヶ月（6months-eft、subscription upgrade）
./scripts/run.sh step3    # +6ヶ月（6months-eft-2）
./scripts/run.sh step4    # 予備 +6ヶ月（6months-eft-ss-2026、エラーになる場合あり）
```

各ステップ後、Play の「定期購入」画面（`https://play.google.com/store/account/subscriptions`）で
**次回のお支払い日** が後ろにずれていることを確認してから次へ進んでください。

| ステップ後 | 期待される期限 |
|---|---|
| step1 | 12ヶ月後 |
| step2 | 18ヶ月後 |
| step3 | 24ヶ月後 |
| step4 | 30ヶ月後（取れれば） |

## 7. 終了処理

```bash
# トライアル期限後に課金されないよう、期限内に解約する
# Play ストア > お支払いと定期購入 > 定期購入 > Google AI Pro > 定期購入を解約
```

解約しても期限までは利用できます。
Frida が不要なら、端末の常駐を止めておくと安定します:

```bash
adb shell su -c "pkill -x frida-server"
# magisk-frida モジュールを使っている場合
adb shell su -c "touch /data/adb/modules/magisk-frida/disable"   # 次回起動から無効
```
