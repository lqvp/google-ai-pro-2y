# 実測ログ（2026-11-19）

> アカウント名・端末識別子などは伏せています（`example@gmail.com` は例示）。

環境:

| | |
|---|---|
| ホスト | Arch Linux / x86_64 |
| 端末 | Pixel 7a (`lynx`) / Android 16 / KernelSU |
| Frida | client 17.22.2 / server 17.22.2 |
| 課金経路 | Google One アプリ + `module_521.apk`（BillingClient 5.x 系） |
| アカウント | `example@gmail.com`（例。日本リージョン・JPY 請求） |

## 開始時の状態

- Play サブスク: **学生プラン `g1.play.2tb.ai.student`** 有効（￥720/月、次回 2026-12-18）
- `--list --plan pro12` で Pro 5TB の offer が 4 種見えている:

```
offer 12months-eft        → 0 micros, P1Y
offer 6months-eft         → 0 micros, P6M
offer 6months-eft-2       → 0 micros, P6M
offer 6months-eft-ss-2026 → 0 micros, P6M
offer null                → 2,900,000,000 micros, P1M   （通常価格 ¥2,900）
```

## 実行結果

| 日時 | 操作 | offer | `subs_valid_until_time` |
|---|---|---|---|
| 2026-11-19 02:34 | step1（`--plan pro12`） | `12months-eft` | 2027-11-19 |
| 2026-11-19 02:38 | step2（`--stack --plan pro6`） | `6months-eft` | 2028-05-19（546 日） |
| 2026-11-19 02:41 | step3（`--stack --plan pro6b`） | `6months-eft-2` | **2028-11-19（730 日）** |
| 2026-11-19 02:45〜 | step4（`--stack --plan pro6c`） | `6months-eft-ss-2026` | 変化なし（Play が即エラー） |

購入ごとに `purchaseToken` が更新される（`library.db` の `ownership` テーブル）:

```
step1 token: hhmmpglombmodehpdjpbfodf
step2 token: dbpakjbaegnpoldodgccdoma
step3 token: kkhcjgmmmdgjahpmkkmeknkj
```

## 最終状態

`library.db`:

```
subs:com.google.android.apps.subscriptions.red:g1.2tb.ai.subs_variant
  valid_until: 2028-11-19
  残り日数: 730
```

Play の定期購入画面:

```
有効
Google One
Google AI Pro (5 TB)
次回のお支払い: ￥2,900（2028/11/19）
```

再起動後も同じ状態であることを確認済み（サーバー側で保持）。

## 観測された注意点

- Frida 注入を繰り返すと Pixel 7a がブートループに入ることがあった
  （電源長押しで復帰、サブスクは無事）
- USB 接続が数回ドロップ（ハブ経由）。Wi-Fi ADB 併用で安定
- 4 回目（`-ss-2026`）だけ Play がシートを出さず「エラーが発生しました」ダイアログを表示
