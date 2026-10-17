# 1pass keychain (`kc`)

[English](README.md) · [한국어](README.ko.md) · **日本語** · [简体中文](README.zh-Hans.md) · [繁體中文](README.zh-Hant.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md)

シークレットを**自分のデバイスの OS キーチェーン同士**で、必要なときに
移動します。macOS キーチェーン、Linux Secret Service、Windows の
資格情報マネージャー (Credential Manager) に対応し、クラウドの保管庫は使いません。

```console
# 新しいマシンで
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# キーを持っているマシンで
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **クラウドには何も保存しません。** リレー (`relay.1pass.dev`) は
  エンドツーエンドで暗号化されたバイト列を 2 台のデバイス間で中継し、
  数分以内に破棄します。平文を見ることはありません。
- **アカウント不要。** ワンタイムコードで 2 台のデバイスを認証します
  (SPAKE2。magic-wormhole と同じ考え方です)。推測を一度でも誤るとコードは無効になります。
- **デバイスの記憶。** `--remember` で一度ペアリングすれば、以後は
  `kc send NAME --to omarchy` がコードなしで使えます。相手のデバイスが
  最大 72 時間オフラインでも構いません。
- **一括移動。** 名前を指定せずに `kc send` を実行するとチェックリストから項目を選べます。
  `--bundle new-machine.toml` も使えます。
- **エージェント向け。** `kc get NAME` はスクリプトや AI エージェントのために
  シークレットをパイプへ出力します。GUI のロック解除プロンプトで止まることはなく、
  `--reveal` なしではターミナルに出力しません。

## インストール

macOS または Linux では [Homebrew](https://brew.sh) を使えます。

```console
$ brew install dcode-co/tap/kc
```

macOS・Linux・Windows では npm または [Bun](https://bun.sh) も使えます。パッケージ名は
`1pass-keychain`、インストールされるコマンドは `kc` です。

```console
$ npm install -g 1pass-keychain        # または: bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # または: bunx 1pass-keychain doctor (インストール不要)
```

または [Releases](https://github.com/dcode-co/1pass-keychain/releases) から
システムに合ったアーカイブをダウンロードし、`kc` を
`PATH` の通った場所に置きます。

| システム | アーカイブ |
|---|---|
| macOS、Apple シリコン | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS、Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (静的リンク、ディストリビューション不問) | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (静的リンク、ディストリビューション不問) | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

リリースに含まれる `SHA256SUMS` に全アーカイブのチェックサムがあります。macOS バイナリは
Developer ID で署名され、Apple の公証を受けています。

`kc doctor` はキーチェーン、リレー、設定を確認します。

**Linux** では gnome-keyring などの Secret Service が動いている必要があります。
デスクトップ環境なら通常は入っていますが、ヘッドレスサーバーや最小構成では入っていないことがあります。

**Windows**: 鍵でログインした SSH セッションでは資格情報マネージャーを使えないため、
デスクトップセッションから kc を実行してください。

ソースからビルドする場合は Rust 1.88 以降を使います。

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## 初めての使い方: 新しいマシンのセットアップ

1. シークレットを持っているマシンで、一度だけ保存します。

   ```console
   $ kc set GITHUB_TOKEN              # 値を尋ねます。入力は表示されません
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # または他のツールが保存済みの項目をコピー
   ```

2. 新しいマシンで `kc receive` を実行します。`4721-absurd-amulet` のようなコードが表示されます。
3. 最初のマシンに戻り、`kc send GITHUB_TOKEN SSH_DEPLOY_KEY` を実行して
   そのコードを入力します。両方のマシンに送信・保存された内容が表示されます。
4. 新しいマシンで値を使います。

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # モード 600 で書き込み
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

コードは 1 回限り、10 分間有効です。コードを使った送信にはターミナルの前に人が必要です。
スクリプトやエージェントは記憶済みデバイスへ送信します。

## 記憶済みデバイス

2 台のマシンを一度ペアリングすれば、以後の送信にコードは不要です。

```console
laptop$  kc pair              # ペアリングコードを表示
desktop$ kc pair --join       # そのコードを入力
```

それぞれ相手を**ラベル**で記憶します。既定はホスト名です。
`kc peers` で一覧を表示でき、`LABEL` 列の値を `--to` に指定します。

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # desktop の電源が切れていても可
desktop$ kc inbox                            # 届いたものを保存 (最大 72 時間保持)
```

`kc device rename` はこのマシンがペアリング時に提示するラベルを変更します。
`kc peers rm LABEL` はデバイスのペアリングを解除します。マシンを紛失したら、他のマシンでこれを実行してください。
`kc device rotate` を使う場面は [docs/SECURITY.md](docs/SECURITY.md) を参照してください。

## 同期

選んだ項目をペアリング済みデバイス間で同期します。**初期状態では何も同期しません。**
`NAME` は既存の項目名に置き換えてください。

```console
$ kc sync add NAME          # 同期対象に登録し、他のデバイスに提案
$ kc sync                   # 両方のデバイスで実行して変更を交換
$ kc sync review            # 受信側で提案と保留中の変更を確認
$ kc sync status            # 値ではなく状態とこのデバイスの値の指紋を表示
```

このバージョンでは、リモートからの上書きをすべて保留して人が確認します。同期で値を
適用するたびに、Touch ID（または OS のパスワード）、Windows Hello、polkit による
ローカル確認が必要です。同期対象の登録にも確認が必要です。通常のローカル書き込みは
変更を送信待ちにできますが、他のデバイスでの上書きを許可するものではありません。
競合した候補の値は保存されます。`kc sync resolve NAME --keep mine` または
`kc sync resolve NAME --keep LABEL` で残す値を選びます。他のデバイスでは結果も
確認が必要です。`kc sync freeze` は確認なしで受信した変更の適用を止めます。
`kc sync unfreeze` には OS の確認が必要です。終了コード 8 は保留中または処理できない
作業が残っていることを示します。[セキュリティ上の制限](docs/SECURITY.md)も参照してください。

## コマンド

| コマンド | 内容 |
|---|---|
| `kc set NAME` | 標準入力または非表示プロンプトから読んだ値を保存 (ファイル全体は `--from-file PATH`) |
| `kc get NAME` | 値をパイプへ出力 (`--to-file PATH` でモード 600 のファイルに書き込み、`--reveal` でターミナルに表示) |
| `kc exec --env VAR=NAME -- CMD…` | 値を環境変数に入れてコマンドを実行 (シェルを介さない) |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | 一覧、削除、直前の上書きの取り消し |
| `kc adopt --service S [--account A] [--as NAME]` | 既存のキーチェーン項目を kc にコピー |
| `kc receive` / `kc send [NAMES…]` | ワンタイムコードで項目を移動 |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | 記憶済みデバイス |
| `kc sync` | 選んだ項目をペアリング済みデバイスと同期 |
| `kc doctor` | キーチェーン、リレー、設定を確認 |

## トラブルシューティング

- **`kc doctor` に `device FAIL: the OS keychain refused access` と表示される**
  (macOS)。Homebrew、npm、ソースビルドを切り替えた後など、別の kc バイナリが
  保存した項目を読む前にキーチェーンが確認を求めます。失敗したコマンド (または
  `kc doctor`) をターミナルで一度実行し、**常に許可** を選んでください。
  `kc --help` と `kc --version` はキーチェーンにアクセスしません。スクリプトやエージェントはこの
  確認に応答できないため、実行前に済ませておいてください。
- **`kc: … is missing. Reinstall 1pass-keychain with optional dependencies
  enabled` と表示される** (npm または Bun)。バイナリは npm が
  オプション依存関係としてインストールするプラットフォーム別パッケージに含まれます:
  `1pass-keychain-darwin-arm64`、`-darwin-x64`、`-linux-arm64`、`-linux-x64`、
  Windows は `@1pass/keychain-win32-x64`。`--omit=optional` (または `--no-optional`)
  でインストールすると含まれないので、そのフラグなしで再インストールしてください。
- **SSH 経由の macOS: キーチェーンがロックされている、または使えない。** macOS は SSH
  ログインではログインキーチェーンをロックしたままにするため、キーチェーンの確認は表示されません。
  Mac 本体のターミナルで kc を実行するか、SSH セッションで先に
  `security unlock-keychain ~/Library/Keychains/login.keychain-db` を実行してください
  (Mac のログインパスワードを求められます)。
- **Windows: `no Credential Manager logon session`。** 鍵でログインした SSH
  セッションには資格情報マネージャーがありません。デスクトップセッションから
  kc を実行するか、パスワードで SSH 接続してください。
- **Linux: キーチェーンが使えない。** Secret Service (gnome-keyring など) を起動して
  ロックを解除してください。何が足りないかは `kc doctor` が示します。
- **メッセージが意図しない言語で表示される。** `KC_LANG` を設定してください (下の「言語」を参照)。
  stdout と stderr のどちらもターミナルでない場合 (スクリプト、エージェント)、
  `KC_LANG` を設定しない限り kc は英語で出力します。

## 言語

kc のメッセージと `kc --help` は English、한국어、日本語、简体中文、繁體中文、
Español、Français、Deutsch で表示できます。ターミナルではロケール (`LC_ALL`、
`LC_MESSAGES`、`LANG`、`LANGUAGE`、次にシステム言語) に従います。スクリプトと
エージェントには `KC_LANG` を設定しない限り英語で出力します。`KC_LANG` で言語を選べます。

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` には `en`、`ko`、`ja`、`zh-Hans`、`zh-Hant`、`es`、`fr`、`de` を指定できます。
値、項目名、コード、JSON 出力は翻訳されません。

## 開発状況

初期リリース (v0.2) です。実機で確認済みの内容:

- macOS と Linux 間、macOS と Windows 11 間の双方向のペアリング送信
- macOS から Linux へのワンタイムコード送信
- 各 OS キーチェーンでの項目の保存・読み出し・削除

実機で未確認: Linux または Windows からのワンタイムコード送信。
PAKE クレートは独立した監査を受けていません。プロトコルは
[docs/PROTOCOL.md](docs/PROTOCOL.md)、脅威モデルは
[docs/SECURITY.md](docs/SECURITY.md) にあります。

メンテナー向け: リリース手順と既知の落とし穴は
[docs/RELEASING.md](docs/RELEASING.md) にあります。

## ライセンス

MIT
