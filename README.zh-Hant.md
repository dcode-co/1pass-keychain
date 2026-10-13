# 1pass keychain (`kc`)

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-Hans.md) · **繁體中文** · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md)

在需要的時候，把密鑰在**你自己裝置的作業系統鑰匙圈之間**直接搬移——支援 macOS 鑰匙圈、
Linux Secret Service 與 Windows 認證管理員（Credential Manager），
不需要雲端保管庫。

```console
# 在新電腦上
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# 在已有金鑰的電腦上
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **雲端不儲存任何內容。** 中繼伺服器（`relay.1pass.dev`）只在兩台裝置之間
  傳遞端對端加密的位元組，並在幾分鐘內丟棄。它永遠看不到明文。
- **不需要帳號。** 一次性代碼完成兩台裝置的驗證（SPAKE2，概念與
  magic-wormhole 相同）。猜錯一次，代碼即失效。
- **記住裝置。** 用 `--remember` 配對一次之後，
  `kc send NAME --to omarchy` 不需代碼即可使用，即使對方裝置
  離線長達 72 小時也沒問題。
- **大量搬移。** 不帶名稱執行 `kc send` 可從清單中勾選項目，
  也可以使用 `--bundle new-machine.toml`。
- **適合代理程式使用。** `kc get NAME` 將密鑰輸出到管線，供指令碼與
  AI 代理程式使用。它不會卡在圖形介面的解鎖提示上，沒有 `--reveal`
  也不會輸出到終端機。

## 安裝

在 macOS 或 Linux 上可以用 [Homebrew](https://brew.sh)：

```console
$ brew install dcode-co/tap/kc
```

在 macOS、Linux 或 Windows 上也可以用 npm 或 [Bun](https://bun.sh)。套件名稱是
`1pass-keychain`，安裝後的命令是 `kc`：

```console
$ npm install -g 1pass-keychain        # 或者：bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # 或者：bunx 1pass-keychain doctor（不需安裝）
```

或者從 [Releases](https://github.com/dcode-co/1pass-keychain/releases)
下載適合你系統的壓縮檔，並把 `kc`
放到 `PATH` 中：

| 系統 | 壓縮檔 |
|---|---|
| macOS，Apple 晶片 | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS，Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64（靜態連結，適用任何發行版） | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64（靜態連結，適用任何發行版） | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

發行版中的 `SHA256SUMS` 列出每個壓縮檔的校驗碼。macOS 執行檔
以 Developer ID 簽署，並經過 Apple 公證。

`kc doctor` 會檢查鑰匙圈、中繼伺服器與設定。

**Linux** 需要正在執行的 Secret Service，例如 gnome-keyring。桌面
安裝通常內建；無頭伺服器或最小安裝可能沒有。

**Windows**：以金鑰登入的 SSH 工作階段無法使用認證管理員，
因此請在桌面工作階段中執行 kc。

若要改從原始碼建置，請使用 Rust 1.88 或更新版本：

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## 第一次使用：設定新電腦

1. 在存有密鑰的電腦上，先儲存一次：

   ```console
   $ kc set GITHUB_TOKEN              # 詢問值；輸入不會顯示
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # 或複製其他工具已儲存的項目
   ```

2. 在新電腦上執行 `kc receive`，它會顯示類似 `4721-absurd-amulet` 的代碼。
3. 回到第一台電腦，執行 `kc send GITHUB_TOKEN SSH_DEPLOY_KEY` 並輸入
   該代碼。兩台電腦都會顯示已傳送與已儲存的內容。
4. 在新電腦上使用這些值：

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # 以權限 600 寫入
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

代碼只能使用一次，有效期 10 分鐘。用代碼傳送需要有人在
終端機前操作；指令碼與代理程式則傳送到已記住的裝置。

## 已記住的裝置

兩台電腦配對一次後，之後的傳送都不需要代碼：

```console
laptop$  kc pair              # 顯示配對代碼
desktop$ kc pair --join       # 輸入該代碼
```

雙方各自以一個**標籤**記住對方，預設是對方的主機名稱。
`kc peers` 列出這些裝置；`--to` 接受的就是 `LABEL` 欄的值：

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # desktop 關機時也可以
desktop$ kc inbox                            # 儲存收到的內容（最多保留 72 小時）
```

`kc device rename` 變更本機在配對時建議的標籤。
`kc peers rm LABEL` 解除與某台裝置的配對；若有電腦遺失，請在其他電腦上執行此指令。
何時使用 `kc device rotate`，請參閱 [docs/SECURITY.md](docs/SECURITY.md)。

## 同步

在已配對的裝置之間同步選定的項目。**預設不會同步任何項目。**
將 `NAME` 換成現有項目的名稱：

```console
$ kc sync add NAME          # 加入同步範圍，並向其他裝置傳送提案
$ kc sync                   # 在兩台裝置上執行，交換變更
$ kc sync review            # 在接收裝置上審核提案與暫存的變更
$ kc sync status            # 顯示狀態與本機的值指紋，不顯示值
```

目前版本會暫存所有遠端覆寫操作，等待人工審核。同步中每次套用值都需要透過
Touch ID（或系統密碼）、Windows Hello 或 polkit 在本機確認。加入同步範圍也需要
確認。一般的本機寫入可以將變更加進傳送佇列，但不會授權覆寫其他裝置上的值。
發生衝突時會保留候選值；使用 `kc sync resolve NAME --keep mine` 或
`kc sync resolve NAME --keep LABEL` 選擇要保留的版本。其他裝置仍須審核結果。
`kc sync freeze` 不需確認即可暫停套用傳入的變更；`kc sync unfreeze` 需要系統確認。
結束代碼 8 表示仍有待處理或受阻的工作。另請參閱[安全限制](docs/SECURITY.md)。

## 指令

| 指令 | 作用 |
|---|---|
| `kc set NAME` | 儲存從標準輸入或隱藏提示讀取的值（整個檔案用 `--from-file PATH`） |
| `kc get NAME` | 將值輸出到管線（`--to-file PATH` 以權限 600 寫入檔案，`--reveal` 輸出到終端機） |
| `kc exec --env VAR=NAME -- CMD…` | 將值放入環境變數後執行指令，不經過 shell |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | 列出、刪除，或復原上一次覆寫 |
| `kc adopt --service S [--account A] [--as NAME]` | 將既有的鑰匙圈項目複製到 kc |
| `kc receive` / `kc send [NAMES…]` | 用一次性代碼搬移項目 |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | 已記住的裝置 |
| `kc sync` | 與已配對的裝置同步選定項目 |
| `kc doctor` | 檢查鑰匙圈、中繼伺服器與設定 |

## 疑難排解

- **`kc doctor` 顯示 `device FAIL: the OS keychain refused access`**（macOS）。
  當另一個 kc 執行檔讀取別的 kc 執行檔儲存的項目時，鑰匙圈會先詢問，
  例如在 Homebrew、npm 與原始碼建置之間切換之後。在終端機中執行一次失敗的指令
  （或 `kc doctor`）並選擇**永遠允許**；`kc --help` 與 `kc --version` 不會存取鑰匙圈。
  指令碼與代理程式無法回應該提示，所以請在它們執行之前完成。
- **`kc: … is missing. Reinstall 1pass-keychain with optional dependencies
  enabled`**（npm 或 Bun）。執行檔位於 npm 以選用相依套件安裝的
  各平台套件中：`1pass-keychain-darwin-arm64`、`-darwin-x64`、`-linux-arm64`、
  `-linux-x64`，Windows 為 `@1pass/keychain-win32-x64`。用 `--omit=optional`
  （或 `--no-optional`）安裝會漏掉它；請拿掉該選項重新安裝。
- **Windows：`no Credential Manager logon session`。** 以金鑰登入的 SSH 工作階段中
  沒有認證管理員。請在桌面工作階段中執行 kc，或以密碼透過 SSH 連線。
- **Linux：鑰匙圈無法使用。** 啟動 Secret Service（例如 gnome-keyring）並解鎖；
  `kc doctor` 會指出缺少哪個部分。
- **訊息語言不對。** 設定 `KC_LANG`（見下方「語言」）。當 stdout 與 stderr
  都不是終端機時（指令碼、代理程式），除非設定了 `KC_LANG`，否則 kc 一律輸出英文。

## 語言

kc 的訊息與 `kc --help` 支援 English、한국어、日本語、简体中文、繁體中文、
Español、Français 與 Deutsch。在終端機中，kc 依循你的地區設定（`LC_ALL`、
`LC_MESSAGES`、`LANG` 與 `LANGUAGE`，接著是系統語言）。指令碼與
代理程式預設取得英文輸出，除非設定了 `KC_LANG`。用 `KC_LANG` 選擇語言：

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` 接受 `en`、`ko`、`ja`、`zh-Hans`、`zh-Hant`、`es`、`fr` 或 `de`。
值、項目名稱、代碼與 JSON 輸出一律不翻譯。

## 狀態

早期版本（v0.2）。已在實體電腦上測試：

- macOS 與 Linux 之間、macOS 與 Windows 11 之間的雙向配對傳送
- 從 macOS 到 Linux 的一次性代碼傳送
- 在各作業系統鑰匙圈中儲存、讀取與刪除項目

尚未在實體電腦上測試：從 Linux 或 Windows 發起的一次性代碼傳送。
PAKE crate 尚未經過獨立稽核。協定見
[docs/PROTOCOL.md](docs/PROTOCOL.md)，威脅模型見
[docs/SECURITY.md](docs/SECURITY.md)。

維護者：發布步驟與已知陷阱見
[docs/RELEASING.md](docs/RELEASING.md)。

## 授權

MIT
