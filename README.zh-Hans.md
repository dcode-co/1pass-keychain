# 1pass keychain (`kc`)

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · **简体中文** · [繁體中文](README.zh-Hant.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md)

在需要的时候，把密钥在**你自己设备的系统钥匙串之间**直接转移——支持 macOS 钥匙串、
Linux Secret Service 和 Windows 凭据管理器（Credential Manager），
无需云端保险库。

```console
# 在新机器上
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# 在已有密钥的机器上
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **云端不存储任何内容。** 中继服务器（`relay.1pass.dev`）只在两台设备之间
  传递端到端加密的字节，并在几分钟内丢弃。它永远看不到明文。
- **无需账号。** 一次性代码完成两台设备的认证（SPAKE2，思路与
  magic-wormhole 相同）。猜错一次，代码即作废。
- **记住设备。** 用 `--remember` 配对一次后，
  `kc send NAME --to omarchy` 无需代码即可使用，即使对方设备
  离线长达 72 小时也可以。
- **批量转移。** 不带名称运行 `kc send` 可从清单中勾选条目，
  也可以使用 `--bundle new-machine.toml`。
- **适合代理使用。** `kc get NAME` 将密钥输出到管道，供脚本和
  AI 代理使用。它不会卡在图形界面的解锁提示上，没有 `--reveal`
  也不会输出到终端。

## 安装

在 macOS 或 Linux 上可以用 [Homebrew](https://brew.sh)：

```console
$ brew install dcode-co/tap/kc
```

在 macOS、Linux 或 Windows 上也可以用 npm 或 [Bun](https://bun.sh)。包名是
`1pass-keychain`，安装后的命令是 `kc`：

```console
$ npm install -g 1pass-keychain        # 或者：bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # 或者：bunx 1pass-keychain doctor（无需安装）
```

或者从 [Releases](https://github.com/dcode-co/1pass-keychain/releases)
下载适合你系统的压缩包，并把 `kc`
放到 `PATH` 中：

| 系统 | 压缩包 |
|---|---|
| macOS，Apple 芯片 | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS，Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64（静态链接，适用任意发行版） | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64（静态链接，适用任意发行版） | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

发布中的 `SHA256SUMS` 列出了每个压缩包的校验和。macOS 二进制文件
使用 Developer ID 签名，并经过 Apple 公证。

`kc doctor` 会检查钥匙串、中继服务器和配置。

**Linux** 需要正在运行的 Secret Service，例如 gnome-keyring。桌面
安装通常自带；无头服务器或最小化安装可能没有。

**Windows**：在使用密钥登录的 SSH 会话中无法使用凭据管理器，
因此请在桌面会话中运行 kc。

如需从源码构建，请使用 Rust 1.88 或更高版本：

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## 首次使用：设置新机器

1. 在存有密钥的机器上，先保存一次：

   ```console
   $ kc set GITHUB_TOKEN              # 询问值；输入不会回显
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # 或复制其他工具已保存的条目
   ```

2. 在新机器上运行 `kc receive`，它会显示类似 `4721-absurd-amulet` 的代码。
3. 回到第一台机器，运行 `kc send GITHUB_TOKEN SSH_DEPLOY_KEY` 并输入
   该代码。两台机器都会显示已发送和已保存的内容。
4. 在新机器上使用这些值：

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # 以权限 600 写入
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

代码只能使用一次，有效期 10 分钟。用代码发送需要有人在
终端前操作；脚本和代理则发送到已记住的设备。

## 已记住的设备

两台机器配对一次后，之后的发送都无需代码：

```console
laptop$  kc pair              # 显示配对代码
desktop$ kc pair --join       # 输入该代码
```

双方各自以一个**标签**记住对方，默认是对方的主机名。
`kc peers` 列出这些设备；`--to` 接受的就是 `LABEL` 列的值：

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # desktop 关机时也可以
desktop$ kc inbox                            # 保存收到的内容（最多保留 72 小时）
```

`kc device rename` 修改本机在配对时建议的标签。
`kc peers rm LABEL` 解除与某台设备的配对；如果有机器丢失，请在其他机器上运行此命令。
何时使用 `kc device rotate`，请参阅 [docs/SECURITY.md](docs/SECURITY.md)。

## 命令

| 命令 | 作用 |
|---|---|
| `kc set NAME` | 保存从标准输入或隐藏提示读取的值（整个文件用 `--from-file PATH`） |
| `kc get NAME` | 将值输出到管道（`--to-file PATH` 以权限 600 写入文件，`--reveal` 输出到终端） |
| `kc exec --env VAR=NAME -- CMD…` | 将值放入环境变量后运行命令，不经过 shell |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | 列出、删除，或撤销上一次覆盖 |
| `kc adopt --service S [--account A] [--as NAME]` | 将现有钥匙串条目复制到 kc |
| `kc receive` / `kc send [NAMES…]` | 用一次性代码转移条目 |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | 已记住的设备 |
| `kc doctor` | 检查钥匙串、中继服务器和配置 |

## 语言

kc 的消息和 `kc --help` 支持 English、한국어、日本語、简体中文、繁體中文、
Español、Français 和 Deutsch。在终端中，kc 跟随你的区域设置（`LC_ALL`、
`LC_MESSAGES`、`LANG` 和 `LANGUAGE`，然后是系统语言）。脚本和
代理默认得到英文输出，除非设置了 `KC_LANG`。用 `KC_LANG` 选择语言：

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` 接受 `en`、`ko`、`ja`、`zh-Hans`、`zh-Hant`、`es`、`fr` 或 `de`。
值、条目名称、代码和 JSON 输出永远不会被翻译。

## 状态

早期版本（v0.2）。已在真实机器上测试：

- macOS 与 Linux 之间、macOS 与 Windows 11 之间的双向配对发送
- 从 macOS 到 Linux 的一次性代码发送
- 在各系统钥匙串中保存、读取和删除条目

尚未在真实机器上测试：从 Linux 或 Windows 发起的一次性代码发送。
PAKE crate 尚未经过独立审计。协议见
[docs/PROTOCOL.md](docs/PROTOCOL.md)，威胁模型见
[docs/SECURITY.md](docs/SECURITY.md)。

## 许可证

MIT
