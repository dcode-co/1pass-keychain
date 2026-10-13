# 1pass keychain (`kc`)

[English](README.md) · **한국어** · [日本語](README.ja.md) · [简体中文](README.zh-Hans.md) · [繁體中文](README.zh-Hant.md) · [Español](README.es.md) · [Français](README.fr.md) · [Deutsch](README.de.md)

필요한 순간에 비밀값을 **내 기기들의 OS 키체인** 사이로 옮깁니다.
macOS 키체인, Linux Secret Service, Windows 자격 증명 관리자를 지원하고
클라우드 금고는 쓰지 않습니다.

```console
# 새 기기에서
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# 키를 가진 기기에서
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **클라우드에 아무것도 남지 않습니다.** 중계 서버(`relay.1pass.dev`)는 두 기기
  사이에서 종단 간 암호화된 바이트만 전달하고 몇 분 안에 지웁니다. 평문은
  보지 못합니다.
- **계정이 없습니다.** 일회용 코드로 두 기기를 인증합니다(SPAKE2,
  magic-wormhole 과 같은 방식). 코드를 한 번 틀리면 그 코드는 폐기됩니다.
- **기억된 기기.** `--remember` 로 한 번 페어링하면 이후에는
  `kc send NAME --to omarchy` 를 코드 없이 쓸 수 있습니다. 상대 기기가 최대
  72시간 꺼져 있어도 됩니다.
- **한꺼번에 옮기기.** 이름 없이 `kc send` 를 실행하면 체크리스트에서 고를 수
  있고, `--bundle new-machine.toml` 로 목록을 넘길 수도 있습니다.
- **에이전트 친화.** `kc get NAME` 은 스크립트와 AI 에이전트를 위해 비밀값을
  파이프로 출력합니다. GUI 잠금 해제 창에서 멈추지 않고, `--reveal` 없이는
  터미널에 값을 찍지 않습니다.

## 설치

macOS 나 Linux 에서는 [Homebrew](https://brew.sh) 로 설치합니다.

```console
$ brew install dcode-co/tap/kc
```

macOS, Linux, Windows 에서는 npm 이나 [Bun](https://bun.sh) 으로도 설치할 수 있습니다.
패키지 이름은 `1pass-keychain`, 설치되는 명령은 `kc` 입니다.

```console
$ npm install -g 1pass-keychain        # 또는: bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # 또는: bunx 1pass-keychain doctor (설치 없이)
```

또는 [Releases](https://github.com/dcode-co/1pass-keychain/releases) 에서 내 시스템에
맞는 압축 파일을 받아 `kc` 를 `PATH` 에 넣습니다.

| 시스템 | 압축 파일 |
|---|---|
| macOS, Apple silicon | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (정적 빌드, 배포판 무관) | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (정적 빌드, 배포판 무관) | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

릴리스의 `SHA256SUMS` 에 모든 압축 파일의 체크섬이 있습니다. macOS 바이너리는
Developer ID 로 서명했고 Apple 공증을 받았습니다.

`kc doctor` 는 키체인, 중계 서버, 설정을 점검합니다.

**Linux** 에서는 gnome-keyring 같은 Secret Service 가 실행 중이어야 합니다.
데스크톱 설치에는 보통 들어 있지만 헤드리스 서버나 최소 설치에는 없을 수
있습니다.

**Windows**: SSH 키로 로그인한 세션에서는 자격 증명 관리자를 쓸 수 없습니다.
데스크톱 세션에서 kc 를 실행하세요.

소스에서 빌드하려면 Rust 1.88 이상이 필요합니다.

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## 처음 쓰기: 새 기기 준비

1. 비밀값이 있는 기기에서 한 번 저장합니다.

   ```console
   $ kc set GITHUB_TOKEN              # 값을 묻고, 입력은 화면에 보이지 않음
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # 다른 도구가 이미 저장한 항목을 복사
   ```

2. 새 기기에서 `kc receive` 를 실행합니다. `4721-absurd-amulet` 같은 코드가
   나옵니다.
3. 처음 기기로 돌아가 `kc send GITHUB_TOKEN SSH_DEPLOY_KEY` 를 실행하고 그
   코드를 입력합니다. 두 기기 모두 보내고 저장한 항목을 보여 줍니다.
4. 새 기기에서 값을 씁니다.

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # 권한 600 으로 저장
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

코드는 10분 동안 한 번만 쓸 수 있습니다. 코드로 보내기는 터미널 앞에 사람이
있어야 합니다. 스크립트와 에이전트는 기억된 기기로 보냅니다.

## 기억된 기기

두 기기를 한 번 페어링하면 이후에는 코드 없이 보낼 수 있습니다.

```console
laptop$  kc pair              # 페어링 코드를 보여 줌
desktop$ kc pair --join       # 그 코드를 입력
```

양쪽은 서로를 **레이블**로 기억합니다. 기본값은 호스트명입니다. `kc peers` 가
목록을 보여 주고, `--to` 에는 `LABEL` 열의 값을 넣습니다.

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # desktop 이 꺼져 있어도 됨
desktop$ kc inbox                            # 도착한 항목을 저장(최대 72시간 보관)
```

`kc device rename` 은 페어링할 때 이 기기가 제안하는 레이블을 바꿉니다.
`kc peers rm LABEL` 은 페어링을 끊습니다. 기기를 잃어버렸다면 남은 기기마다
실행하세요. `kc device rotate` 를 언제 쓰는지는
[docs/SECURITY.md](docs/SECURITY.md) 에 있습니다.

## 동기화

선택한 항목을 페어링한 기기끼리 동기화합니다. **처음에는 아무 항목도
동기화하지 않습니다.** `NAME`에 기존 항목 이름을 넣으세요.

```console
$ kc sync add NAME          # 동기화 대상으로 등록하고 다른 기기에 제안
$ kc sync                   # 양쪽 기기에서 실행해 변경 사항 교환
$ kc sync review            # 받는 기기에서 제안과 보류된 변경 검토
$ kc sync status            # 값 대신 상태와 이 기기의 값 지문 표시
```

이 버전은 원격 덮어쓰기를 모두 보류하고 사람이 검토합니다. 동기화 과정에서
값을 적용할 때마다 Touch ID(또는 OS 암호), Windows Hello, polkit으로 확인합니다.
동기화 대상 등록에도 이 확인이 필요합니다. 일반적인 로컬 쓰기는 변경을 전송 대기열에
넣을 수 있지만, 다른 기기의 값을 덮어쓸 권한까지 부여하지는 않습니다.
충돌이 나면 후보 값을 보관합니다. `kc sync resolve NAME --keep mine`으로
이 기기의 값을, `kc sync resolve NAME --keep LABEL`로 해당 기기의 후보 값을
선택하세요. 다른 기기에서는 그 결과도 검토해야 합니다. `kc sync freeze`는 별도
확인 없이 수신 변경의 적용을 중단하고, `kc sync unfreeze`는 OS 확인 후 다시
허용합니다. 종료 코드 8은 대기 중이거나 막힌 작업이 남아 있다는 뜻입니다.
[보안상 한계](docs/SECURITY.md)도 참고하세요.

## 명령

| 명령 | 하는 일 |
|---|---|
| `kc set NAME` | stdin 이나 숨김 입력으로 받은 값을 저장(파일 전체는 `--from-file PATH`) |
| `kc get NAME` | 값을 파이프로 출력(`--to-file PATH` 는 권한 600 으로 저장, `--reveal` 은 터미널에 출력) |
| `kc exec --env VAR=NAME -- CMD…` | 값을 환경 변수에 넣어 셸 없이 명령 실행 |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | 목록, 삭제, 마지막 덮어쓰기 되돌리기 |
| `kc adopt --service S [--account A] [--as NAME]` | 이미 있는 키체인 항목을 kc 로 복사 |
| `kc receive` / `kc send [NAMES…]` | 일회용 코드로 항목 옮기기 |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | 기억된 기기 |
| `kc sync` | 선택한 항목을 페어링한 기기끼리 동기화 |
| `kc doctor` | 키체인, 중계 서버, 설정 점검 |

## 문제 해결

- **`kc doctor` 에 `device FAIL: the OS keychain refused access` 가 나올 때**
  (macOS). Homebrew, npm, 소스 빌드처럼 설치 방법을 바꾸면 다른 kc 바이너리가
  저장한 항목을 읽기 전에 키체인이 허용 여부를 묻습니다. 실패한 명령(또는
  `kc doctor`)을 터미널에서 한 번 실행하고 **항상 허용**을 누르세요.
  `kc --help`·`kc --version` 은 키체인을 읽지 않습니다. 스크립트와 에이전트는 이 창에 답할
  수 없으니 그 전에 해 두어야 합니다.
- **`kc: … is missing. Reinstall 1pass-keychain with optional dependencies
  enabled` 가 나올 때** (npm·Bun). 바이너리는 npm 이 선택 의존성으로 설치하는
  플랫폼별 패키지에 들어 있습니다. `1pass-keychain-darwin-arm64`,
  `-darwin-x64`, `-linux-arm64`, `-linux-x64`, 그리고 Windows 는
  `@1pass/keychain-win32-x64` 입니다. `--omit=optional`(또는 `--no-optional`)
  로 설치하면 빠지니 그 옵션 없이 다시 설치하세요.
- **Windows 에서 `no Credential Manager logon session` 이 나올 때.** SSH 키로
  로그인한 세션에는 자격 증명 관리자가 없습니다. 데스크톱 세션에서 실행하거나
  비밀번호로 SSH 접속하세요.
- **Linux 에서 키체인을 쓸 수 없을 때.** gnome-keyring 같은 Secret Service 를
  실행하고 잠금을 푸세요. 무엇이 빠졌는지는 `kc doctor` 가 알려 줍니다.
- **메시지가 원하지 않는 언어로 나올 때.** `KC_LANG` 을 지정하세요(아래 언어
  절 참고). stdout 과 stderr 가 모두 터미널이 아니면(스크립트·에이전트)
  `KC_LANG` 이 없는 한 영어로 나옵니다.

## 언어

kc 의 메시지와 `kc --help` 는 English, 한국어, 日本語, 简体中文, 繁體中文,
Español, Français, Deutsch 로 나옵니다. 터미널에서는 로케일(`LC_ALL`,
`LC_MESSAGES`, `LANG`, `LANGUAGE`, 그다음 시스템 언어)을 따릅니다. 스크립트와
에이전트에는 `KC_LANG` 을 지정하지 않는 한 영어로 나옵니다. 언어를 고르려면
`KC_LANG` 을 씁니다.

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` 에는 `en`, `ko`, `ja`, `zh-Hans`, `zh-Hant`, `es`, `fr`, `de` 를 넣을
수 있습니다. 값, 항목 이름, 코드, JSON 출력은 번역하지 않습니다.

## 상태

초기 릴리스(v0.2)입니다. 실제 기기에서 시험한 것:

- macOS ↔ Linux, macOS ↔ Windows 11 사이 페어링 전송(양방향)
- macOS 에서 Linux 로 일회용 코드 전송
- 각 OS 키체인에서 항목 저장·조회·삭제

아직 실제 기기에서 시험하지 않은 것: Linux 나 Windows 에서 보내는 일회용 코드
전송. PAKE 크레이트는 독립 감사를 받지 않았습니다. 프로토콜은
[docs/PROTOCOL.md](docs/PROTOCOL.md), 위협 모델은
[docs/SECURITY.md](docs/SECURITY.md) 에 있습니다.

배포 절차와 알려진 함정은 [docs/RELEASING.md](docs/RELEASING.md) 에 있습니다.

## 라이선스

MIT
