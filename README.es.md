# 1pass keychain (`kc`)

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-Hans.md) · [繁體中文](README.zh-Hant.md) · **Español** · [Français](README.fr.md) · [Deutsch](README.de.md)

Mueve secretos entre **los llaveros del sistema de tus propios dispositivos**: el
Llavero de macOS, Linux Secret Service y el Administrador de credenciales de
Windows (Credential Manager), en el momento en que los necesitas y sin una bóveda en la nube.

```console
# en la máquina nueva
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# en una máquina que tiene las claves
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **No se guarda nada en la nube.** El relé (`relay.1pass.dev`) transmite
  bytes cifrados de extremo a extremo entre dos dispositivos y los olvida en
  pocos minutos. Nunca ve el texto en claro.
- **Sin cuenta.** Un código de un solo uso autentica los dos dispositivos (SPAKE2,
  la misma idea que magic-wormhole). Un intento fallido invalida el código.
- **Dispositivos recordados.** Empareja una vez con `--remember`. Después,
  `kc send NAME --to omarchy` funciona sin código, incluso si el otro dispositivo
  está desconectado hasta 72 horas.
- **Envíos en bloque.** Ejecuta `kc send` sin nombres para elegir elementos de una lista,
  o usa `--bundle new-machine.toml`.
- **Pensado para agentes.** `kc get NAME` escribe un secreto en una tubería para scripts y
  agentes de IA. Nunca se bloquea en un aviso gráfico de desbloqueo y no escribe en una
  terminal sin `--reveal`.

## Instalación

Con [Homebrew](https://brew.sh) en macOS o Linux:

```console
$ brew install dcode-co/tap/kc
```

Con npm o [Bun](https://bun.sh) en macOS, Linux o Windows. El paquete es
`1pass-keychain`; el comando que instala es `kc`:

```console
$ npm install -g 1pass-keychain        # o: bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # o: bunx 1pass-keychain doctor (sin instalar)
```

O descarga el archivo para tu sistema desde
[Releases](https://github.com/dcode-co/1pass-keychain/releases) y coloca `kc`
en tu `PATH`:

| Sistema | Archivo |
|---|---|
| macOS, Apple silicon | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (estático, cualquier distribución) | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (estático, cualquier distribución) | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

`SHA256SUMS` en la versión publicada contiene la suma de verificación de cada archivo. Los binarios de macOS
están firmados con un Developer ID y notarizados por Apple.

`kc doctor` comprueba el llavero, el relé y la configuración.

**Linux** necesita un Secret Service en ejecución, como gnome-keyring. Las instalaciones
de escritorio suelen tenerlo; un servidor sin interfaz gráfica o una instalación mínima puede que no.

**Windows**: el Administrador de credenciales no está disponible en una sesión SSH iniciada
con una clave, así que ejecuta kc desde una sesión de escritorio.

Para compilar desde el código fuente, usa Rust 1.88 o posterior:

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## Primer uso: configurar una máquina nueva

1. En la máquina que tiene el secreto, guárdalo una vez:

   ```console
   $ kc set GITHUB_TOKEN              # pide el valor; nunca lo muestra
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # o copia una entrada que ya guarda otra herramienta
   ```

2. En la máquina nueva, ejecuta `kc receive`. Muestra un código como `4721-absurd-amulet`.
3. De vuelta en la primera máquina, ejecuta `kc send GITHUB_TOKEN SSH_DEPLOY_KEY` y escribe
   ese código. Ambas máquinas muestran lo que se envió y se guardó.
4. En la máquina nueva, usa los valores:

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # se escribe con modo 600
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

Un código funciona una sola vez, durante 10 minutos. Enviar con código requiere una persona
en la terminal; los scripts y agentes envían a dispositivos recordados.

## Dispositivos recordados

Empareja dos máquinas una vez y los envíos posteriores no necesitan código:

```console
laptop$  kc pair              # muestra un código de emparejamiento
desktop$ kc pair --join       # escribe ese código
```

Cada lado recuerda al otro con una **etiqueta**, por defecto su nombre de host.
`kc peers` los lista; la columna `LABEL` es lo que acepta `--to`:

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # funciona aunque desktop esté apagado
desktop$ kc inbox                            # guarda lo que llegó (se conserva hasta 72 horas)
```

`kc device rename` cambia la etiqueta que esta máquina sugiere al emparejar.
`kc peers rm LABEL` desempareja un dispositivo; si pierdes una máquina, ejecútalo en las demás.
Consulta [docs/SECURITY.md](docs/SECURITY.md) para saber cuándo usar `kc device rotate`.

## Sincronización

Sincroniza los elementos que elijas entre dispositivos emparejados. **No se
sincroniza nada por defecto.** Sustituye `NAME` por el nombre de un elemento existente:

```console
$ kc sync add NAME          # incluye el elemento y lo propone a los otros dispositivos
$ kc sync                   # ejecútalo en ambos dispositivos para intercambiar cambios
$ kc sync review            # revisa propuestas y cambios retenidos en el receptor
$ kc sync status            # muestra el estado y las huellas locales, nunca los valores
```

En esta versión, toda sobrescritura remota queda pendiente de revisión. Cada paso de
sincronización que aplica un valor pide confirmación local mediante Touch ID
(o la contraseña del sistema), Windows Hello o polkit. Incluir un elemento también
requiere confirmación. Las escrituras locales normales pueden poner cambios en cola,
pero no autorizan sobrescrituras en otros dispositivos. Los conflictos conservan los
valores candidatos: elige con `kc sync resolve NAME --keep mine` o
`kc sync resolve NAME --keep LABEL`. Los demás dispositivos también revisan el resultado.
`kc sync freeze` detiene la aplicación de cambios entrantes sin pedir confirmación;
`kc sync unfreeze` requiere confirmación del sistema. El código de salida 8 indica
trabajo pendiente o bloqueado. Consulta los [límites de seguridad](docs/SECURITY.md).

## Comandos

| Comando | Qué hace |
|---|---|
| `kc set NAME` | guarda un valor leído de stdin o de un aviso oculto (`--from-file PATH` para archivos completos) |
| `kc get NAME` | escribe un valor en una tubería (`--to-file PATH` lo escribe con modo 600, `--reveal` lo muestra en la terminal) |
| `kc exec --env VAR=NAME -- CMD…` | ejecuta un comando con valores en su entorno, sin shell |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | listar, eliminar o deshacer la última sobrescritura |
| `kc adopt --service S [--account A] [--as NAME]` | copia un elemento existente del llavero a kc |
| `kc receive` / `kc send [NAMES…]` | mueve elementos con un código de un solo uso |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | dispositivos recordados |
| `kc sync` | sincroniza elementos seleccionados con dispositivos emparejados |
| `kc doctor` | comprueba el llavero, el relé y la configuración |

## Solución de problemas

- **`kc doctor` muestra `device FAIL: the OS keychain refused access`** (macOS).
  El llavero pregunta antes de que un binario de kc distinto lea elementos que guardó otro,
  por ejemplo tras cambiar entre Homebrew, npm y una compilación desde el código fuente.
  Ejecuta una vez en una terminal el comando que falla (o `kc doctor`) y elige
  **Permitir siempre**; `kc --help` y `kc --version` no acceden al llavero.
  Los scripts y agentes no pueden responder a ese aviso, así que hazlo antes de que se ejecuten.
- **`kc: … is missing. Reinstall 1pass-keychain with optional dependencies
  enabled`** (npm o Bun). El binario viene en un paquete por plataforma que
  npm instala como dependencia opcional: `1pass-keychain-darwin-arm64`,
  `-darwin-x64`, `-linux-arm64`, `-linux-x64` y `@1pass/keychain-win32-x64`
  para Windows. Instalar con `--omit=optional` (o `--no-optional`) lo omite;
  reinstala sin esa opción.
- **Windows: `no Credential Manager logon session`.** El Administrador de credenciales
  no existe en una sesión SSH iniciada con una clave. Ejecuta kc desde una
  sesión de escritorio o conéctate por SSH con una contraseña.
- **Linux: el llavero no está disponible.** Inicia un Secret Service (por ejemplo
  gnome-keyring) y desbloquéalo; `kc doctor` indica qué parte falta.
- **Mensajes en el idioma equivocado.** Define `KC_LANG` (consulta Idiomas más abajo).
  Cuando ni stdout ni stderr son una terminal (scripts, agentes), kc escribe en
  inglés salvo que `KC_LANG` esté definido.

## Idiomas

Los mensajes de kc y `kc --help` están disponibles en English, 한국어, 日本語, 简体中文, 繁體中文,
Español, Français y Deutsch. En una terminal, kc sigue tu configuración regional (`LC_ALL`,
`LC_MESSAGES`, `LANG` y `LANGUAGE`, y luego el idioma del sistema). Los scripts y
agentes reciben inglés salvo que `KC_LANG` esté definido. Elige uno con `KC_LANG`:

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` acepta `en`, `ko`, `ja`, `zh-Hans`, `zh-Hant`, `es`, `fr` o `de`.
Los valores, nombres de elementos, códigos y la salida JSON nunca se traducen.

## Estado

Versión temprana (v0.2). Probado en máquinas reales:

- envíos emparejados en ambos sentidos entre macOS y Linux, y entre macOS y Windows 11
- un envío con código de un solo uso de macOS a Linux
- guardar, leer y eliminar elementos en el llavero de cada sistema operativo

Aún sin probar en máquinas reales: envíos con código de un solo uso desde Linux o Windows.
El crate de PAKE no ha tenido una auditoría independiente. El protocolo está en
[docs/PROTOCOL.md](docs/PROTOCOL.md) y el modelo de amenazas en
[docs/SECURITY.md](docs/SECURITY.md).

Mantenedores: los pasos de publicación y los problemas conocidos están en
[docs/RELEASING.md](docs/RELEASING.md).

## Licencia

MIT
