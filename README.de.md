# 1pass keychain (`kc`)

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-Hans.md) · [繁體中文](README.zh-Hant.md) · [Español](README.es.md) · [Français](README.fr.md) · **Deutsch**

Übertrage Secrets zwischen **den Betriebssystem-Schlüsselbunden deiner eigenen Geräte** —
macOS-Schlüsselbund, Linux Secret Service und Windows-Anmeldeinformationsverwaltung
(Credential Manager) — genau dann, wenn du sie brauchst, ohne Cloud-Tresor.

```console
# auf dem neuen Rechner
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# auf einem Rechner, der die Schlüssel hat
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **Nichts wird in der Cloud gespeichert.** Das Relay (`relay.1pass.dev`) reicht
  Ende-zu-Ende-verschlüsselte Bytes zwischen zwei Geräten weiter und vergisst sie
  innerhalb von Minuten. Klartext sieht es nie.
- **Kein Konto.** Ein Einmalcode authentifiziert die beiden Geräte (SPAKE2, dieselbe
  Idee wie magic-wormhole). Ein falscher Versuch macht den Code ungültig.
- **Gemerkte Geräte.** Einmal mit `--remember` koppeln. Danach funktioniert
  `kc send NAME --to omarchy` ohne Code, selbst wenn das andere Gerät
  bis zu 72 Stunden offline ist.
- **Sammelübertragung.** Starte `kc send` ohne Namen, um Einträge aus einer Checkliste zu wählen,
  oder nutze `--bundle new-machine.toml`.
- **Agentenfreundlich.** `kc get NAME` gibt ein Secret für Skripte und KI-Agenten
  in eine Pipe aus. Es blockiert nie an einer grafischen Entsperrabfrage und gibt ohne
  `--reveal` nichts auf einem Terminal aus.

## Installation

Mit [Homebrew](https://brew.sh) unter macOS oder Linux:

```console
$ brew install dcode-co/tap/kc
```

Mit npm oder [Bun](https://bun.sh) unter macOS, Linux oder Windows. Das Paket heißt
`1pass-keychain`, der installierte Befehl ist `kc`:

```console
$ npm install -g 1pass-keychain        # oder: bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # oder: bunx 1pass-keychain doctor (ohne Installation)
```

Oder lade das Archiv für dein System von
[Releases](https://github.com/dcode-co/1pass-keychain/releases) herunter und lege `kc`
in deinen `PATH`:

| System | Archiv |
|---|---|
| macOS, Apple Silicon | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (statisch, jede Distribution) | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (statisch, jede Distribution) | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

`SHA256SUMS` im Release enthält die Prüfsumme jedes Archivs. Die macOS-Binärdateien
sind mit einer Developer ID signiert und von Apple notarisiert.

`kc doctor` prüft den Schlüsselbund, das Relay und die Konfiguration.

**Linux** braucht einen laufenden Secret Service, etwa gnome-keyring. Desktop-Installationen
haben meist einen; ein Headless-Server oder eine Minimalinstallation unter Umständen nicht.

**Windows**: Die Anmeldeinformationsverwaltung ist in einer SSH-Sitzung, die per Schlüssel
angemeldet wurde, nicht verfügbar; starte kc daher aus einer Desktop-Sitzung.

Zum Bauen aus dem Quellcode brauchst du Rust 1.88 oder neuer:

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## Erste Schritte: einen neuen Rechner einrichten

1. Speichere das Secret einmal auf dem Rechner, der es hat:

   ```console
   $ kc set GITHUB_TOKEN              # fragt nach dem Wert; die Eingabe wird nie angezeigt
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # oder einen Eintrag kopieren, den ein anderes Tool schon hat
   ```

2. Starte auf dem neuen Rechner `kc receive`. Es zeigt einen Code wie `4721-absurd-amulet`.
3. Starte zurück auf dem ersten Rechner `kc send GITHUB_TOKEN SSH_DEPLOY_KEY` und gib
   diesen Code ein. Beide Rechner zeigen, was gesendet und gespeichert wurde.
4. Verwende die Werte auf dem neuen Rechner:

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # mit Modus 600 geschrieben
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

Ein Code gilt einmal, für 10 Minuten. Senden mit Code erfordert eine Person
am Terminal; Skripte und Agenten senden stattdessen an gemerkte Geräte.

## Gemerkte Geräte

Kopple zwei Rechner einmal, danach brauchen Sendungen keinen Code mehr:

```console
laptop$  kc pair              # zeigt einen Kopplungscode
desktop$ kc pair --join       # diesen Code eingeben
```

Jede Seite merkt sich die andere unter einem **Label**, standardmäßig ihrem Hostnamen.
`kc peers` listet sie auf; die Spalte `LABEL` ist das, was `--to` erwartet:

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # funktioniert, auch wenn desktop aus ist
desktop$ kc inbox                            # speichert, was angekommen ist (bis zu 72 Stunden aufbewahrt)
```

`kc device rename` ändert das Label, das dieser Rechner beim Koppeln vorschlägt.
`kc peers rm LABEL` hebt die Kopplung eines Geräts auf; geht ein Rechner verloren, führe es auf deinen anderen Rechnern aus.
Wann `kc device rotate` sinnvoll ist, steht in [docs/SECURITY.md](docs/SECURITY.md).

## Synchronisierung

Synchronisiere ausgewählte Einträge zwischen gekoppelten Geräten. **Standardmäßig
wird nichts synchronisiert.** Ersetze `NAME` durch den Namen eines vorhandenen Eintrags:

```console
$ kc sync add NAME          # Eintrag aufnehmen und anderen Geräten vorschlagen
$ kc sync                   # auf beiden Geräten ausführen, um Änderungen auszutauschen
$ kc sync review            # Vorschläge und zurückgehaltene Änderungen auf dem Empfänger prüfen
$ kc sync status            # Status und lokale Fingerabdrücke anzeigen, niemals Werte
```

Diese Version hält jedes Überschreiben durch ein anderes Gerät zur Prüfung zurück. Jeder
Synchronisierungsschritt, der einen Wert übernimmt, verlangt eine lokale Bestätigung
per Touch ID (oder Systempasswort), Windows Hello oder polkit. Auch die Aufnahme eines
Eintrags verlangt diese Bestätigung. Normale lokale Schreibvorgänge können Änderungen
in die Warteschlange stellen, erlauben aber kein Überschreiben auf anderen Geräten.
Bei Konflikten bleiben die möglichen Werte erhalten. Wähle mit
`kc sync resolve NAME --keep mine` oder `kc sync resolve NAME --keep LABEL` einen Wert.
Die anderen Geräte müssen auch dieses Ergebnis prüfen. `kc sync freeze` stoppt die
Übernahme eingehender Änderungen ohne Bestätigung; `kc sync unfreeze` verlangt eine
Bestätigung des Betriebssystems. Exit-Code 8 bedeutet, dass noch Arbeit aussteht oder
blockiert ist. Siehe die [Sicherheitsgrenzen](docs/SECURITY.md).

## Befehle

| Befehl | Funktion |
|---|---|
| `kc set NAME` | speichert einen Wert aus stdin oder einer verdeckten Eingabe (`--from-file PATH` für ganze Dateien) |
| `kc get NAME` | gibt einen Wert in eine Pipe aus (`--to-file PATH` schreibt ihn mit Modus 600, `--reveal` gibt ihn auf einem Terminal aus) |
| `kc exec --env VAR=NAME -- CMD…` | führt einen Befehl mit Werten in seiner Umgebung aus, ohne Shell |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | auflisten, entfernen oder das letzte Überschreiben rückgängig machen |
| `kc adopt --service S [--account A] [--as NAME]` | kopiert einen vorhandenen Schlüsselbundeintrag in kc |
| `kc receive` / `kc send [NAMES…]` | überträgt Einträge mit einem Einmalcode |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | gemerkte Geräte |
| `kc sync` | ausgewählte Einträge mit gekoppelten Geräten synchronisieren |
| `kc doctor` | prüft den Schlüsselbund, das Relay und die Konfiguration |

## Fehlerbehebung

- **`kc doctor` meldet `device FAIL: the OS keychain refused access`** (macOS).
  Der Schlüsselbund fragt nach, bevor ein anderes kc-Binary Einträge liest, die ein
  anderes gespeichert hat, zum Beispiel nach einem Wechsel zwischen Homebrew, npm und
  einem Build aus dem Quellcode. Führe den fehlschlagenden Befehl (oder `kc doctor`)
  einmal im Terminal aus und wähle **Immer erlauben**; `kc --help` und
  `kc --version` greifen nicht auf den Schlüsselbund zu. Skripte und Agenten können diese Abfrage nicht
  beantworten, also erledige das, bevor sie laufen.
- **`kc: … is missing. Reinstall 1pass-keychain with optional dependencies
  enabled`** (npm oder Bun). Das Binary steckt in einem plattformspezifischen
  Paket, das npm als optionale Abhängigkeit installiert: `1pass-keychain-darwin-arm64`,
  `-darwin-x64`, `-linux-arm64`, `-linux-x64` und `@1pass/keychain-win32-x64`
  für Windows. Bei einer Installation mit `--omit=optional` (oder `--no-optional`)
  fehlt es; installiere ohne diese Option neu.
- **Windows: `no Credential Manager logon session`.** In einer SSH-Sitzung, die sich
  mit einem Schlüssel angemeldet hat, gibt es keine Anmeldeinformationsverwaltung. Führe kc
  in einer Desktop-Sitzung aus oder verbinde dich per SSH mit einem Passwort.
- **Linux: Der Schlüsselbund ist nicht verfügbar.** Starte einen Secret Service (zum Beispiel
  gnome-keyring) und entsperre ihn; `kc doctor` sagt, welcher Teil fehlt.
- **Meldungen in der falschen Sprache.** Setze `KC_LANG` (siehe Sprachen unten).
  Wenn weder stdout noch stderr ein Terminal ist (Skripte, Agenten), schreibt kc
  Englisch, sofern `KC_LANG` nicht gesetzt ist.

## Sprachen

Die Meldungen von kc und `kc --help` gibt es auf English, 한국어, 日本語, 简体中文, 繁體中文,
Español, Français und Deutsch. Am Terminal folgt kc deinem Gebietsschema (`LC_ALL`,
`LC_MESSAGES`, `LANG` und `LANGUAGE`, danach der Systemsprache). Skripte und
Agenten erhalten Englisch, sofern `KC_LANG` nicht gesetzt ist. Wähle eine Sprache mit `KC_LANG`:

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` akzeptiert `en`, `ko`, `ja`, `zh-Hans`, `zh-Hant`, `es`, `fr` oder `de`.
Werte, Eintragsnamen, Codes und JSON-Ausgabe werden nie übersetzt.

## Status

Frühe Version (v0.2). Auf echten Rechnern getestet:

- gekoppelte Sendungen in beide Richtungen zwischen macOS und Linux sowie zwischen macOS und Windows 11
- eine Sendung mit Einmalcode von macOS nach Linux
- Speichern, Lesen und Entfernen von Einträgen im Schlüsselbund jedes Betriebssystems

Noch nicht auf echten Rechnern getestet: Sendungen mit Einmalcode von Linux oder Windows aus.
Das PAKE-Crate wurde noch nicht unabhängig geprüft. Das Protokoll steht in
[docs/PROTOCOL.md](docs/PROTOCOL.md), das Bedrohungsmodell in
[docs/SECURITY.md](docs/SECURITY.md).

Für Maintainer: Release-Schritte und bekannte Fallstricke stehen in
[docs/RELEASING.md](docs/RELEASING.md).

## Lizenz

MIT
