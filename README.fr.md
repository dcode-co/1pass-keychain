# 1pass keychain (`kc`)

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-Hans.md) · [繁體中文](README.zh-Hant.md) · [Español](README.es.md) · **Français** · [Deutsch](README.de.md)

Transférez des secrets entre **les trousseaux système de vos propres appareils** — le
trousseau macOS, Linux Secret Service et le Gestionnaire d'identification de
Windows (Credential Manager) — au moment où vous en avez besoin, sans coffre-fort dans le cloud.

```console
# sur la nouvelle machine
$ kc receive
Code: 4721-absurd-amulet   (waiting up to 10 minutes)

# sur une machine qui possède les clés
$ kc send GITHUB_TOKEN RENDER_API_KEY
Code: 4721-absurd-amulet
Sent 2 items. omarchy accepted 2.
```

- **Rien n'est stocké dans le cloud.** Le relais (`relay.1pass.dev`) transmet
  des octets chiffrés de bout en bout entre deux appareils et les oublie en
  quelques minutes. Il ne voit jamais le texte en clair.
- **Aucun compte.** Un code à usage unique authentifie les deux appareils (SPAKE2,
  la même idée que magic-wormhole). Une seule mauvaise tentative invalide le code.
- **Appareils mémorisés.** Appairez une fois avec `--remember`. Ensuite,
  `kc send NAME --to omarchy` fonctionne sans code, même si l'autre appareil
  reste hors ligne jusqu'à 72 heures.
- **Transferts groupés.** Lancez `kc send` sans nom pour choisir des éléments dans une liste,
  ou utilisez `--bundle new-machine.toml`.
- **Adapté aux agents.** `kc get NAME` écrit un secret dans un tube pour les scripts et
  les agents IA. Il ne bloque jamais sur une invite graphique de déverrouillage et n'écrit pas
  dans un terminal sans `--reveal`.

## Installation

Avec [Homebrew](https://brew.sh) sur macOS ou Linux :

```console
$ brew install dcode-co/tap/kc
```

Avec npm ou [Bun](https://bun.sh) sur macOS, Linux ou Windows. Le paquet s'appelle
`1pass-keychain` ; la commande installée est `kc` :

```console
$ npm install -g 1pass-keychain        # ou : bun install -g 1pass-keychain
$ npx 1pass-keychain doctor            # ou : bunx 1pass-keychain doctor (sans installation)
```

Ou téléchargez l'archive correspondant à votre système depuis
[Releases](https://github.com/dcode-co/1pass-keychain/releases) et placez `kc`
dans votre `PATH` :

| Système | Archive |
|---|---|
| macOS, puce Apple | `kc-<version>-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `kc-<version>-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 (statique, toute distribution) | `kc-<version>-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (statique, toute distribution) | `kc-<version>-aarch64-unknown-linux-musl.tar.gz` |
| Windows x86_64 | `kc-<version>-x86_64-pc-windows-msvc.zip` |

```console
$ tar -xzf kc-v0.2.0-aarch64-apple-darwin.tar.gz
$ install -m 755 kc-v0.2.0-aarch64-apple-darwin/kc ~/.local/bin/kc
$ kc doctor
```

Le fichier `SHA256SUMS` de la version publiée liste la somme de contrôle de chaque archive. Les binaires macOS
sont signés avec un Developer ID et notariés par Apple.

`kc doctor` vérifie le trousseau, le relais et la configuration.

**Linux** nécessite un Secret Service en cours d'exécution, comme gnome-keyring. Les installations
de bureau en ont généralement un ; un serveur sans interface graphique ou une installation minimale peut ne pas en avoir.

**Windows** : le Gestionnaire d'identification n'est pas disponible dans une session SSH ouverte
avec une clé ; lancez donc kc depuis une session de bureau.

Pour compiler depuis les sources, utilisez Rust 1.88 ou une version plus récente :

```console
$ cargo install --locked --git https://github.com/dcode-co/1pass-keychain kc-cli
```

## Première utilisation : configurer une nouvelle machine

1. Sur la machine qui possède le secret, enregistrez-le une fois :

   ```console
   $ kc set GITHUB_TOKEN              # demande la valeur ; elle ne s'affiche jamais
   $ kc set SSH_DEPLOY_KEY --from-file ~/.ssh/deploy_key
   $ kc adopt --service my-cli        # ou copiez une entrée qu'un autre outil conserve déjà
   ```

2. Sur la nouvelle machine, lancez `kc receive`. Un code comme `4721-absurd-amulet` s'affiche.
3. De retour sur la première machine, lancez `kc send GITHUB_TOKEN SSH_DEPLOY_KEY` et saisissez
   ce code. Les deux machines affichent ce qui a été envoyé et enregistré.
4. Sur la nouvelle machine, utilisez les valeurs :

   ```console
   $ kc get SSH_DEPLOY_KEY --to-file ~/.ssh/deploy_key   # écrit avec le mode 600
   $ kc exec --env GITHUB_TOKEN=GITHUB_TOKEN -- gh repo list
   ```

Un code ne sert qu'une fois, pendant 10 minutes. Envoyer avec un code nécessite une personne
devant un terminal ; les scripts et les agents envoient plutôt vers des appareils mémorisés.

## Appareils mémorisés

Appairez deux machines une fois, et les envois suivants n'ont plus besoin de code :

```console
laptop$  kc pair              # affiche un code d'appairage
desktop$ kc pair --join       # saisissez ce code
```

Chaque côté mémorise l'autre sous une **étiquette**, par défaut son nom d'hôte.
`kc peers` les liste ; la colonne `LABEL` est ce qu'attend `--to` :

```console
laptop$ kc peers
LABEL    FINGERPRINT          PAIRED
desktop  0faf-98f4-0dfe-7133  2026-10-12T13:08:13Z

laptop$ kc send GITHUB_TOKEN --to desktop    # fonctionne même si desktop est éteint
desktop$ kc inbox                            # enregistre ce qui est arrivé (conservé jusqu'à 72 heures)
```

`kc device rename` modifie l'étiquette que cette machine propose lors de l'appairage.
`kc peers rm LABEL` supprime l'appairage d'un appareil ; si une machine est perdue, lancez-le sur vos autres machines.
Consultez [docs/SECURITY.md](docs/SECURITY.md) pour savoir quand utiliser `kc device rotate`.

## Synchronisation

Synchronisez les éléments choisis entre appareils appairés. **Rien n’est
synchronisé par défaut.** Remplacez `NAME` par le nom d’un élément existant :

```console
$ kc sync add NAME          # inscrit l’élément et le propose aux autres appareils
$ kc sync                   # à lancer sur les deux appareils pour échanger les modifications
$ kc sync review            # examine les propositions et modifications en attente sur le destinataire
$ kc sync status            # affiche l’état et les empreintes locales, jamais les valeurs
```

Dans cette version, tout écrasement distant attend une vérification humaine. Chaque étape de
synchronisation qui applique une valeur demande une confirmation locale via Touch ID
(ou le mot de passe du système), Windows Hello ou polkit. L’inscription d’un élément
exige aussi cette confirmation. Les écritures locales ordinaires peuvent mettre des
modifications en file d’attente, sans autoriser d’écrasement sur les autres appareils.
Les valeurs en conflit sont conservées : choisissez avec `kc sync resolve NAME --keep mine`
ou `kc sync resolve NAME --keep LABEL`. Les autres appareils doivent aussi examiner le
résultat. `kc sync freeze` suspend l’application des modifications entrantes sans
confirmation ; `kc sync unfreeze` exige une confirmation du système. Le code de sortie 8
signale du travail en attente ou bloqué. Voir les [limites de sécurité](docs/SECURITY.md).

## Commandes

| Commande | Rôle |
|---|---|
| `kc set NAME` | enregistre une valeur lue sur stdin ou via une invite masquée (`--from-file PATH` pour des fichiers entiers) |
| `kc get NAME` | écrit une valeur dans un tube (`--to-file PATH` l'écrit avec le mode 600, `--reveal` l'affiche dans un terminal) |
| `kc exec --env VAR=NAME -- CMD…` | exécute une commande avec des valeurs dans son environnement, sans shell |
| `kc list [--verify]` / `kc rm NAME` / `kc restore NAME` | lister, supprimer ou annuler le dernier écrasement |
| `kc adopt --service S [--account A] [--as NAME]` | copie un élément existant du trousseau dans kc |
| `kc receive` / `kc send [NAMES…]` | transfère des éléments avec un code à usage unique |
| `kc pair`, `kc peers`, `kc inbox`, `kc device` | appareils mémorisés |
| `kc sync` | synchronise les éléments choisis avec les appareils appairés |
| `kc doctor` | vérifie le trousseau, le relais et la configuration |

## Dépannage

- **`kc doctor` affiche `device FAIL: the OS keychain refused access`** (macOS).
  Le trousseau demande une autorisation avant qu'un autre binaire kc lise des éléments
  enregistrés par un autre, par exemple après être passé de Homebrew à npm ou à une
  compilation depuis les sources. Lancez une fois dans un terminal la commande qui échoue
  (ou `kc doctor`) et choisissez **Toujours autoriser** ; `kc --help` et
  `kc --version` n'accèdent pas au trousseau. Les scripts et les agents ne peuvent pas répondre
  à cette demande ; faites-le donc avant de les lancer.
- **`kc: … is missing. Reinstall 1pass-keychain with optional dependencies
  enabled`** (npm ou Bun). Le binaire est fourni dans un paquet par plateforme
  que npm installe comme dépendance optionnelle : `1pass-keychain-darwin-arm64`,
  `-darwin-x64`, `-linux-arm64`, `-linux-x64`, et `@1pass/keychain-win32-x64`
  pour Windows. Une installation avec `--omit=optional` (ou `--no-optional`)
  l'omet ; réinstallez sans cette option.
- **macOS via SSH : le trousseau est verrouillé ou n'est pas disponible.** macOS garde
  le trousseau de session verrouillé dans une session SSH, donc aucune demande du
  trousseau ne peut s'y afficher. Lancez kc dans un terminal sur le Mac lui-même, ou
  lancez d'abord `security unlock-keychain ~/Library/Keychains/login.keychain-db`
  dans la session SSH (il demande le mot de passe de session du Mac).
- **Windows : `no Credential Manager logon session`.** Le Gestionnaire d'identification
  n'existe pas dans une session SSH ouverte avec une clé. Lancez kc depuis une
  session de bureau, ou depuis un processus démarré avec votre mot de passe Windows
  (par exemple `Start-Process -Credential` dans PowerShell), qui obtient une session
  de connexion complète. Se connecter en SSH avec un mot de passe n'est pas une solution
  fiable : Windows peut le refuser pour un compte Microsoft même si le mot de passe est bon.
- **Linux : le trousseau n'est pas disponible.** Démarrez un Secret Service (par exemple
  gnome-keyring) et déverrouillez-le ; `kc doctor` indique ce qui manque.
- **Messages dans la mauvaise langue.** Définissez `KC_LANG` (voir Langues ci-dessous).
  Quand ni stdout ni stderr ne sont un terminal (scripts, agents), kc écrit en
  anglais sauf si `KC_LANG` est défini.

## Langues

Les messages de kc et `kc --help` existent en English, 한국어, 日本語, 简体中文, 繁體中文,
Español, Français et Deutsch. Dans un terminal, kc suit vos paramètres régionaux (`LC_ALL`,
`LC_MESSAGES`, `LANG` et `LANGUAGE`, puis la langue du système). Les scripts et
les agents reçoivent l'anglais sauf si `KC_LANG` est défini. Choisissez une langue avec `KC_LANG` :

```console
$ KC_LANG=ko kc doctor
```

`KC_LANG` accepte `en`, `ko`, `ja`, `zh-Hans`, `zh-Hant`, `es`, `fr` ou `de`.
Les valeurs, noms d'éléments, codes et la sortie JSON ne sont jamais traduits.

## État

Version préliminaire (v0.2). Testé sur de vraies machines :

- envois appairés dans les deux sens entre macOS et Linux, et entre macOS et Windows 11
- un envoi avec code à usage unique de macOS vers Linux
- enregistrement, lecture et suppression d'éléments dans le trousseau de chaque système

Pas encore testé sur de vraies machines : les envois avec code à usage unique depuis Linux ou Windows.
Le crate PAKE n'a pas fait l'objet d'un audit indépendant. Le protocole est décrit dans
[docs/PROTOCOL.md](docs/PROTOCOL.md) et le modèle de menace dans
[docs/SECURITY.md](docs/SECURITY.md).

Mainteneurs : les étapes de publication et les pièges connus sont décrits dans
[docs/RELEASING.md](docs/RELEASING.md).

## Licence

MIT
