//! Messages for people in the reader's language.
//!
//! The English text in the source is the key: [`tr!`] looks it up in the catalog of the
//! current language (`locales/<lang>.toml`, compiled in) and fills `{name}` placeholders.
//! A missing entry falls back to the English text, so an incomplete catalog never hides
//! a message. The tests in this module keep every catalog complete and its placeholders in
//! step with the source.
//!
//! What is never translated: data on stdout (values, JSON, names), pairing codes and their
//! words (they are part of the protocol), and clap's own parse errors and "Possible values"
//! lists.
//!
//! Which language: `KC_LANG` if set (`ko`, `ja`, `zh-Hans`, `zh-Hant`, `es`, `fr`, `de`,
//! `en`). Otherwise English unless a person is reading (stdout or stderr is a terminal);
//! then the POSIX locale (`LC_ALL`, `LC_MESSAGES`, `LANG`, and `LANGUAGE`), then the
//! system's preferred language. Agents and scripts therefore keep getting English.
//!
//! The current language belongs to the run: [`crate::run`] picks it once and runs the
//! command inside [`scope`], so runs joined on one thread (the tests' two devices) keep
//! their own. [`set`] covers code outside a run.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::OnceLock;

use crate::host::Host;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    En,
    Ko,
    Ja,
    ZhHans,
    ZhHant,
    Es,
    Fr,
    De,
}

impl Lang {
    /// Every language with a catalog (all but English, the source).
    pub const TRANSLATED: [Lang; 7] = [
        Lang::Ko,
        Lang::Ja,
        Lang::ZhHans,
        Lang::ZhHant,
        Lang::Es,
        Lang::Fr,
        Lang::De,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ko => "ko",
            Lang::Ja => "ja",
            Lang::ZhHans => "zh-Hans",
            Lang::ZhHant => "zh-Hant",
            Lang::Es => "es",
            Lang::Fr => "fr",
            Lang::De => "de",
        }
    }

    /// A locale name such as `ko_KR.UTF-8`, `zh-Hant-TW`, `pt_BR` or `C`. `None` when kc
    /// has no catalog for it.
    pub fn parse(locale: &str) -> Option<Lang> {
        let base = locale
            .split(['.', '@'])
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .replace('_', "-");
        let mut parts = base.split('-');
        let lang = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();
        Some(match lang {
            "en" => Lang::En,
            "ko" => Lang::Ko,
            "ja" => Lang::Ja,
            "zh" => {
                let traditional = rest
                    .iter()
                    .any(|p| matches!(*p, "hant" | "tw" | "hk" | "mo"));
                let simplified = rest.contains(&"hans");
                if traditional && !simplified {
                    Lang::ZhHant
                } else {
                    Lang::ZhHans
                }
            }
            "es" => Lang::Es,
            "fr" => Lang::Fr,
            "de" => Lang::De,
            _ => return None,
        })
    }

    fn catalog_source(self) -> &'static str {
        match self {
            Lang::En => "",
            Lang::Ko => include_str!("../locales/ko.toml"),
            Lang::Ja => include_str!("../locales/ja.toml"),
            Lang::ZhHans => include_str!("../locales/zh-Hans.toml"),
            Lang::ZhHant => include_str!("../locales/zh-Hant.toml"),
            Lang::Es => include_str!("../locales/es.toml"),
            Lang::Fr => include_str!("../locales/fr.toml"),
            Lang::De => include_str!("../locales/de.toml"),
        }
    }
}

/// Overrides the language for every run (`KC_LANG=ko`).
pub const ENV_LANG: &str = "KC_LANG";

/// Picks the language for this run; see the module docs.
pub fn choose<H: Host + ?Sized>(host: &H) -> Lang {
    choose_from(
        |key| host.env_var(key).and_then(|v| v.into_string().ok()),
        host.stdout_is_terminal() || host.stderr_is_terminal(),
        || host.system_locale(),
    )
}

/// [`choose`] without a host: `env` reads a variable, `terminal` says whether a person is
/// reading, `system` asks the OS for its preferred language.
pub fn choose_from(
    env: impl Fn(&str) -> Option<String>,
    terminal: bool,
    system: impl FnOnce() -> Option<String>,
) -> Lang {
    let env = |key: &str| env(key).filter(|v| !v.trim().is_empty());
    if let Some(v) = env(ENV_LANG) {
        return Lang::parse(&v).unwrap_or(Lang::En);
    }
    if !terminal {
        return Lang::En;
    }
    let posix = env("LC_ALL")
        .or_else(|| env("LC_MESSAGES"))
        .or_else(|| env("LANG"));
    if let Some(locale) = &posix {
        if matches!(locale.as_str(), "C" | "POSIX") || locale.starts_with("C.") {
            return Lang::En;
        }
        // GNU gettext: LANGUAGE is a preference list that wins over the locale.
        if let Some(lang) = env("LANGUAGE").and_then(|list| list.split(':').find_map(Lang::parse)) {
            return lang;
        }
        return Lang::parse(locale).unwrap_or(Lang::En);
    }
    if let Some(lang) = env("LANGUAGE").and_then(|list| list.split(':').find_map(Lang::parse)) {
        return lang;
    }
    system().and_then(|l| Lang::parse(&l)).unwrap_or(Lang::En)
}

thread_local! {
    static CURRENT: Cell<Lang> = const { Cell::new(Lang::En) };
}

tokio::task_local! {
    static TASK_LANG: Lang;
}

/// Sets the language for code that runs outside [`scope`] on this thread.
pub fn set(lang: Lang) {
    CURRENT.with(|c| c.set(lang));
}

/// Runs `fut` with `lang` as its language. Two runs joined on one thread (the tests'
/// two devices) each keep their own.
pub async fn scope<F: std::future::Future>(lang: Lang, fut: F) -> F::Output {
    TASK_LANG.scope(lang, fut).await
}

pub fn current() -> Lang {
    TASK_LANG
        .try_with(|lang| *lang)
        .unwrap_or_else(|_| CURRENT.with(Cell::get))
}

fn catalog(lang: Lang) -> &'static HashMap<String, String> {
    static CATALOGS: OnceLock<HashMap<Lang, HashMap<String, String>>> = OnceLock::new();
    static EMPTY: OnceLock<HashMap<String, String>> = OnceLock::new();
    let all = CATALOGS.get_or_init(|| {
        Lang::TRANSLATED
            .iter()
            .map(|&l| (l, parse_catalog(l.catalog_source()).unwrap_or_default()))
            .collect()
    });
    all.get(&lang)
        .unwrap_or_else(|| EMPTY.get_or_init(HashMap::new))
}

/// A catalog file: a `[messages]` table from English text to its translation.
pub fn parse_catalog(source: &str) -> Result<HashMap<String, String>, String> {
    #[derive(serde::Deserialize)]
    struct File {
        #[serde(default)]
        messages: HashMap<String, String>,
    }
    toml::from_str::<File>(source)
        .map(|f| f.messages)
        .map_err(|e| e.to_string())
}

/// The current language's text for `english`, or `english` itself.
pub fn lookup(english: &str) -> &str {
    let lang = current();
    if lang == Lang::En {
        return english;
    }
    match catalog(lang).get(english) {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => english,
    }
}

/// Replaces `{name}` with the matching argument; `{{` and `}}` are literal braces. An
/// unknown placeholder stays as it is.
pub fn fill(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(i) = rest.find(['{', '}']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if tail.starts_with("{{") || tail.starts_with("}}") {
            out.push_str(&tail[..1]);
            rest = &tail[2..];
            continue;
        }
        if let Some(end) = tail.starts_with('{').then(|| tail.find('}')).flatten() {
            let name = &tail[1..end];
            if let Some((_, value)) = args.iter().find(|(k, _)| *k == name) {
                out.push_str(&value.to_string());
                rest = &tail[end + 1..];
                continue;
            }
        }
        out.push_str(&tail[..1]);
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

/// The translated text before and after the one placeholder `{name}` in `english`. For
/// messages that show a code or its words: the caller formats the secret straight into the
/// output, so no extra unwiped copy of it is made the way [`fill`] would.
pub fn around<'a>(english: &'a str, name: &str) -> (&'a str, &'a str) {
    let text = lookup(english);
    let mark = format!("{{{name}}}");
    text.split_once(mark.as_str()).unwrap_or((text, ""))
}

/// A message for people, in the current language: `tr!("Stored {name}.", name = item)`.
/// The first argument must be a string literal (the tests collect them from the source).
/// Placeholders are `{name}` only, with no format specs; pad or align after translating.
macro_rules! tr {
    ($text:literal) => {
        $crate::i18n::fill($crate::i18n::lookup($text), &[])
    };
    ($text:literal, $($key:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::fill(
            $crate::i18n::lookup($text),
            &[$((stringify!($key), &$value as &dyn ::std::fmt::Display)),+],
        )
    };
}
pub(crate) use tr;

/// `kc --help` in the current language: about texts, argument help, the section headings
/// and clap's built-in help and version flags.
pub fn localize(cmd: clap::Command) -> clap::Command {
    if current() == Lang::En {
        return cmd;
    }
    let mut cmd = cmd;
    cmd.build();
    localize_built(cmd)
}

fn localize_built(mut cmd: clap::Command) -> clap::Command {
    let template = format!(
        "{{before-help}}{{about-with-newline}}\n{} {{usage}}\n\n{{all-args}}{{after-help}}",
        styled_heading(lookup("Usage:"))
    );
    cmd = cmd
        .help_template(template)
        .subcommand_help_heading(lookup("Commands"));
    if let Some(about) = cmd.get_about().map(ToString::to_string) {
        cmd = cmd.about(lookup(&about).to_string());
    }
    if let Some(long) = cmd.get_long_about().map(ToString::to_string) {
        cmd = cmd.long_about(lookup(&long).to_string());
    }
    let args: Vec<(clap::Id, Option<String>, Option<String>, bool)> = cmd
        .get_arguments()
        .map(|a| {
            (
                a.get_id().clone(),
                a.get_help().map(ToString::to_string),
                a.get_long_help().map(ToString::to_string),
                a.is_positional(),
            )
        })
        .collect();
    for (id, help, long, positional) in args {
        let heading: &'static str = lookup(if positional { "Arguments" } else { "Options" });
        cmd = cmd.mut_arg(id, |mut a| {
            if let Some(h) = &help {
                a = a.help(lookup(h).to_string());
            }
            if let Some(l) = &long {
                a = a.long_help(lookup(l).to_string());
            }
            a.help_heading(heading)
        });
    }
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in names {
        cmd = cmd.mut_subcommand(name, localize_built);
    }
    cmd
}

/// Section headings are bold and underlined in clap's default styles.
fn styled_heading(text: &str) -> String {
    let style = *clap::builder::Styles::default().get_usage();
    format!("{style}{text}{style:#}")
}

/// Every text [`localize`] looks up for `cmd`, for the catalog tests.
pub fn help_texts(cmd: clap::Command) -> Vec<String> {
    let mut cmd = cmd;
    cmd.build();
    let mut out = vec![
        "Usage:".to_string(),
        "Commands".to_string(),
        "Options".to_string(),
        "Arguments".to_string(),
    ];
    collect_help(&cmd, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_help(cmd: &clap::Command, out: &mut Vec<String>) {
    out.extend(cmd.get_about().map(ToString::to_string));
    out.extend(cmd.get_long_about().map(ToString::to_string));
    for a in cmd.get_arguments() {
        out.extend(a.get_help().map(ToString::to_string));
        out.extend(a.get_long_help().map(ToString::to_string));
    }
    for s in cmd.get_subcommands() {
        collect_help(s, out);
    }
}

#[cfg(test)]
mod tests;
