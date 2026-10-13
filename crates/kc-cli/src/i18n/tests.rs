use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use clap::CommandFactory as _;

use super::*;
use crate::cli::Cli;

/// Every `tr!("…")` literal under `src/`, unescaped.
fn source_texts() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            // The i18n module's own docs and tests mention tr! with example texts.
            if path.file_stem().is_some_and(|s| s == "i18n") {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                // A Windows checkout may have CRLF line ends; rustc reads `\` + CRLF
                // as a line continuation too.
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("\r\n", "\n");
                collect_literals(&text, &mut out);
            }
        }
    }
    out
}

fn collect_literals(text: &str, out: &mut BTreeSet<String>) {
    for call in ["tr!(", "i18n::around("] {
        collect_after(text, call, out);
    }
}

fn collect_after(text: &str, call: &str, out: &mut BTreeSet<String>) {
    let mut rest = text;
    while let Some(i) = rest.find(call) {
        rest = &rest[i + call.len()..];
        let trimmed = rest.trim_start();
        let Some(body) = trimmed.strip_prefix('"') else {
            continue;
        };
        let mut lit = String::new();
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => lit.push('\n'),
                    Some('t') => lit.push('\t'),
                    Some('\\') => lit.push('\\'),
                    Some('"') => lit.push('"'),
                    Some('\'') => lit.push('\''),
                    Some('\n') => {
                        // A line continuation skips the newline and leading whitespace.
                        let skipped: String = chars.clone().collect();
                        let ws = skipped.len() - skipped.trim_start().len();
                        for _ in 0..skipped[..ws].chars().count() {
                            chars.next();
                        }
                    }
                    Some(other) => panic!("unsupported escape \\{other} in a tr! literal"),
                    None => break,
                },
                c => lit.push(c),
            }
        }
        out.insert(lit);
    }
}

fn placeholders(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let cleaned = text.replace("{{", "").replace("}}", "");
    let mut rest = cleaned.as_str();
    while let Some(i) = rest.find('{') {
        let Some(end) = rest[i..].find('}') else {
            break;
        };
        out.insert(rest[i + 1..i + end].to_string());
        rest = &rest[i + end + 1..];
    }
    out
}

fn wanted() -> BTreeSet<String> {
    let mut all = source_texts();
    all.extend(help_texts(Cli::command()));
    all
}

fn load(lang: Lang) -> HashMap<String, String> {
    parse_catalog(lang.catalog_source())
        .unwrap_or_else(|e| panic!("locales/{}.toml doesn't parse: {e}", lang.code()))
}

#[test]
fn every_catalog_is_complete_and_has_no_stale_entries() {
    let wanted = wanted();
    let mut problems = Vec::new();
    for lang in Lang::TRANSLATED {
        let catalog = load(lang);
        let missing: Vec<_> = wanted
            .iter()
            .filter(|k| !catalog.contains_key(*k))
            .collect();
        let stale: Vec<_> = catalog.keys().filter(|k| !wanted.contains(*k)).collect();
        if !missing.is_empty() {
            problems.push(format!(
                "{}: {} missing, e.g. {:?}",
                lang.code(),
                missing.len(),
                &missing[..missing.len().min(5)]
            ));
        }
        if !stale.is_empty() {
            problems.push(format!(
                "{}: {} stale, e.g. {:?}",
                lang.code(),
                stale.len(),
                &stale[..stale.len().min(5)]
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn translations_keep_their_placeholders() {
    let mut problems = Vec::new();
    for lang in Lang::TRANSLATED {
        for (english, translated) in load(lang) {
            if translated.trim().is_empty() {
                problems.push(format!(
                    "{}: empty translation for {english:?}",
                    lang.code()
                ));
            } else if placeholders(&english) != placeholders(&translated) {
                problems.push(format!("{}: {english:?} -> {translated:?}", lang.code()));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_source_text_is_a_literal_kc_can_fill() {
    for text in source_texts() {
        for name in placeholders(&text) {
            assert!(
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "placeholder {{{name}}} in {text:?} must be a plain name (no format specs)"
            );
        }
    }
}

#[test]
fn fill_replaces_names_and_keeps_literal_braces() {
    let n = 3;
    let name = "API_KEY";
    assert_eq!(
        fill(
            "Stored {name} ({n} bytes). {{x}} {other}",
            &[("name", &name), ("n", &n)]
        ),
        "Stored API_KEY (3 bytes). {x} {other}"
    );
    assert_eq!(fill("no braces", &[]), "no braces");
    assert_eq!(fill("unclosed {", &[]), "unclosed {");
}

#[test]
fn locale_names_map_to_catalogs() {
    assert_eq!(Lang::parse("ko_KR.UTF-8"), Some(Lang::Ko));
    assert_eq!(Lang::parse("ja-JP"), Some(Lang::Ja));
    assert_eq!(Lang::parse("zh_CN.UTF-8"), Some(Lang::ZhHans));
    assert_eq!(Lang::parse("zh-Hans-HK"), Some(Lang::ZhHans));
    assert_eq!(Lang::parse("zh_TW"), Some(Lang::ZhHant));
    assert_eq!(Lang::parse("zh-Hant"), Some(Lang::ZhHant));
    assert_eq!(Lang::parse("de_DE@euro"), Some(Lang::De));
    assert_eq!(Lang::parse("en_US"), Some(Lang::En));
    assert_eq!(Lang::parse("pt_BR"), None);
    assert_eq!(Lang::parse("C"), None);
}

#[test]
fn people_get_their_locale_and_agents_get_english() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    };
    let none = || None;
    let korean = &[("LANG", "ko_KR.UTF-8")];
    assert_eq!(choose_from(env(korean), true, none), Lang::Ko);
    // Not a terminal: English, whatever the locale says.
    assert_eq!(choose_from(env(korean), false, none), Lang::En);
    // KC_LANG wins everywhere, also for agents.
    assert_eq!(
        choose_from(env(&[("KC_LANG", "ja"), ("LANG", "ko_KR")]), false, none),
        Lang::Ja
    );
    assert_eq!(choose_from(env(&[("KC_LANG", "xx")]), true, none), Lang::En);
    // LC_ALL over LANG; C means English.
    assert_eq!(
        choose_from(env(&[("LC_ALL", "fr_FR"), ("LANG", "ko_KR")]), true, none),
        Lang::Fr
    );
    assert_eq!(
        choose_from(env(&[("LC_ALL", "C"), ("LANGUAGE", "ko")]), true, none),
        Lang::En
    );
    assert_eq!(
        choose_from(env(&[("LANG", "en_US"), ("LANGUAGE", "pt:es")]), true, none),
        Lang::Es
    );
    // No locale variable: the system's language.
    assert_eq!(
        choose_from(env(&[]), true, || Some("de-DE".into())),
        Lang::De
    );
    assert_eq!(choose_from(env(&[]), true, none), Lang::En);
}

#[test]
fn around_splits_the_translation_at_the_placeholder() {
    set(Lang::Ko);
    let (before, after) = around("Code: {code}", "code");
    assert_eq!(
        format!("{before}X{after}"),
        fill(lookup("Code: {code}"), &[("code", &"X")])
    );
    set(Lang::En);
    assert_eq!(around("Code: {code}", "code"), ("Code: ", ""));
}

#[tokio::test]
async fn joined_runs_keep_their_own_language() {
    let probe = |lang| {
        scope(lang, async move {
            tokio::task::yield_now().await;
            current()
        })
    };
    let (a, b) = tokio::join!(probe(Lang::Ko), probe(Lang::En));
    assert_eq!((a, b), (Lang::Ko, Lang::En));
}

#[test]
fn lookup_falls_back_to_english() {
    set(Lang::Ko);
    assert_eq!(lookup("a text no catalog has"), "a text no catalog has");
    set(Lang::En);
    assert_eq!(lookup("Usage:"), "Usage:");
}

/// `KC_I18N_DUMP=keys.json cargo test -p kc-cli --lib dump_texts -- --ignored` writes every
/// text a catalog needs, for translators.
#[test]
#[ignore]
fn dump_texts() {
    let path = std::env::var("KC_I18N_DUMP").expect("set KC_I18N_DUMP to an output path");
    let texts: Vec<String> = wanted().into_iter().collect();
    std::fs::write(path, serde_json::to_string_pretty(&texts).unwrap()).unwrap();
}
