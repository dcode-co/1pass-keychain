//! Codes people read out and type: `<channel>-<even>-<odd>` for a one-shot
//! transfer and `<channel>-<even>-<odd>-<even>` for pairing (PROTOCOL §2).
//!
//! Input is case-insensitive and accepts `-` or whitespace between parts.
//! Words are checked against the lists here, before anything touches the
//! network, so a typo never burns a code. The canonical form is lowercase and
//! joined with `-`; the SPAKE2 password is `"kc1:" || canonical`.

use std::fmt;

use kc_wire::limits::CHANNEL_NUMBER_MAX;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::rng;
use crate::words::WordList;

/// Prefix of the SPAKE2 password: `pw = "kc1:" || canonical code`.
pub const PAKE_PASSWORD_PREFIX: &[u8] = b"kc1:";

/// What a code is for. The number of words tells the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeKind {
    /// `kc send` / `kc receive`: 2 words, 16 bits.
    Transfer,
    /// `kc pair` and `--remember`: 3 words, 24 bits.
    Pairing,
}

impl CodeKind {
    pub fn word_count(self) -> usize {
        match self {
            CodeKind::Transfer => 2,
            CodeKind::Pairing => 3,
        }
    }

    fn from_word_count(n: usize) -> Option<CodeKind> {
        match n {
            2 => Some(CodeKind::Transfer),
            3 => Some(CodeKind::Pairing),
            _ => None,
        }
    }
}

impl fmt::Display for CodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CodeKind::Transfer => "transfer",
            CodeKind::Pairing => "pairing",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    #[error("no code was entered")]
    Empty,
    #[error("a code starts with the channel number (1-9999), like 4721-absurd-amulet")]
    BadChannel,
    #[error(
        "a code has 2 words (transfer) or 3 words (pairing) after the number, but {found} were entered"
    )]
    WordCount { found: usize },
    #[error("this needs a {expected} code ({} words), but a {found} code was entered", expected.word_count())]
    WrongKind { expected: CodeKind, found: CodeKind },
    #[error("word {position} ({word:?}) is not a code word{}", did_you_mean(*.suggestion))]
    UnknownWord {
        /// 1-based position among the words (the channel number isn't counted).
        position: usize,
        /// What was typed, lowercased and shortened for display.
        word: String,
        suggestion: Option<&'static str>,
    },
    #[error("word {position} belongs at a different position; check the order of the words")]
    MisplacedWord { position: usize },
}

fn did_you_mean(suggestion: Option<&'static str>) -> String {
    suggestion
        .map(|s| format!("; did you mean {s:?}?"))
        .unwrap_or_default()
}

/// A parsed or generated code. `Display` prints the canonical form; `Debug`
/// hides the words.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    channel: u16,
    kind: CodeKind,
    /// One byte per word; only the first `kind.word_count()` are used.
    words: [u8; 3],
}

impl Drop for Code {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

impl ZeroizeOnDrop for Code {}

impl Code {
    /// A fresh random code for an allocated channel.
    pub fn generate(channel: u16, kind: CodeKind) -> Result<Code, CodeError> {
        if !channel_in_range(channel) {
            return Err(CodeError::BadChannel);
        }
        let mut words = rng::array::<3>();
        words[kind.word_count()..].fill(0);
        Ok(Code {
            channel,
            kind,
            words,
        })
    }

    /// Parses a code of either kind.
    pub fn parse(input: &str) -> Result<Code, CodeError> {
        let parts: Vec<&str> = input
            .split(|c: char| c == '-' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .collect();
        let (first, words) = parts.split_first().ok_or(CodeError::Empty)?;
        let channel = parse_channel(first)?;
        let kind = CodeKind::from_word_count(words.len())
            .ok_or(CodeError::WordCount { found: words.len() })?;

        let mut bytes = [0u8; 3];
        for (i, typed) in words.iter().enumerate() {
            let typed = Zeroizing::new(typed.to_ascii_lowercase());
            let list = WordList::for_position(i);
            bytes[i] = match list.byte(&typed) {
                Some(b) => b,
                None => {
                    bytes.zeroize();
                    return Err(word_error(i + 1, list, &typed));
                }
            };
        }
        Ok(Code {
            channel,
            kind,
            words: bytes,
        })
    }

    /// Parses a code and requires it to be of `kind`.
    pub fn parse_as(input: &str, kind: CodeKind) -> Result<Code, CodeError> {
        let code = Code::parse(input)?;
        if code.kind != kind {
            return Err(CodeError::WrongKind {
                expected: kind,
                found: code.kind,
            });
        }
        Ok(code)
    }

    pub fn channel(&self) -> u16 {
        self.channel
    }

    pub fn kind(&self) -> CodeKind {
        self.kind
    }

    /// The words, lowercase, in order.
    pub fn words(&self) -> Vec<&'static str> {
        (0..self.kind.word_count())
            .map(|i| WordList::for_position(i).word(self.words[i]))
            .collect()
    }

    /// The canonical form, e.g. `4721-absurd-amulet`.
    pub fn to_canonical(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(48));
        s.push_str(&self.channel.to_string());
        for w in self.words() {
            s.push('-');
            s.push_str(w);
        }
        s
    }

    /// The SPAKE2 password: `"kc1:" || canonical code`.
    pub(crate) fn pake_password(&self) -> Zeroizing<Vec<u8>> {
        let canonical = self.to_canonical();
        let mut pw = Zeroizing::new(Vec::with_capacity(
            PAKE_PASSWORD_PREFIX.len() + canonical.len(),
        ));
        pw.extend_from_slice(PAKE_PASSWORD_PREFIX);
        pw.extend_from_slice(canonical.as_bytes());
        pw
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical())
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Code")
            .field("channel", &self.channel)
            .field("kind", &self.kind)
            .field("words", &"<hidden>")
            .finish()
    }
}

fn channel_in_range(channel: u16) -> bool {
    (1..=CHANNEL_NUMBER_MAX).contains(&channel)
}

fn parse_channel(s: &str) -> Result<u16, CodeError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CodeError::BadChannel);
    }
    let digits = s.trim_start_matches('0');
    if digits.len() > 4 {
        return Err(CodeError::BadChannel);
    }
    let channel: u16 = if digits.is_empty() {
        0
    } else {
        digits.parse().map_err(|_| CodeError::BadChannel)?
    };
    if channel_in_range(channel) {
        Ok(channel)
    } else {
        Err(CodeError::BadChannel)
    }
}

fn word_error(position: usize, list: WordList, typed: &str) -> CodeError {
    let other = match list {
        WordList::Even => WordList::Odd,
        WordList::Odd => WordList::Even,
    };
    if other.byte(typed).is_some() {
        return CodeError::MisplacedWord { position };
    }
    let shown: String = typed
        .chars()
        .take(24)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    CodeError::UnknownWord {
        position,
        word: shown,
        suggestion: suggest(list, typed),
    }
}

/// The word the user most likely meant: a unique prefix of at least 3
/// letters, or the unique closest word within a small edit distance.
fn suggest(list: WordList, typed: &str) -> Option<&'static str> {
    if typed.is_empty() || typed.len() > 32 {
        return None;
    }
    if typed.len() >= 3 {
        let mut prefixed = list.words().iter().filter(|w| w.starts_with(typed));
        if let (Some(only), None) = (prefixed.next(), prefixed.next()) {
            return Some(only);
        }
    }
    let limit = if typed.chars().count() <= 4 { 1 } else { 2 };
    let mut best: Option<&'static str> = None;
    let mut best_distance = usize::MAX;
    let mut tied = false;
    for w in list.words().iter().copied() {
        let d = edit_distance(typed, w);
        if d < best_distance {
            (best, best_distance, tied) = (Some(w), d, false);
        } else if d == best_distance {
            tied = true;
        }
    }
    if best_distance <= limit && !tied {
        best
    } else {
        None
    }
}

/// Optimal string alignment distance: insertions, deletions, substitutions
/// and swaps of adjacent letters.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(input: &str) -> String {
        Code::parse(input).unwrap().to_canonical().to_string()
    }

    #[test]
    fn parses_and_normalises() {
        assert_eq!(canonical("4721-absurd-amulet"), "4721-absurd-amulet");
        assert_eq!(canonical("4721 Absurd AMULET"), "4721-absurd-amulet");
        assert_eq!(
            canonical("  4721 -  absurd\t-amulet\n"),
            "4721-absurd-amulet"
        );
        assert_eq!(canonical("4721--absurd--amulet"), "4721-absurd-amulet");
        assert_eq!(canonical("0042-absurd-amulet"), "42-absurd-amulet");
        assert_eq!(
            canonical("4721-absurd-amulet-apple"),
            "4721-absurd-amulet-apple"
        );
        assert_eq!(canonical("9999 zulu yucatan"), "9999-zulu-yucatan");
        assert_eq!(
            canonical("1 aardvark adroitness aardvark"),
            "1-aardvark-adroitness-aardvark"
        );

        let c = Code::parse("4721-absurd-amulet").unwrap();
        assert_eq!(
            (c.channel(), c.kind(), c.words()),
            (4721, CodeKind::Transfer, vec!["absurd", "amulet"])
        );
        assert_eq!(c.to_string(), "4721-absurd-amulet");
        let p = Code::parse("4721 absurd amulet apple").unwrap();
        assert_eq!(p.kind(), CodeKind::Pairing);
        assert_eq!(&*p.pake_password(), b"kc1:4721-absurd-amulet-apple");
    }

    #[test]
    fn rejects_bad_channels() {
        for input in [
            "0-absurd-amulet",
            "0000-absurd-amulet",
            "10000-absurd-amulet",
            "65536-absurd-amulet",
            "+42-absurd-amulet",
            "４２-absurd-amulet",
            "47a1-absurd-amulet",
            "absurd-amulet",
        ] {
            assert_eq!(Code::parse(input), Err(CodeError::BadChannel), "{input}");
        }
        assert_eq!(
            Code::generate(0, CodeKind::Transfer),
            Err(CodeError::BadChannel)
        );
        assert_eq!(
            Code::generate(10_000, CodeKind::Transfer),
            Err(CodeError::BadChannel)
        );
    }

    #[test]
    fn rejects_wrong_word_counts_and_kinds() {
        assert_eq!(Code::parse(""), Err(CodeError::Empty));
        assert_eq!(Code::parse(" - "), Err(CodeError::Empty));
        assert_eq!(Code::parse("4721"), Err(CodeError::WordCount { found: 0 }));
        assert_eq!(
            Code::parse("4721-absurd"),
            Err(CodeError::WordCount { found: 1 })
        );
        assert_eq!(
            Code::parse("4721-absurd-amulet-apple-amulet"),
            Err(CodeError::WordCount { found: 4 })
        );
        assert_eq!(
            Code::parse_as("4721-absurd-amulet", CodeKind::Pairing),
            Err(CodeError::WrongKind {
                expected: CodeKind::Pairing,
                found: CodeKind::Transfer
            })
        );
        assert!(Code::parse_as("4721-absurd-amulet-apple", CodeKind::Pairing).is_ok());
    }

    #[test]
    fn unknown_words_get_suggestions() {
        let err = |input| Code::parse(input).unwrap_err();
        assert_eq!(
            err("4721-absrd-amulet"),
            CodeError::UnknownWord {
                position: 1,
                word: "absrd".into(),
                suggestion: Some("absurd")
            }
        );
        assert_eq!(
            err("4721-absurd-amuelt"),
            CodeError::UnknownWord {
                position: 2,
                word: "amuelt".into(),
                suggestion: Some("amulet")
            }
        );
        assert_eq!(
            err("4721-absurd-adroit"),
            CodeError::UnknownWord {
                position: 2,
                word: "adroit".into(),
                suggestion: Some("adroitness")
            }
        );
        assert_eq!(
            err("4721-absurd-amulet-appel"),
            CodeError::UnknownWord {
                position: 3,
                word: "appel".into(),
                suggestion: Some("apple")
            }
        );
        assert_eq!(
            err("4721-xyzzy-amulet"),
            CodeError::UnknownWord {
                position: 1,
                word: "xyzzy".into(),
                suggestion: None
            }
        );
        assert!(
            err("4721-absrd-amulet")
                .to_string()
                .contains("did you mean \"absurd\"")
        );
    }

    #[test]
    fn swapped_words_are_reported_as_misplaced() {
        assert_eq!(
            Code::parse("4721-amulet-absurd"),
            Err(CodeError::MisplacedWord { position: 1 })
        );
        assert_eq!(
            Code::parse("4721-absurd-apple-amulet"),
            Err(CodeError::MisplacedWord { position: 2 })
        );
    }

    #[test]
    fn generated_codes_round_trip_and_debug_hides_words() {
        for kind in [CodeKind::Transfer, CodeKind::Pairing] {
            for _ in 0..200 {
                let c = Code::generate(4721, kind).unwrap();
                let parsed = Code::parse_as(&c.to_canonical(), kind).unwrap();
                assert_eq!(parsed, c);
                assert_eq!(c.words().len(), kind.word_count());
            }
        }
        let c = Code::parse("4721-absurd-amulet").unwrap();
        let debug = format!("{c:?}");
        assert!(
            !debug.contains("absurd") && !debug.contains("amulet"),
            "{debug}"
        );
    }

    #[test]
    fn edit_distance_counts_adjacent_swaps_once() {
        assert_eq!(edit_distance("amulet", "amulet"), 0);
        assert_eq!(edit_distance("amuelt", "amulet"), 1);
        assert_eq!(edit_distance("amulet", "amult"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
    }
}
