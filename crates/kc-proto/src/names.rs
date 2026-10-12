//! Validated names that cross the wire: item names and device labels (PROTOCOL §3).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest item name, in bytes (all characters are ASCII).
pub const ITEM_NAME_MAX: usize = 128;
/// Longest device label, in characters (all ASCII).
pub const LABEL_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error(
        "item names are 1-128 characters of A-Z a-z 0-9 . _ / -, start with a letter or digit, \
         and contain no \"..\" and no trailing \"/\""
    )]
    InvalidItemName,
    #[error("device labels are 1-64 printable ASCII characters")]
    InvalidLabel,
}

/// An item name: `^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`, with no `..` and no
/// trailing `/` (a leading `/` is already excluded by the first character).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemName(String);

impl ItemName {
    pub fn new(name: &str) -> Result<ItemName, NameError> {
        if is_valid_item_name(name) {
            Ok(ItemName(name.to_owned()))
        } else {
            Err(NameError::InvalidItemName)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_valid_item_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= ITEM_NAME_MAX
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
        && !s.contains("..")
        && !s.ends_with('/')
}

impl fmt::Display for ItemName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ItemName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemName({:?})", self.0)
    }
}

impl std::str::FromStr for ItemName {
    type Err = NameError;
    fn from_str(s: &str) -> Result<ItemName, NameError> {
        ItemName::new(s)
    }
}

impl AsRef<str> for ItemName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for ItemName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ItemName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<ItemName, D::Error> {
        let s = String::deserialize(deserializer)?;
        if is_valid_item_name(&s) {
            Ok(ItemName(s))
        } else {
            Err(serde::de::Error::custom(NameError::InvalidItemName))
        }
    }
}

/// A device label: 1-64 printable ASCII characters (0x20-0x7E). Safe to print
/// to a terminal: it can't hold control or escape characters.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl Label {
    pub fn new(label: &str) -> Result<Label, NameError> {
        if is_valid_label(label) {
            Ok(Label(label.to_owned()))
        } else {
            Err(NameError::InvalidLabel)
        }
    }

    /// Turns any text (a hostname, a peer's suggestion) into a valid label:
    /// whitespace and control characters become spaces, other characters
    /// outside printable ASCII become `_`, runs of spaces collapse, the ends
    /// are trimmed and the result is cut to 64 characters. Empty becomes
    /// `"device"`.
    pub fn sanitize(input: &str) -> Label {
        let mut out = String::with_capacity(LABEL_MAX);
        for c in input.chars() {
            let c = if c.is_whitespace() || c.is_control() {
                ' '
            } else if c.is_ascii_graphic() {
                c
            } else {
                '_'
            };
            if c == ' ' && (out.is_empty() || out.ends_with(' ')) {
                continue;
            }
            if out.len() == LABEL_MAX {
                break;
            }
            out.push(c);
        }
        let trimmed = out.trim_end();
        Label(if trimmed.is_empty() {
            "device".to_owned()
        } else {
            trimmed.to_owned()
        })
    }

    /// This label if `taken` says it's free, otherwise the first free one of
    /// `label-2`, `label-3`, ... (shortened to stay within 64 characters).
    pub fn unique(&self, taken: impl Fn(&str) -> bool) -> Label {
        if !taken(&self.0) {
            return self.clone();
        }
        for n in 2u32.. {
            let suffix = format!("-{n}");
            let keep = LABEL_MAX - suffix.len();
            let base = if self.0.len() > keep {
                &self.0[..keep]
            } else {
                &self.0[..]
            };
            let candidate = format!("{}{suffix}", base.trim_end());
            if !taken(&candidate) {
                return Label(candidate);
            }
        }
        unreachable!("u32 range exhausted while looking for a free label")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= LABEL_MAX && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label({:?})", self.0)
    }
}

impl std::str::FromStr for Label {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Label, NameError> {
        Label::new(s)
    }
}

impl Serialize for Label {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Label, D::Error> {
        let s = String::deserialize(deserializer)?;
        if is_valid_label(&s) {
            Ok(Label(s))
        } else {
            Err(serde::de::Error::custom(NameError::InvalidLabel))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_names_follow_the_spec() {
        for ok in [
            "GITHUB_TOKEN",
            "a",
            "app.env",
            "zai-api-key",
            "team/prod/db.url",
            "9",
            &"x".repeat(128),
        ] {
            assert!(ItemName::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".env",
            "_x",
            "-x",
            "/abs",
            "dir/",
            "a..b",
            "a/../b",
            "a b",
            "ä",
            "a\n",
            "a\\b",
            "a:b",
            &"x".repeat(129),
        ] {
            assert_eq!(
                ItemName::new(bad),
                Err(NameError::InvalidItemName),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn labels_are_printable_ascii_up_to_64() {
        assert!(Label::new("MacBook Pro (work)").is_ok());
        assert!(Label::new(&"x".repeat(64)).is_ok());
        for bad in [
            "",
            "tab\there",
            "esc\u{1b}[31m",
            "macbook\u{7f}",
            "맥북",
            &"x".repeat(65),
        ] {
            assert_eq!(Label::new(bad), Err(NameError::InvalidLabel), "{bad:?}");
        }
    }

    #[test]
    fn sanitize_always_yields_a_valid_label() {
        assert_eq!(Label::sanitize("  omarchy  ").as_str(), "omarchy");
        assert_eq!(
            Label::sanitize("my\tlaptop\n\u{1b}[2J").as_str(),
            "my laptop [2J"
        );
        assert_eq!(Label::sanitize("승한의 맥북").as_str(), "___ __");
        assert_eq!(Label::sanitize("\u{7}\n ").as_str(), "device");
        assert_eq!(Label::sanitize(&"y".repeat(100)).as_str().len(), 64);
        for s in ["", "a\u{0}b", &"é".repeat(70), "x y  z"] {
            assert!(Label::new(Label::sanitize(s).as_str()).is_ok());
        }
    }

    #[test]
    fn unique_appends_a_counter() {
        let taken = ["mac", "mac-2"];
        let l = Label::new("mac").unwrap().unique(|s| taken.contains(&s));
        assert_eq!(l.as_str(), "mac-3");
        let long = Label::new(&"m".repeat(64)).unwrap();
        let u = long.unique(|s| s.len() == 64 && s.bytes().all(|b| b == b'm'));
        assert_eq!(u.as_str().len(), 64);
        assert!(u.as_str().ends_with("-2"));
    }

    #[test]
    fn deserialize_validates() {
        assert!(serde_json::from_str::<ItemName>("\"ok.name\"").is_ok());
        assert!(serde_json::from_str::<ItemName>("\"../etc/passwd\"").is_err());
        assert!(serde_json::from_str::<Label>("\"\\u001b[31m\"").is_err());
    }
}
