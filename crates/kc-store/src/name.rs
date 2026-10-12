//! Item names, namespaces and the keychain account layout.
//!
//! Every keychain entry kc writes has `service = <namespace>` and one of these accounts:
//!
//! | account | holds |
//! |---|---|
//! | `item:<name>` | the current value of a user item (inline value or chunk manifest) |
//! | `item:<name>#prev` | the value that the last overwrite replaced (one level) |
//! | `item:<name>#swap` | only while a restore runs: the value being displaced |
//! | `item:<name>#<gen>.<i>` | chunk `i` of generation `gen` of a large value |
//! | `sys:<key>` | an internal slot (device key, inbox token), never listed |
//! | `sys:<key>#<gen>.<i>` | chunk of a large internal value |
//!
//! Names can't contain `#`, so the suffixes never collide with a real name.

use crate::error::{Result, StoreError};

/// Longest allowed item name, internal key or namespace, in bytes.
pub const MAX_NAME_LEN: usize = 128;

const NAME_RULE: &str = "use 1-128 characters from A-Z a-z 0-9 . _ / -, start with a letter or \
                         digit, no \"..\" and no trailing \"/\"";
const NAMESPACE_RULE: &str = "use 1-128 characters from A-Z a-z 0-9 . _ -, start with a letter \
                              or digit, no \"..\"";

pub(crate) const ITEM_PREFIX: &str = "item:";
pub(crate) const SYS_PREFIX: &str = "sys:";
const PREV_SUFFIX: &str = "prev";
const SWAP_SUFFIX: &str = "swap";

/// Checks an item name against `^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`, with no `..` and no
/// trailing `/`. Names such as `dev-env/x` or `apple-p8/ID` are fine.
pub fn validate_name(name: &str) -> Result<()> {
    if is_valid_name(name) {
        Ok(())
    } else {
        Err(StoreError::InvalidName {
            what: "item name",
            value: name.to_owned(),
            rule: NAME_RULE,
        })
    }
}

pub(crate) fn validate_internal_key(key: &str) -> Result<()> {
    if is_valid_name(key) {
        Ok(())
    } else {
        Err(StoreError::InvalidName {
            what: "internal key",
            value: key.to_owned(),
            rule: NAME_RULE,
        })
    }
}

pub(crate) fn validate_namespace(namespace: &str) -> Result<()> {
    if is_valid_ident(namespace, false) {
        Ok(())
    } else {
        Err(StoreError::InvalidName {
            what: "namespace",
            value: namespace.to_owned(),
            rule: NAMESPACE_RULE,
        })
    }
}

pub(crate) fn is_valid_name(name: &str) -> bool {
    is_valid_ident(name, true)
}

fn is_valid_ident(s: &str, allow_slash: bool) -> bool {
    let bytes = s.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    bytes.len() <= MAX_NAME_LEN
        && first.is_ascii_alphanumeric()
        && bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'-')
                || (allow_slash && b == b'/')
        })
        && !s.contains("..")
        && !s.ends_with('/')
}

/// One logical value in the keychain: a user item or an internal slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot<'a> {
    Item(&'a str),
    Internal(&'a str),
}

impl Slot<'_> {
    /// The account holding the current value.
    pub(crate) fn account(self) -> String {
        match self {
            Slot::Item(name) => format!("{ITEM_PREFIX}{name}"),
            Slot::Internal(key) => format!("{SYS_PREFIX}{key}"),
        }
    }

    /// The account holding the previous value, for slots that keep one (user items only).
    pub(crate) fn prev_account(self) -> Option<String> {
        match self {
            Slot::Item(_) => Some(format!("{}#{PREV_SUFFIX}", self.account())),
            Slot::Internal(_) => None,
        }
    }

    /// Where a restore keeps the value it displaces until the swap is complete (user items only).
    pub(crate) fn swap_account(self) -> Option<String> {
        match self {
            Slot::Item(_) => Some(format!("{}#{SWAP_SUFFIX}", self.account())),
            Slot::Internal(_) => None,
        }
    }
}

/// The account of chunk `index` of generation `gen` under `base` (`item:<name>#<gen>.<index>`).
pub(crate) fn chunk_account(base: &str, generation: u64, index: u32) -> String {
    format!("{base}#{generation}.{index}")
}

/// What a keychain account in our namespace refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedAccount {
    pub internal: bool,
    pub name: String,
    pub part: Part,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Part {
    Current,
    Prev,
    Swap,
    Chunk { generation: u64, index: u32 },
}

/// Parses an account name found in the namespace. Returns `None` for accounts kc didn't write.
pub(crate) fn parse_account(account: &str) -> Option<ParsedAccount> {
    let (internal, rest) = match account.strip_prefix(ITEM_PREFIX) {
        Some(rest) => (false, rest),
        None => (true, account.strip_prefix(SYS_PREFIX)?),
    };
    let (name, suffix) = match rest.split_once('#') {
        Some((name, suffix)) => (name, Some(suffix)),
        None => (rest, None),
    };
    if !is_valid_name(name) {
        return None;
    }
    let part = match suffix {
        None => Part::Current,
        Some(PREV_SUFFIX) if !internal => Part::Prev,
        Some(SWAP_SUFFIX) if !internal => Part::Swap,
        Some(suffix) => {
            let (generation, index) = suffix.split_once('.')?;
            Part::Chunk {
                generation: parse_decimal(generation)?,
                index: parse_decimal(index)?,
            }
        }
    };
    Some(ParsedAccount {
        internal,
        name: name.to_owned(),
        part,
    })
}

fn parse_decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for name in [
            "a",
            "Z",
            "0",
            "openai-api-key",
            "dev-env/x",
            "apple-p8/ID",
            "a.b_c-d/e/f",
            "x.",
            "a/b.c",
            &"a".repeat(MAX_NAME_LEN),
        ] {
            assert!(validate_name(name).is_ok(), "{name:?} should be valid");
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for name in [
            "",
            "/a",
            "a/",
            "a/b/",
            ".hidden",
            "-dash",
            "_under",
            "a..b",
            "..",
            "a/../b",
            "a#1",
            "a:b",
            "a b",
            "a@b",
            "a\\b",
            "naïve",
            "a\nb",
            &"a".repeat(MAX_NAME_LEN + 1),
        ] {
            let err = validate_name(name).expect_err(name);
            assert!(matches!(err, StoreError::InvalidName { .. }));
            assert_eq!(err.exit_code(), 2);
        }
    }

    #[test]
    fn namespace_rule_forbids_slashes_and_at_signs() {
        assert!(validate_namespace("dev.1pass.kc").is_ok());
        assert!(validate_namespace("dev.1pass.kc.test-0a1b").is_ok());
        for ns in ["", "dev/1pass", "dev@1pass", ".dev", "dev..kc", "dev kc"] {
            assert!(validate_namespace(ns).is_err(), "{ns:?} should be invalid");
        }
    }

    #[test]
    fn slot_accounts() {
        let item = Slot::Item("dev-env/x");
        assert_eq!(item.account(), "item:dev-env/x");
        assert_eq!(item.prev_account().as_deref(), Some("item:dev-env/x#prev"));
        assert_eq!(chunk_account(&item.account(), 7, 3), "item:dev-env/x#7.3");
        let sys = Slot::Internal("device-key");
        assert_eq!(sys.account(), "sys:device-key");
        assert_eq!(sys.prev_account(), None);
    }

    #[test]
    fn parses_accounts_back() {
        let p = parse_account("item:dev-env/x").unwrap();
        assert_eq!(
            (p.internal, p.name.as_str(), p.part),
            (false, "dev-env/x", Part::Current)
        );
        let p = parse_account("item:a#prev").unwrap();
        assert_eq!(p.part, Part::Prev);
        assert_eq!(parse_account("item:a#swap").unwrap().part, Part::Swap);
        assert_eq!(parse_account("sys:a#swap"), None);
        let p = parse_account("item:a#12.0").unwrap();
        assert_eq!(
            p.part,
            Part::Chunk {
                generation: 12,
                index: 0
            }
        );
        let p = parse_account("sys:device-key#3.9").unwrap();
        assert!(p.internal);
        assert_eq!(
            p.part,
            Part::Chunk {
                generation: 3,
                index: 9
            }
        );
        for bad in [
            "other",
            "item:",
            "item:a#",
            "item:a#x.1",
            "item:a#1.",
            "item:a#+1.2",
            "item:a#1.2.3",
            "sys:a#prev",
            "item:../a",
        ] {
            assert_eq!(parse_account(bad), None, "{bad:?}");
        }
    }
}
