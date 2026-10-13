//! Reading and writing values without leaving copies behind, and the checks that keep
//! values and mistyped names out of messages.

use std::io::{self, Read};
use std::path::Path;

use kc_proto::ItemName;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CliError, Result};
use crate::i18n::tr;

/// Reads everything from `reader` into a wiped buffer. Growing copies into a new wiped
/// buffer, so no reallocation leaves the secret behind. Fails past `limit` bytes.
pub(crate) fn read_secret(reader: &mut dyn Read, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(1024));
    let mut chunk = [0u8; 8192];
    let result = loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(e),
        };
        if out.len() + n > limit {
            break Err(io::Error::new(
                io::ErrorKind::InvalidData,
                tr!(
                    "the value is larger than the limit of {limit} bytes",
                    limit = limit
                ),
            ));
        }
        if out.len() + n > out.capacity() {
            let mut bigger =
                Zeroizing::new(Vec::with_capacity((out.capacity() * 2).max(out.len() + n)));
            bigger.extend_from_slice(&out);
            out = bigger;
        }
        out.extend_from_slice(&chunk[..n]);
    };
    chunk.zeroize();
    result.map(|()| out)
}

/// Reads one line (a code) of at most `limit` bytes.
pub(crate) fn read_line_secret(
    reader: &mut dyn Read,
    limit: usize,
) -> io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(Vec::with_capacity(limit));
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if line.len() >= limit => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    tr!("the line is too long"),
                ));
            }
            Ok(_) => line.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    byte.zeroize();
    match std::str::from_utf8(&line) {
        Ok(text) => Ok(Zeroizing::new(text.trim().to_owned())),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            tr!("the line is not UTF-8"),
        )),
    }
}

/// Removes one trailing line ending (`\n` or `\r\n`).
pub(crate) fn strip_line_ending(value: &mut Zeroizing<Vec<u8>>) {
    let len = value.len();
    if value.ends_with(b"\r\n") {
        value.truncate(len - 2);
    } else if value.ends_with(b"\n") {
        value.truncate(len - 1);
    }
}

/// Reads a whole file as a value, refusing files over `limit`.
pub(crate) fn read_file(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let shown = path.display();
    let mut file = std::fs::File::open(path)
        .map_err(|e| CliError::usage(tr!("can't open {path}: {e}", path = shown, e = e)))?;
    if let Ok(meta) = file.metadata() {
        if meta.is_dir() {
            return Err(CliError::usage(tr!("{path} is a directory", path = shown)));
        }
        if meta.len() > limit as u64 {
            return Err(CliError::usage(tr!(
                "{path} is {size} bytes; the limit is {limit}",
                path = shown,
                size = meta.len(),
                limit = limit
            )));
        }
    }
    read_secret(&mut file, limit)
        .map_err(|e| CliError::usage(tr!("can't read {path}: {e}", path = shown, e = e)))
}

/// `xxxx-xxxx-xxxx-xxxx`: the first 8 bytes of `SHA-256("kc1 value fingerprint" || value)`.
/// Equal on two devices exactly when the values are equal (barring collisions).
pub(crate) fn value_fingerprint(value: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(b"kc1 value fingerprint")
        .chain_update(value)
        .finalize();
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

/// Checks an item name typed on the command line. An invalid one isn't repeated in the
/// error: it might be a value pasted in the wrong place.
pub(crate) fn item_name(input: &str) -> Result<ItemName> {
    ItemName::new(input).map_err(|_| {
        CliError::usage(tr!(
            "invalid item name (not shown): item names are 1-128 characters of A-Z a-z 0-9 . _ \
             / -, start with a letter or digit, and have no \"..\" and no trailing \"/\""
        ))
    })
}

/// `[A-Za-z_][A-Za-z0-9_]*`, at most 255 characters.
pub(crate) fn is_env_var_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 255
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// `text` as one POSIX shell word, for commands kc suggests: as is when that's safe, else
/// in single quotes. Device labels are printable ASCII, so this covers them.
pub(crate) fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-+=:,@%".contains(&b));
    if plain {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

/// Text safe to print on a terminal: control characters become `?`.
pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out at most `step` bytes per read.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn reads_everything_up_to_the_limit() {
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let got = read_secret(
            &mut Trickle {
                data: &data,
                step: 777,
            },
            50_000,
        )
        .unwrap();
        assert_eq!(got.as_slice(), data.as_slice());
        assert!(
            read_secret(
                &mut Trickle {
                    data: &data,
                    step: 777
                },
                49_999
            )
            .is_err()
        );
        assert!(read_secret(&mut io::empty(), 10).unwrap().is_empty());
    }

    #[test]
    fn line_endings() {
        for (input, want) in [
            (&b"abc\n"[..], &b"abc"[..]),
            (b"abc\r\n", b"abc"),
            (b"abc\n\n", b"abc\n"),
            (b"abc", b"abc"),
            (b"\n", b""),
        ] {
            let mut v = Zeroizing::new(input.to_vec());
            strip_line_ending(&mut v);
            assert_eq!(v.as_slice(), want);
        }
    }

    #[test]
    fn code_lines() {
        let mut input: &[u8] = b"  4721-absurd-amulet \nrest";
        assert_eq!(
            read_line_secret(&mut input, 64).unwrap().as_str(),
            "4721-absurd-amulet"
        );
        let mut long: &[u8] = &[b'a'; 100];
        assert!(read_line_secret(&mut long, 64).is_err());
        let mut eof: &[u8] = b"9-x-y";
        assert_eq!(read_line_secret(&mut eof, 64).unwrap().as_str(), "9-x-y");
    }

    #[test]
    fn fingerprints_are_stable_and_short() {
        let fp = value_fingerprint(b"example value");
        assert_eq!(fp.len(), 19);
        assert_eq!(fp, value_fingerprint(b"example value"));
        assert_ne!(fp, value_fingerprint(b"example valuf"));
        assert!(!fp.contains("example"));
    }

    #[test]
    fn names_and_env_vars() {
        assert!(item_name("GITHUB_TOKEN").is_ok());
        let err = item_name("SOME_NAME=not-a-real-value").unwrap_err();
        assert_eq!(err.code, kc_wire::exit::USAGE);
        assert!(!err.message.contains("not-a-real"));
        assert!(is_env_var_name("_A1"));
        assert!(!is_env_var_name("1A"));
        assert!(!is_env_var_name("A-B"));
        assert!(!is_env_var_name(""));
        assert_eq!(printable("a\u{1b}[2Jb"), "a?[2Jb");
        assert_eq!(shell_word("laptop-2"), "laptop-2");
        assert_eq!(shell_word("work laptop"), "'work laptop'");
        assert_eq!(shell_word("$(touch x)"), "'$(touch x)'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word("`id`"), "'`id`'");
    }
}
