//! [`SecretValue`]: secret bytes that are wiped on drop and never printed.

use std::fmt;

use zeroize::Zeroizing;

/// The bytes of a secret.
///
/// The buffer is zeroized when the value is dropped. `Debug` prints only the length, and there is
/// deliberately no `Display`, `Clone` or `PartialEq`: copy the bytes out explicitly with
/// [`as_bytes`](Self::as_bytes) when you have to.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Takes ownership of `bytes` (no copy).
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretValue(Zeroizing::new(bytes))
    }

    /// Copies `bytes` into a new zeroizing buffer.
    pub fn from_slice(bytes: &[u8]) -> Self {
        SecretValue(Zeroizing::new(bytes.to_vec()))
    }

    /// The secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The secret as UTF-8 text, or `None` if it isn't valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Unwraps into the zeroizing buffer.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<redacted, {} bytes>)", self.0.len())
    }
}

impl From<Vec<u8>> for SecretValue {
    fn from(bytes: Vec<u8>) -> Self {
        SecretValue::new(bytes)
    }
}

impl From<String> for SecretValue {
    /// Reuses the string's buffer (no copy).
    fn from(text: String) -> Self {
        SecretValue::new(text.into_bytes())
    }
}

impl From<Zeroizing<Vec<u8>>> for SecretValue {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        SecretValue(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_secret() {
        let secret = SecretValue::from("fake-secret-for-test-123".to_owned());
        let shown = format!("{secret:?} {secret:#?}");
        assert!(!shown.contains("fake-secret"), "{shown}");
        assert!(shown.contains("24 bytes"));
    }

    #[test]
    fn accessors() {
        let secret = SecretValue::from_slice(b"abc");
        assert_eq!(secret.as_bytes(), b"abc");
        assert_eq!(secret.as_str(), Some("abc"));
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
        assert_eq!(SecretValue::new(vec![0xff, 0xfe]).as_str(), None);
        assert_eq!(&*SecretValue::new(vec![1]).into_zeroizing(), &[1]);
    }
}
