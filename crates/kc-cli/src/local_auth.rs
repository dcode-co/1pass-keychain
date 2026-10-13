//! Local confirmation (sync design §3.1): the OS shows secure UI and reads biometrics
//! or credentials outside the terminal, so owning a PTY cannot type/script the answer.
//! There is no terminal fallback or cached confirmation in kc.

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos;
#[cfg(windows)]
mod windows;
// Compile the pure Linux parser and result tests on the native test platform too.
#[cfg(any(target_os = "linux", test))]
mod linux;

/// The result of an OS user-presence check.
#[derive(Debug, Clone, PartialEq)]
pub enum LocalAuthOutcome {
    Confirmed,
    Denied,
    Unavailable(String),
}

/// Blocks for a fresh OS confirmation, showing `reason` in the authentication UI.
pub fn confirm(reason: &str) -> LocalAuthOutcome {
    // LocalAuthentication throws an Objective-C exception for an empty reason.
    if reason.trim().is_empty() {
        return LocalAuthOutcome::Unavailable("local confirmation needs a reason".into());
    }
    #[cfg(target_os = "macos")]
    { macos::confirm(reason) }
    #[cfg(windows)]
    { windows::confirm(reason) }
    #[cfg(target_os = "linux")]
    { linux::confirm(reason) }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    { LocalAuthOutcome::Unavailable("local confirmation is unsupported on this platform".into()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reason_does_not_prompt() {
        assert!(matches!(confirm(" \t\n"), LocalAuthOutcome::Unavailable(_)));
    }

    #[test]
    #[ignore = "requires a human to answer the OS authentication prompt"]
    fn manual_local_confirmation() {
        eprintln!("{:?}", confirm("kc test"));
    }
}
