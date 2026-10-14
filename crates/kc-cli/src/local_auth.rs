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

use crate::i18n::tr;

/// The result of an OS user-presence check.
#[derive(Debug, Clone, PartialEq)]
pub enum LocalAuthOutcome {
    Confirmed,
    Denied,
    Unavailable(String),
}

/// The start of the [`LocalAuthOutcome::Unavailable`] reason when polkit has no
/// authentication agent to ask (pkcheck exit 2).
pub(crate) const NO_POLKIT_AGENT: &str = "no polkit authentication agent";

impl LocalAuthOutcome {
    /// What to do about a refused confirmation, for the error's hint.
    pub(crate) fn hint(&self) -> String {
        match self {
            LocalAuthOutcome::Unavailable(reason) if reason.starts_with(NO_POLKIT_AGENT) => tr!(
                "No polkit authentication agent is running in this session (for example over SSH, or on a desktop without one such as hyprpolkitagent or polkit-gnome). Run this command from a desktop session that has an agent."
            ),
            LocalAuthOutcome::Unavailable(reason) => tr!(
                "The operating system couldn't ask for confirmation: {reason}.",
                reason = reason
            ),
            _ => tr!("Run this command at a terminal and confirm in the operating system."),
        }
    }
}

/// Blocks for a fresh OS confirmation, showing `reason` in the authentication UI.
pub fn confirm(reason: &str) -> LocalAuthOutcome {
    // LocalAuthentication throws an Objective-C exception for an empty reason.
    if reason.trim().is_empty() {
        return LocalAuthOutcome::Unavailable("local confirmation needs a reason".into());
    }
    #[cfg(target_os = "macos")]
    {
        macos::confirm(reason)
    }
    #[cfg(windows)]
    {
        windows::confirm(reason)
    }
    #[cfg(target_os = "linux")]
    {
        linux::confirm(reason)
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        LocalAuthOutcome::Unavailable("local confirmation is unsupported on this platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reason_does_not_prompt() {
        assert!(matches!(confirm(" \t\n"), LocalAuthOutcome::Unavailable(_)));
    }

    #[test]
    fn hint_names_a_missing_polkit_agent_and_shows_other_reasons() {
        let no_agent = LocalAuthOutcome::Unavailable(format!(
            "{NO_POLKIT_AGENT}: Authorization requires authentication but no agent is available."
        ));
        assert!(no_agent.hint().contains("polkit authentication agent"));
        let other = LocalAuthOutcome::Unavailable("cannot run pkcheck: not found".into());
        assert!(other.hint().contains("cannot run pkcheck: not found"));
        assert_eq!(
            LocalAuthOutcome::Denied.hint(),
            "Run this command at a terminal and confirm in the operating system."
        );
    }

    #[test]
    #[ignore = "requires a human to answer the OS authentication prompt"]
    fn manual_local_confirmation() {
        eprintln!("{:?}", confirm("kc test"));
    }
}
