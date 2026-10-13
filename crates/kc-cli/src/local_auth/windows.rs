use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use windows::core::HSTRING;

use super::LocalAuthOutcome;

pub(super) fn confirm(reason: &str) -> LocalAuthOutcome {
    // Request a new verification every time; never retain a previous result.
    match UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(reason))
        .and_then(|request| request.get())
    {
        Ok(result) => outcome(result),
        Err(error) => LocalAuthOutcome::Unavailable(format!("Windows Hello: {error}")),
    }
}

fn outcome(result: UserConsentVerificationResult) -> LocalAuthOutcome {
    match result {
        UserConsentVerificationResult::Verified => LocalAuthOutcome::Confirmed,
        UserConsentVerificationResult::Canceled | UserConsentVerificationResult::RetriesExhausted => {
            LocalAuthOutcome::Denied
        }
        UserConsentVerificationResult::DeviceNotPresent => {
            LocalAuthOutcome::Unavailable("Windows Hello device not present".into())
        }
        UserConsentVerificationResult::NotConfiguredForUser => {
            LocalAuthOutcome::Unavailable("Windows Hello is not configured for this user".into())
        }
        UserConsentVerificationResult::DisabledByPolicy => {
            LocalAuthOutcome::Unavailable("Windows Hello is disabled by policy".into())
        }
        UserConsentVerificationResult::DeviceBusy => {
            LocalAuthOutcome::Unavailable("Windows Hello device is busy".into())
        }
        _ => LocalAuthOutcome::Unavailable(format!("Windows Hello returned {result:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_verified_confirms() {
        assert_eq!(outcome(UserConsentVerificationResult::Verified), LocalAuthOutcome::Confirmed);
        for result in [UserConsentVerificationResult::Canceled, UserConsentVerificationResult::RetriesExhausted] {
            assert_eq!(outcome(result), LocalAuthOutcome::Denied);
        }
        for result in [
            UserConsentVerificationResult::DeviceNotPresent,
            UserConsentVerificationResult::NotConfiguredForUser,
            UserConsentVerificationResult::DisabledByPolicy,
            UserConsentVerificationResult::DeviceBusy,
            UserConsentVerificationResult(-1),
        ] {
            assert!(matches!(outcome(result), LocalAuthOutcome::Unavailable(_)));
        }
    }
}
