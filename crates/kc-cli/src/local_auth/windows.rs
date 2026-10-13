#![allow(unsafe_code)] // Window handles and WinRT interop require Win32 FFI.

use windows::Foundation::IAsyncOperation;
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows::core::{HSTRING, factory};

use super::LocalAuthOutcome;

pub(super) fn confirm(reason: &str) -> LocalAuthOutcome {
    // Request a new verification every time; never retain a previous result.
    match request_verification(reason) {
        Ok(result) => outcome(result),
        Err(error) => LocalAuthOutcome::Unavailable(format!("Windows Hello: {error}")),
    }
}

fn request_verification(reason: &str) -> windows::core::Result<UserConsentVerificationResult> {
    let verifier = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    // SAFETY: These calls take no pointers; the returned handles are borrowed
    // for the OS verification UI and are never freed or dereferenced here.
    let hwnd = unsafe {
        let console = GetConsoleWindow();
        if console.0.is_null() {
            GetForegroundWindow()
        } else {
            console
        }
    };
    // SAFETY: The OS-provided window handle and owned HSTRING remain valid
    // for the call; the requested interface is the documented result type.
    let request: IAsyncOperation<UserConsentVerificationResult> = unsafe {
        verifier.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(reason))?
    };
    request.get()
}

fn outcome(result: UserConsentVerificationResult) -> LocalAuthOutcome {
    match result {
        UserConsentVerificationResult::Verified => LocalAuthOutcome::Confirmed,
        UserConsentVerificationResult::Canceled
        | UserConsentVerificationResult::RetriesExhausted => LocalAuthOutcome::Denied,
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
        assert_eq!(
            outcome(UserConsentVerificationResult::Verified),
            LocalAuthOutcome::Confirmed
        );
        for result in [
            UserConsentVerificationResult::Canceled,
            UserConsentVerificationResult::RetriesExhausted,
        ] {
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
