use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};

use super::LocalAuthOutcome;

pub(super) fn confirm(reason: &str) -> LocalAuthOutcome {
    // SAFETY: LAContext has no thread affinity; this fresh, owned context stays
    // alive until the asynchronous reply arrives. No prior context is reused.
    let context = unsafe { LAContext::new() };
    // SAFETY: zero is a valid reuse duration and disables reuse of device unlocks.
    unsafe { context.setTouchIDAuthenticationAllowableReuseDuration(0.0) };
    let policy = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY: policy is a supported constant, and this preflight is not inside
    // an evaluation reply block (which could deadlock LocalAuthentication).
    if let Err(error) = unsafe { context.canEvaluatePolicy_error(policy) } {
        return LocalAuthOutcome::Unavailable(error.localizedDescription().to_string());
    }

    let reason = NSString::from_str(reason);
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let outcome = if success.as_bool() {
            LocalAuthOutcome::Confirmed
        } else {
            // SAFETY: LocalAuthentication supplies nil or a valid NSError for
            // the duration of this callback. Only owned Rust data leaves it.
            match unsafe { error.as_ref() } {
                Some(error) => failure(LAError(error.code()), error.localizedDescription().to_string()),
                None => LocalAuthOutcome::Unavailable("LocalAuthentication returned no error details".into()),
            }
        };
        // A dropped receiver must not unwind across the Objective-C callback.
        let _ = tx.send(outcome);
    });
    // SAFETY: the reason is nonempty (checked by the parent), the context and
    // block remain alive during evaluation, and the callback captures only a
    // thread-safe Sender. Apple invokes it on a private queue, so recv can block.
    unsafe { context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply) };
    rx.recv().unwrap_or_else(|error| {
        LocalAuthOutcome::Unavailable(format!("LocalAuthentication reply unavailable: {error}"))
    })
}

fn failure(code: LAError, message: String) -> LocalAuthOutcome {
    match code {
        LAError::AuthenticationFailed | LAError::UserCancel | LAError::UserFallback => {
            LocalAuthOutcome::Denied
        }
        _ => LocalAuthOutcome::Unavailable(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_or_failed_authentication_is_denied() {
        for code in [LAError::UserCancel, LAError::UserFallback, LAError::AuthenticationFailed] {
            assert_eq!(failure(code, "denied".into()), LocalAuthOutcome::Denied);
        }
    }

    #[test]
    fn unavailable_errors_preserve_the_message() {
        for code in [
            LAError::BiometryNotAvailable,
            LAError::BiometryNotEnrolled,
            LAError::PasscodeNotSet,
            LAError::SystemCancel,
            LAError::InvalidContext,
            LAError(-999),
        ] {
            assert_eq!(failure(code, "OS error".into()), LocalAuthOutcome::Unavailable("OS error".into()));
        }
    }
}
