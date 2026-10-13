use std::process::Command;

use super::LocalAuthOutcome;

#[cfg(target_os = "linux")]
pub(super) fn confirm(reason: &str) -> LocalAuthOutcome {
    let start_time = match std::fs::read_to_string("/proc/self/stat") {
        Ok(stat) => match process_start_time(&stat) {
            Ok(time) => time,
            Err(error) => return LocalAuthOutcome::Unavailable(error.into()),
        },
        Err(error) => {
            return LocalAuthOutcome::Unavailable(format!("cannot read /proc/self/stat: {error}"));
        }
    };
    // Do not enable pkcheck's internal terminal agent. Authentication belongs to
    // the session's OS agent, with no input inherited from kc's PTY.
    // Polkit policy controls whether this check requires fresh authentication;
    // kc itself never retains or reuses an authorization result.
    match command(reason, std::process::id(), start_time).output() {
        Ok(output) => outcome(output.status.code(), &output.stderr),
        Err(error) => LocalAuthOutcome::Unavailable(format!("cannot run pkcheck: {error}")),
    }
}

fn command(reason: &str, pid: u32, start_time: u64) -> Command {
    let mut command = Command::new("pkcheck");
    command.args([
        "--action-id",
        "org.freedesktop.policykit.exec",
        "--process",
        &format!("{pid},{start_time}"),
        "--allow-user-interaction",
        "--detail",
        "polkit.message",
        reason,
    ]);
    command.stdin(std::process::Stdio::null());
    command
}

/// Field 22 follows the state (field 3) by 19 fields. `comm` (field 2) can
/// contain whitespace and parentheses, so only the final ')' ends that field.
fn process_start_time(stat: &str) -> Result<u64, &'static str> {
    let (_, fields) = stat
        .rsplit_once(')')
        .ok_or("/proc/self/stat has no comm terminator")?;
    fields
        .split_whitespace()
        .nth(19)
        .ok_or("/proc/self/stat has no start time")?
        .parse()
        .map_err(|_| "/proc/self/stat has an invalid start time")
}

fn outcome(code: Option<i32>, stderr: &[u8]) -> LocalAuthOutcome {
    match code {
        Some(0) => LocalAuthOutcome::Confirmed,
        // pkcheck(1): 1 = not authorized, 3 = dialog dismissed. 2 means user interaction was
        // needed but no authentication agent could ask: Unavailable, named so the hint can say so.
        Some(1 | 3) => LocalAuthOutcome::Denied,
        Some(2) => LocalAuthOutcome::Unavailable(format!(
            "{}: {}",
            super::NO_POLKIT_AGENT,
            String::from_utf8_lossy(stderr).trim()
        )),
        _ => LocalAuthOutcome::Unavailable(format!(
            "pkcheck failed (exit {code:?}): {}",
            String::from_utf8_lossy(stderr).trim()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(comm: &str, start: &str) -> String {
        // Fields 4..21 intentionally differ from field 22 to catch off-by-one errors.
        format!("42 ({comm}) S {}{start} 900 901\n", "7 ".repeat(18))
    }

    #[test]
    fn reads_field_22() {
        assert_eq!(process_start_time(&stat("kc", "123456")), Ok(123456));
        assert_eq!(process_start_time(&stat("kc", "0")), Ok(0));
        assert_eq!(
            process_start_time(&stat("kc", "18446744073709551615")),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn comm_can_contain_spaces_and_parentheses() {
        for comm in [
            "kc local confirm",
            "kc (nested) name",
            "kc)) (a) b)",
            "kc\nname",
        ] {
            assert_eq!(process_start_time(&stat(comm, "123456")), Ok(123456));
        }
    }

    #[test]
    fn malformed_stat_is_unavailable() {
        for text in ["", "42 kc S 1 2 3", "42 (kc) S 1 2 3"] {
            assert!(process_start_time(text).is_err());
        }
        for start in ["invalid", "-1", "18446744073709551616"] {
            assert!(process_start_time(&stat("kc", start)).is_err());
        }
    }

    #[test]
    fn reason_is_one_argument_and_no_internal_agent_is_enabled() {
        let command = command("kc: allow 'this' $(action)?", 42, 123456);
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "--action-id",
                "org.freedesktop.policykit.exec",
                "--process",
                "42,123456",
                "--allow-user-interaction",
                "--detail",
                "polkit.message",
                "kc: allow 'this' $(action)?",
            ]
        );
    }

    #[test]
    fn exit_status_fails_closed() {
        assert_eq!(outcome(Some(0), b""), LocalAuthOutcome::Confirmed);
        assert_eq!(outcome(Some(1), b""), LocalAuthOutcome::Denied);
        assert_eq!(outcome(Some(3), b""), LocalAuthOutcome::Denied);
        for code in [Some(2), Some(126), Some(127), Some(255), None] {
            match outcome(code, b"no agent\n") {
                LocalAuthOutcome::Unavailable(message) => assert!(message.contains("no agent")),
                result => panic!("unexpected outcome: {result:?}"),
            }
        }
    }

    #[test]
    fn exit_2_is_a_missing_agent() {
        let stderr = b"Authorization requires authentication but no agent is available.\n";
        match outcome(Some(2), stderr) {
            LocalAuthOutcome::Unavailable(message) => {
                assert!(message.starts_with(super::super::NO_POLKIT_AGENT));
                assert!(message.ends_with("no agent is available."));
            }
            result => panic!("unexpected outcome: {result:?}"),
        }
        assert!(!matches!(
            outcome(Some(127), stderr),
            LocalAuthOutcome::Unavailable(m) if m.starts_with(super::super::NO_POLKIT_AGENT)
        ));
    }
}
