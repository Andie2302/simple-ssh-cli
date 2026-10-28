//! Abbildung des Remote-Status auf Exit-Codes (Konvention von ssh).

use simple_ssh_lib::ExitStatus;

use crate::signals;

/// Exit-Code, wenn die Verbindung verloren ging oder kein Status vorliegt (wie ssh).
pub const LOST: i32 = 255;
/// 128 + SIGPIPE: lokales stdout wurde geschlossen (`… | head`).
pub const BROKEN_PIPE: i32 = 141;
/// 128 + SIGINT.
pub const INTERRUPTED: i32 = 130;

/// Übersetzt den Status des Remote-Programms in einen Exit-Code.
pub fn exit_code(status: &ExitStatus) -> i32 {
    match status {
        ExitStatus::Code(n) => i32::try_from(*n).map_or(LOST, |n| n.clamp(0, 255)),
        ExitStatus::Signal(name) => signals::number(name).map_or(LOST, |n| 128 + n),
        _ => LOST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_codes_pass_through_and_signals_follow_the_shell_convention() {
        assert_eq!(exit_code(&ExitStatus::Code(0)), 0);
        assert_eq!(exit_code(&ExitStatus::Code(7)), 7);
        assert_eq!(exit_code(&ExitStatus::Code(255)), 255);
        assert_eq!(exit_code(&ExitStatus::Code(300)), 255);
        assert_eq!(exit_code(&ExitStatus::Signal("KILL".into())), 137);
        assert_eq!(exit_code(&ExitStatus::Signal("SIGTERM".into())), 143);
        assert_eq!(exit_code(&ExitStatus::Signal("WHATEVER".into())), 255);
        assert_eq!(exit_code(&ExitStatus::Unknown), 255);
    }
}
