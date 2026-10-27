//! Fehler des Programms mit dem dazugehörigen Exit-Code.

use std::fmt;

/// Exit-Codes, die das Programm verwendet (Remote-Codes von `exec` und `shell` kommen dazu).
pub mod exit {
    /// Allgemeiner Fehler.
    pub const GENERAL: i32 = 1;
    /// Der Host-Key des Servers ist unbekannt.
    pub const UNKNOWN_HOST: i32 = 2;
    /// Der Host-Key des Servers hat sich geändert oder passt nicht zu `--fingerprint`.
    pub const CHANGED_HOST: i32 = 3;
    /// Anmeldung fehlgeschlagen.
    pub const AUTH: i32 = 4;
    /// Falsche Bedienung (Argumente).
    pub const USAGE: i32 = 64;
}

/// Ein Fehler mit Meldung und Exit-Code.
#[derive(Debug)]
pub struct CliError {
    pub code: i32,
    pub message: String,
}

impl CliError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self::new(exit::GENERAL, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(exit::USAGE, message)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}
