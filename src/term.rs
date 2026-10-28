//! Terminal: Raw-Mode mit Wächter, Größe.

use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};

/// Schaltet den Raw-Mode ein und beim Fallenlassen wieder aus.
pub struct RawMode(());

impl RawMode {
    pub fn enable() -> std::io::Result<Self> {
        enable_raw_mode()?;
        // Auch bei einer Panik muss das Terminal zurückgesetzt werden, bevor die Meldung erscheint.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            previous(info);
        }));
        Ok(Self(()))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Größe des Terminals (Spalten, Zeilen); 80x24, wenn sie sich nicht ermitteln lässt.
pub fn terminal_size() -> (u32, u32) {
    match size() {
        Ok((c, r)) if c > 0 && r > 0 => (u32::from(c), u32::from(r)),
        _ => (80, 24),
    }
}

/// Wert für `$TERM`: aus der Umgebung, sonst `xterm-256color`.
pub fn term_name() -> String {
    pick_term(std::env::var("TERM").ok())
}

fn pick_term(value: Option<String>) -> String {
    value
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| "xterm-256color".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_selection() {
        assert_eq!(pick_term(Some("vt100".into())), "vt100");
        assert_eq!(pick_term(Some("  ".into())), "xterm-256color");
        assert_eq!(pick_term(None), "xterm-256color");
    }
}
