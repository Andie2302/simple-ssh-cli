//! Ausgabeformate: Größen, Rechte, Zeiten, Fortschritt.

use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

/// `1536` → `1.5 KiB`.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Durchsatz als `12.3 MiB/s`.
pub fn rate(bytes: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64().max(0.000_001);
    format!("{}/s", size((bytes as f64 / secs) as u64))
}

/// Modus als `drwxr-xr-x`.
pub fn mode_string(mode: u32) -> String {
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o100000 => '-',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '?',
    };
    let mut s = String::with_capacity(10);
    s.push(kind);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

/// Sekunden seit 1970 als `JJJJ-MM-TT HH:MM` (UTC).
pub fn time(secs: u32) -> String {
    let secs = u64::from(secs);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Datum aus Tagen seit 1970 (Algorithmus von Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Fortschrittsanzeige auf stderr. Zeichnet nur auf einem Terminal, die Zusammenfassung am Ende
/// kommt immer.
pub struct Progress {
    label: String,
    total: Option<u64>,
    started: Instant,
    last_draw: Instant,
    tty: bool,
}

impl Progress {
    pub fn new(label: impl Into<String>, total: Option<u64>) -> Self {
        let now = Instant::now();
        Self {
            label: label.into(),
            total,
            started: now,
            last_draw: now,
            tty: std::io::stderr().is_terminal(),
        }
    }

    pub fn update(&mut self, done: u64) {
        if !self.tty || self.last_draw.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.last_draw = Instant::now();
        let mut err = std::io::stderr();
        let percent = match self.total {
            Some(t) if t > 0 => format!(" / {}  {:>3}%", size(t), done * 100 / t),
            _ => String::new(),
        };
        let _ = write!(
            err,
            "\r\x1b[K{}  {}{}  {}",
            self.label,
            size(done),
            percent,
            rate(done, self.started.elapsed())
        );
        let _ = err.flush();
    }

    pub fn finish(self, done: u64) {
        if self.tty {
            eprint!("\r\x1b[K");
        }
        let elapsed = self.started.elapsed();
        eprintln!(
            "{}: {} in {:.1} s ({})",
            self.label,
            size(done),
            elapsed.as_secs_f64(),
            rate(done, elapsed)
        );
    }

    /// Bricht ohne Zusammenfassung ab (Zeile aufräumen).
    pub fn abort(self) {
        if self.tty {
            eprint!("\r\x1b[K");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(20 * 1024 * 1024), "20.0 MiB");
    }

    #[test]
    fn modes() {
        assert_eq!(mode_string(0o100644), "-rw-r--r--");
        assert_eq!(mode_string(0o040755), "drwxr-xr-x");
        assert_eq!(mode_string(0o120777), "lrwxrwxrwx");
    }

    #[test]
    fn times() {
        assert_eq!(time(0), "1970-01-01 00:00");
        assert_eq!(time(951_782_400), "2000-02-29 00:00");
        assert_eq!(time(1_700_000_000), "2023-11-14 22:13");
    }
}
