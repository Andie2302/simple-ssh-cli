//! Host-Key-Prüfung: eigene `known_hosts`-Datei und die Entscheidungsregeln.
//!
//! Regeln (sicherheitsrelevant):
//! * Ein geänderter Key wird nie akzeptiert und die Datei nie umgeschrieben.
//! * Ein unbekannter Server wird nur mit `--accept-new` akzeptiert und erst nach
//!   erfolgreicher Anmeldung gespeichert.
//! * `--fingerprint` hat Vorrang und lässt die Datei unberührt.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use simple_ssh_lib::{HostKey, HostKeyCheck};

use crate::error::CliError;

/// Länge eines SHA-256-Fingerprints in Base64 ohne Padding.
const FINGERPRINT_BASE64_LEN: usize = 43;

/// Prüft die Form `SHA256:<43 Base64-Zeichen>`.
pub fn is_valid_fingerprint(s: &str) -> bool {
    match s.strip_prefix("SHA256:") {
        Some(b64) => {
            b64.len() == FINGERPRINT_BASE64_LEN
                && b64
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
        }
        None => false,
    }
}

/// Standardpfad: `$XDG_CONFIG_HOME/simple-ssh-cli/known_hosts` bzw. `~/.config/...`.
pub fn default_path() -> Result<PathBuf, CliError> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    CliError::general(
                        "Weder XDG_CONFIG_HOME noch HOME ist gesetzt; nutze --known-hosts <datei>",
                    )
                })?;
            PathBuf::from(home).join(".config")
        }
    };
    Ok(base.join("simple-ssh-cli").join("known_hosts"))
}

/// Inhalt einer `known_hosts`-Datei: Zeilen `host SHA256:...`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KnownHosts {
    entries: Vec<(String, String)>,
}

impl KnownHosts {
    /// Liest den Text einer Datei. Kommentare (`#`) und Leerzeilen werden übersprungen,
    /// ungültige Zeilen führen zu einem Fehler mit Zeilennummer.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(host), Some(fingerprint)) = (fields.next(), fields.next()) else {
                return Err(format!("Zeile {}: erwartet `host SHA256:...`", index + 1));
            };
            if !is_valid_fingerprint(fingerprint) {
                return Err(format!(
                    "Zeile {}: `{fingerprint}` ist kein gültiger SHA256-Fingerprint",
                    index + 1
                ));
            }
            entries.push((host.to_string(), fingerprint.to_string()));
        }
        Ok(Self { entries })
    }

    /// Lädt die Datei; fehlt sie, ist die Liste leer.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).map_err(|e| {
                CliError::general(format!("known_hosts-Datei {}: {e}", path.display()))
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(CliError::general(format!(
                "known_hosts-Datei {} nicht lesbar: {e}",
                path.display()
            ))),
        }
    }

    /// Alle für `host` gespeicherten Fingerprints.
    pub fn fingerprints_for(&self, host: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(h, _)| h == host)
            .map(|(_, f)| f.as_str())
            .collect()
    }
}

/// Hängt `host fingerprint` an die Datei an (legt Verzeichnis 0700 und Datei 0600 an).
/// Vorhandenes wird nie verändert; ein schon vorhandener identischer Eintrag wird nicht doppelt geschrieben.
pub fn append(path: &Path, host: &str, fingerprint: &str) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    let mut existing = String::new();
    file.read_to_string(&mut existing)?;
    let line = format!("{host} {fingerprint}");
    if existing
        .lines()
        .any(|l| l.split_whitespace().take(2).collect::<Vec<_>>() == [host, fingerprint])
    {
        return Ok(());
    }
    let mut out = String::new();
    if !existing.is_empty() && !existing.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&line);
    out.push('\n');
    file.write_all(out.as_bytes())
}

/// Ergebnis der Prüfung eines Host-Keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// In der Datei vorhanden.
    Trusted,
    /// Stimmt mit `--fingerprint` überein.
    PinnedOk,
    /// Für diesen Host steht nichts in der Datei.
    Unknown,
    /// Für diesen Host stehen andere Fingerprints in der Datei.
    Changed { expected: Vec<String> },
    /// Weicht von `--fingerprint` ab.
    PinnedMismatch { expected: String },
}

/// Regeln für die Host-Key-Prüfung einer Verbindung.
#[derive(Debug, Clone)]
pub struct Policy {
    pub known: KnownHosts,
    /// Schlüssel in der Datei (`host` bzw. `[host]:port`).
    pub label: String,
    pub accept_new: bool,
    pub pinned: Option<String>,
}

impl Policy {
    /// Beurteilt den vom Server gezeigten Fingerprint.
    pub fn decide(&self, fingerprint: &str) -> Decision {
        if let Some(pinned) = &self.pinned {
            return if pinned == fingerprint {
                Decision::PinnedOk
            } else {
                Decision::PinnedMismatch {
                    expected: pinned.clone(),
                }
            };
        }
        let known = self.known.fingerprints_for(&self.label);
        if known.is_empty() {
            Decision::Unknown
        } else if known.contains(&fingerprint) {
            Decision::Trusted
        } else {
            Decision::Changed {
                expected: known.into_iter().map(str::to_string).collect(),
            }
        }
    }

    /// Darf die Verbindung mit dieser Entscheidung weiterlaufen?
    pub fn allows(&self, decision: &Decision) -> bool {
        match decision {
            Decision::Trusted | Decision::PinnedOk => true,
            Decision::Unknown => self.accept_new,
            Decision::Changed { .. } | Decision::PinnedMismatch { .. } => false,
        }
    }
}

/// Was der Callback beobachtet hat.
#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub fingerprint: Option<String>,
    pub decision: Option<Decision>,
}

/// Baut aus der Richtlinie den Prüf-Callback für die Bibliothek.
/// Das zweite Ergebnis gibt Zugriff auf die beobachtete Entscheidung.
pub fn host_key_check(policy: Policy) -> (HostKeyCheck, Arc<Mutex<Outcome>>) {
    let outcome = Arc::new(Mutex::new(Outcome::default()));
    let shared = outcome.clone();
    let check = HostKeyCheck::Callback(Box::new(move |key: &HostKey| {
        let fingerprint = key.fingerprint();
        let decision = policy.decide(&fingerprint);
        let allowed = policy.allows(&decision);
        let mut seen = shared.lock().unwrap_or_else(|e| e.into_inner());
        seen.fingerprint = Some(fingerprint);
        seen.decision = Some(decision);
        allowed
    }));
    (check, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FP_B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn policy(known: &str, accept_new: bool, pinned: Option<&str>) -> Policy {
        Policy {
            known: KnownHosts::parse(known).unwrap(),
            label: "host".into(),
            accept_new,
            pinned: pinned.map(str::to_string),
        }
    }

    #[test]
    fn fingerprint_format_is_validated() {
        assert!(is_valid_fingerprint(FP_A));
        for bad in [
            "",
            "SHA256:",
            "SHA1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "SHA256:short",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(!is_valid_fingerprint(bad), "{bad}");
        }
    }

    #[test]
    fn parser_skips_comments_and_reports_bad_lines_with_numbers() {
        let text = format!("# Kommentar\n\nhost {FP_A}\n  [h]:22 {FP_B}  # Rest\n");
        let kh = KnownHosts::parse(&text).unwrap();
        assert_eq!(kh.fingerprints_for("host"), [FP_A]);
        assert_eq!(kh.fingerprints_for("[h]:22"), [FP_B]);
        assert!(kh.fingerprints_for("other").is_empty());

        assert!(
            KnownHosts::parse("host\n")
                .unwrap_err()
                .starts_with("Zeile 1")
        );
        let err = KnownHosts::parse(&format!("host {FP_A}\nhost nonsense\n")).unwrap_err();
        assert!(err.starts_with("Zeile 2"), "{err}");
    }

    #[test]
    fn one_host_may_have_several_keys() {
        let kh = KnownHosts::parse(&format!("host {FP_A}\nhost {FP_B}\n")).unwrap();
        assert_eq!(kh.fingerprints_for("host"), [FP_A, FP_B]);
    }

    /// Alle Kombinationen aus Dateistand, `--accept-new` und `--fingerprint`.
    #[test]
    fn decision_table() {
        let known = format!("host {FP_A}\n");
        let unknown = String::new();
        let other = format!("host {FP_B}\n");
        for accept_new in [false, true] {
            // bekannt und passend
            let p = policy(&known, accept_new, None);
            assert_eq!(p.decide(FP_A), Decision::Trusted);
            assert!(p.allows(&p.decide(FP_A)));
            // unbekannt: nur mit --accept-new
            let p = policy(&unknown, accept_new, None);
            assert_eq!(p.decide(FP_A), Decision::Unknown);
            assert_eq!(p.allows(&p.decide(FP_A)), accept_new);
            // geändert: nie, auch nicht mit --accept-new
            let p = policy(&other, accept_new, None);
            assert_eq!(
                p.decide(FP_A),
                Decision::Changed {
                    expected: vec![FP_B.into()]
                }
            );
            assert!(!p.allows(&p.decide(FP_A)));
            // bekannt, aber zusätzlich anderer Key vorhanden: der passende gilt
            let p = policy(&format!("host {FP_B}\nhost {FP_A}\n"), accept_new, None);
            assert_eq!(p.decide(FP_A), Decision::Trusted);
            // --fingerprint hat Vorrang, egal was in der Datei steht
            for file in [&known, &unknown, &other] {
                let p = policy(file, accept_new, Some(FP_A));
                assert_eq!(p.decide(FP_A), Decision::PinnedOk);
                assert!(p.allows(&p.decide(FP_A)));
                assert_eq!(
                    p.decide(FP_B),
                    Decision::PinnedMismatch {
                        expected: FP_A.into()
                    }
                );
                assert!(!p.allows(&p.decide(FP_B)));
            }
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ssc-unit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn append_creates_private_files_and_never_rewrites() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("append");
        let path = dir.join("cfg").join("known_hosts");
        append(&path, "a", FP_A).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        append(&path, "b", FP_B).unwrap();
        append(&path, "a", FP_A).unwrap(); // Duplikat wird nicht erneut geschrieben
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, format!("a {FP_A}\nb {FP_B}\n"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_keeps_existing_content_even_without_trailing_newline() {
        let dir = scratch("nonl");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        fs::write(&path, format!("# mein Kommentar\nold {FP_A}")).unwrap();
        append(&path, "new", FP_B).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("# mein Kommentar\nold {FP_A}\nnew {FP_B}\n")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_empty_and_broken_file_is_an_error() {
        let dir = scratch("load");
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            KnownHosts::load(&dir.join("nope")).unwrap(),
            KnownHosts::default()
        );
        let bad = dir.join("bad");
        fs::write(&bad, "kaputt\n").unwrap();
        let err = KnownHosts::load(&bad).unwrap_err();
        assert!(err.message.contains("Zeile 1"), "{}", err.message);
        let _ = fs::remove_dir_all(&dir);
    }
}
