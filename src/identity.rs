//! Privaten Schlüssel laden, bei Bedarf mit Passphrase.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use simple_ssh_lib::{Error, PrivateKey};
use zeroize::Zeroizing;

use crate::error::CliError;

const PASSPHRASE_ENV: &str = "SSH_KEY_PASSPHRASE";
const MAX_PROMPTS: usize = 3;

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// Ersetzt ein führendes `~` durch das Home-Verzeichnis.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let mut parts = path.components();
    match (parts.next(), home()) {
        (Some(std::path::Component::Normal(first)), Some(home)) if first == "~" => {
            home.join(parts.as_path())
        }
        _ => path.to_path_buf(),
    }
}

/// `~/.ssh/id_ed25519`
pub fn default_identity() -> Result<PathBuf, CliError> {
    home()
        .map(|h| h.join(".ssh").join("id_ed25519"))
        .ok_or_else(|| {
            CliError::general("HOME ist nicht gesetzt; gib den Schlüssel mit --identity an")
        })
}

fn describe(path: &Path, err: Error) -> CliError {
    let shown = path.display();
    match err {
        Error::UnsupportedKey(why) => CliError::general(format!(
            "Der Schlüssel {shown} wird nicht unterstützt ({why}). Erwartet wird ein ed25519-Schlüssel im OpenSSH-Format (ssh-keygen -t ed25519)"
        )),
        Error::Malformed(_) | Error::UnexpectedEof | Error::TrailingData(_) => {
            CliError::general(format!("{shown} ist keine gültige OpenSSH-Schlüsseldatei"))
        }
        Error::WrongPassphrase => CliError::general(format!("Falsche Passphrase für {shown}")),
        other => CliError::general(format!("Schlüssel {shown} nicht verwendbar: {other}")),
    }
}

fn with_passphrase(
    text: &str,
    path: &Path,
    passphrase: &Zeroizing<String>,
    source: &str,
) -> Result<PrivateKey, CliError> {
    PrivateKey::from_openssh(text, Some(passphrase.as_bytes())).map_err(|e| match e {
        Error::WrongPassphrase => CliError::general(format!(
            "Falsche Passphrase für {} (aus {source})",
            path.display()
        )),
        other => describe(path, other),
    })
}

/// Lädt den Schlüssel. Ist er verschlüsselt, kommt die Passphrase der Reihe nach aus
/// `SSH_KEY_PASSPHRASE`, aus `--passphrase-file` oder per Rückfrage im Terminal.
pub fn load(path: &Path, passphrase_file: Option<&Path>) -> Result<PrivateKey, CliError> {
    let path = expand_tilde(path);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        CliError::general(format!(
            "Schlüsseldatei {} nicht lesbar: {e}",
            path.display()
        ))
    })?;

    match PrivateKey::from_openssh(&text, None) {
        Ok(key) => return Ok(key),
        Err(Error::PassphraseRequired) => {}
        Err(other) => return Err(describe(&path, other)),
    }

    if let Some(value) = std::env::var(PASSPHRASE_ENV).ok().filter(|v| !v.is_empty()) {
        return with_passphrase(&text, &path, &Zeroizing::new(value), PASSPHRASE_ENV);
    }

    if let Some(file) = passphrase_file {
        let file = expand_tilde(file);
        let raw = Zeroizing::new(std::fs::read_to_string(&file).map_err(|e| {
            CliError::general(format!(
                "Passphrase-Datei {} nicht lesbar: {e}",
                file.display()
            ))
        })?);
        let line = raw.lines().next().unwrap_or("");
        return with_passphrase(
            &text,
            &path,
            &Zeroizing::new(line.to_string()),
            "--passphrase-file",
        );
    }

    if std::io::stdin().is_terminal() {
        for attempt in 1..=MAX_PROMPTS {
            eprint!("Passphrase für {}: ", path.display());
            let _ = std::io::stderr().flush();
            let entered = rpassword::read_password().map_err(|e| {
                CliError::general(format!("Passphrase konnte nicht gelesen werden: {e}"))
            })?;
            let passphrase = Zeroizing::new(entered);
            match PrivateKey::from_openssh(&text, Some(passphrase.as_bytes())) {
                Ok(key) => return Ok(key),
                Err(Error::WrongPassphrase) if attempt < MAX_PROMPTS => {
                    eprintln!("Falsche Passphrase, nochmal.")
                }
                Err(Error::WrongPassphrase) => {
                    return Err(CliError::general(format!(
                        "Falsche Passphrase für {} ({MAX_PROMPTS} Versuche)",
                        path.display()
                    )));
                }
                Err(other) => return Err(describe(&path, other)),
            }
        }
    }

    Err(CliError::general(format!(
        "Der Schlüssel {} ist durch eine Passphrase geschützt. Setze {PASSPHRASE_ENV}, nutze --passphrase-file oder starte das Programm in einem Terminal",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_is_only_expanded_at_the_start_of_a_path() {
        // HOME wird hier nicht verändert (Tests laufen parallel); wir prüfen nur,
        // dass Pfade ohne führende Tilde unverändert bleiben.
        assert_eq!(
            expand_tilde(Path::new("/etc/key")),
            PathBuf::from("/etc/key")
        );
        assert_eq!(
            expand_tilde(Path::new("rel/~/key")),
            PathBuf::from("rel/~/key")
        );
        assert_eq!(
            expand_tilde(Path::new("~user/key")),
            PathBuf::from("~user/key")
        );
    }
}
