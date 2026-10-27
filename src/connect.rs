//! Verbindung aufbauen: Schlüssel laden, Host-Key prüfen, anmelden, Fehler übersetzen.

use std::path::PathBuf;
use std::time::Duration;

use simple_ssh_lib::{Config, Error, Session};

use crate::cli::GlobalArgs;
use crate::error::{CliError, exit};
use crate::hostkeys::{self, Decision, KnownHosts, Outcome, Policy};
use crate::identity;
use crate::target::Target;

/// Eine angemeldete Verbindung.
pub struct Connected {
    pub session: Session,
    pub user: String,
}

/// Baut die Host-Key-Richtlinie aus den Optionen. Gibt außerdem den Pfad der known_hosts-Datei zurück.
pub fn build_policy(global: &GlobalArgs, target: &Target) -> Result<(Policy, PathBuf), CliError> {
    let path = match &global.known_hosts {
        Some(p) => identity::expand_tilde(p),
        None => hostkeys::default_path()?,
    };
    if let Some(fp) = global
        .fingerprint
        .as_deref()
        .filter(|fp| !hostkeys::is_valid_fingerprint(fp))
    {
        return Err(CliError::usage(format!(
            "--fingerprint `{fp}` hat nicht die Form SHA256:<43 Zeichen Base64>"
        )));
    }
    // Mit --fingerprint wird die Datei weder gelesen noch verändert.
    let known = if global.fingerprint.is_some() {
        KnownHosts::default()
    } else {
        KnownHosts::load(&path)?
    };
    let policy = Policy {
        known,
        label: target.known_hosts_label(),
        accept_new: global.accept_new,
        pinned: global.fingerprint.clone(),
    };
    Ok((policy, path))
}

/// Übersetzt einen Fehler der Bibliothek in eine verständliche Meldung samt Exit-Code.
pub fn translate(
    err: Error,
    outcome: &Outcome,
    target: &Target,
    user: &str,
    known_hosts: &std::path::Path,
    timeout: u64,
) -> CliError {
    let label = target.known_hosts_label();
    match err {
        Error::HostKeyRejected { fingerprint } => match &outcome.decision {
            Some(Decision::Unknown) => CliError::new(
                exit::UNKNOWN_HOST,
                format!(
                    "Der Host-Key von {label} ist unbekannt.\n  Fingerprint: {fingerprint}\nPrüfe ihn über einen vertrauenswürdigen Weg. Mit --accept-new wird er nach erfolgreicher Anmeldung in {} gespeichert (oder gib ihn mit --fingerprint an).",
                    known_hosts.display()
                ),
            ),
            Some(Decision::Changed { expected }) => CliError::new(
                exit::CHANGED_HOST,
                format!(
                    "WARNUNG: Der Host-Key von {label} hat sich geändert!\n  erwartet:  {}\n  erhalten:  {fingerprint}\nDie Verbindung wurde abgebrochen. {} wird nicht verändert. Ist der Wechsel gewollt, entferne die alte Zeile dort von Hand.",
                    expected.join(", "),
                    known_hosts.display()
                ),
            ),
            Some(Decision::PinnedMismatch { expected }) => CliError::new(
                exit::CHANGED_HOST,
                format!(
                    "Der Host-Key von {label} passt nicht zu --fingerprint!\n  erwartet:  {expected}\n  erhalten:  {fingerprint}"
                ),
            ),
            _ => CliError::general(format!("Host-Key von {label} abgelehnt ({fingerprint})")),
        },
        Error::AuthFailed => CliError::new(
            exit::AUTH,
            format!(
                "Anmeldung als {user} abgelehnt: Der Server akzeptiert diesen Schlüssel nicht (authorized_keys und Benutzername prüfen)"
            ),
        ),
        Error::PublicKeyAuthUnavailable => CliError::new(
            exit::AUTH,
            "Der Server bietet keine Public-Key-Anmeldung an; mehr unterstützt dieses Programm nicht",
        ),
        Error::Timeout(_) => CliError::general(format!(
            "Zeitüberschreitung: keine fertige Verbindung zu {} innerhalb von {timeout} s (--timeout)",
            target.display_addr()
        )),
        Error::NoCommonAlgorithm(what) => CliError::general(format!(
            "Der Server unterstützt einen benötigten Algorithmus nicht: {what}. Verwendet werden ausschließlich curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com und Strict KEX"
        )),
        Error::Io(e) => CliError::general(format!(
            "Verbindung zu {} fehlgeschlagen: {e}",
            target.display_addr()
        )),
        other => CliError::general(format!(
            "Verbindung zu {} fehlgeschlagen: {other}",
            target.display_addr()
        )),
    }
}

/// Verbindet und meldet an. Ein neuer Host wird bei `--accept-new` erst nach der Anmeldung gespeichert.
pub async fn connect(global: &GlobalArgs, target: &Target) -> Result<Connected, CliError> {
    let user = target.resolve_user()?;
    let identity_path = match &global.identity {
        Some(p) => p.clone(),
        None => identity::default_identity()?,
    };
    let key = identity::load(&identity_path, global.passphrase_file.as_deref())?;
    let (policy, known_path) = build_policy(global, target)?;
    let (check, outcome) = hostkeys::host_key_check(policy);

    let config = Config::new(user.clone(), key, check).timeout(Duration::from_secs(global.timeout));
    if global.verbose {
        eprintln!("Verbinde mit {} als {user} ...", target.display_addr());
    }
    let result = Session::connect((target.host.as_str(), target.port), config).await;
    let seen = outcome.lock().unwrap_or_else(|e| e.into_inner()).clone();

    match result {
        Ok(session) => {
            if let (Some(Decision::Unknown), Some(fp)) = (&seen.decision, &seen.fingerprint) {
                // Nur mit --accept-new kann eine unbekannte Verbindung hier ankommen.
                match hostkeys::append(&known_path, &target.known_hosts_label(), fp) {
                    Ok(()) => eprintln!(
                        "Hinweis: Host-Key von {} gespeichert ({fp}) in {}",
                        target.known_hosts_label(),
                        known_path.display()
                    ),
                    Err(e) => eprintln!(
                        "Warnung: Host-Key konnte nicht in {} gespeichert werden: {e}",
                        known_path.display()
                    ),
                }
            }
            Ok(Connected { session, user })
        }
        Err(e) => Err(translate(
            e,
            &seen,
            target,
            &user,
            &known_path,
            global.timeout,
        )),
    }
}
