//! `hostkey`: Fingerprint des Servers anzeigen, ohne ihm zu vertrauen.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use simple_ssh_lib::transport::Transport;
use simple_ssh_lib::{Error, HostKeyCheck};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::cli::GlobalArgs;
use crate::connect::build_policy;
use crate::error::CliError;
use crate::hostkeys::Decision;
use crate::target::Target;

pub async fn run(global: &GlobalArgs, target: &Target) -> Result<(), CliError> {
    let limit = Duration::from_secs(global.timeout);
    let timed_out = || {
        CliError::general(format!(
            "Zeitüberschreitung: keine Antwort von {} innerhalb von {} s (--timeout)",
            target.display_addr(),
            global.timeout
        ))
    };
    let unreachable = |e: std::io::Error| {
        CliError::general(format!(
            "Verbindung zu {} fehlgeschlagen: {e}",
            target.display_addr()
        ))
    };

    // Der Callback merkt sich den Fingerprint und lehnt ab: Es wird nichts anvertraut
    // und nichts gespeichert. Die Signatur des Servers prüft die Bibliothek vorher.
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let recorder = seen.clone();
    let check = HostKeyCheck::Callback(Box::new(move |key| {
        *recorder.lock().unwrap_or_else(|e| e.into_inner()) = Some(key.fingerprint());
        false
    }));

    let stream = timeout(
        limit,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| timed_out())?
    .map_err(unreachable)?;
    let handshake = timeout(limit, Transport::connect(stream, &check))
        .await
        .map_err(|_| timed_out())?;
    let fingerprint = match handshake {
        Err(Error::HostKeyRejected { fingerprint }) => fingerprint,
        Err(Error::NoCommonAlgorithm(what)) => {
            return Err(CliError::general(format!(
                "Der Server bietet keinen ssh-ed25519-Host-Key oder keinen anderen benötigten Algorithmus an ({what})"
            )));
        }
        Err(other) => {
            return Err(CliError::general(format!(
                "Handshake mit {} fehlgeschlagen: {other}",
                target.display_addr()
            )));
        }
        Ok(_) => {
            // Kann nicht vorkommen, weil der Callback immer ablehnt.
            return Err(CliError::general(
                "Unerwarteter Verlauf: Der Host-Key wurde nicht abgelehnt",
            ));
        }
    };

    println!("256 {fingerprint} {} (ED25519)", target.known_hosts_label());

    // Vergleich mit dem, was wir schon kennen (nur Anzeige).
    let (policy, path) = build_policy(global, target)?;
    let status = match policy.decide(&fingerprint) {
        Decision::Trusted => format!("bekannt (in {})", path.display()),
        Decision::PinnedOk => "stimmt mit --fingerprint überein".to_string(),
        Decision::Unknown => format!("unbekannt (noch nicht in {})", path.display()),
        Decision::Changed { expected } => format!("ABWEICHEND von {}", expected.join(", ")),
        Decision::PinnedMismatch { expected } => format!("ABWEICHEND von --fingerprint {expected}"),
    };
    eprintln!("Status: {status}");
    Ok(())
}
