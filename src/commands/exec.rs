//! `exec`: Befehl ausführen, Ausgabe und Eingabe laufen live.
//!
//! Exit-Code wie bei ssh: der des Remote-Befehls; bei Signal 128 + Nummer; 255, wenn die
//! Verbindung verloren geht oder der Server keinen Status meldet.

use std::io::{ErrorKind, IsTerminal};

use simple_ssh_lib::{Error, ExecEvent, ExecStdin, ExitStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cli::GlobalArgs;
use crate::connect;
use crate::error::CliError;
use crate::signals;
use crate::target::Target;

/// Exit-Code, wenn die Verbindung verloren ging oder kein Status vorliegt (wie ssh).
const LOST: i32 = 255;
/// 128 + SIGPIPE: lokales stdout wurde geschlossen (`… | head`).
const BROKEN_PIPE: i32 = 141;
/// 128 + SIGINT.
const INTERRUPTED: i32 = 130;

/// Übersetzt den Status des Remote-Befehls in einen Exit-Code.
pub fn exit_code(status: &ExitStatus) -> i32 {
    match status {
        ExitStatus::Code(n) => i32::try_from(*n).map_or(LOST, |n| n.clamp(0, 255)),
        ExitStatus::Signal(name) => signals::number(name).map_or(LOST, |n| 128 + n),
        _ => LOST,
    }
}

fn lost(e: &Error) -> CliError {
    CliError::new(LOST, format!("Verbindung zum Server verloren: {e}"))
}

/// Reicht lokales stdin an den Befehl weiter und sendet am Ende EOF.
async fn pump_stdin(mut stdin: ExecStdin) {
    let mut local = tokio::io::stdin();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match local.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdin.write_all(&buf[..n]).await.is_err() {
                    return; // der Befehl ist beendet oder die Verbindung weg
                }
            }
        }
    }
    let _ = stdin.shutdown().await;
}

pub async fn run(
    global: &GlobalArgs,
    target: &Target,
    no_stdin: bool,
    command: &[String],
) -> Result<i32, CliError> {
    let command = command.join(" ");
    // Erst anmelden (und dabei den Host-Key prüfen): Bei unbekanntem oder geändertem Key
    // läuft auf dem Server nichts.
    let connected = connect::connect(global, target).await?;
    let stream = connected
        .session
        .exec_stream(&command)
        .await
        .map_err(|e| match e {
            Error::CommandRejected => CliError::general("Der Server hat den Befehl abgelehnt"),
            other => lost(&other),
        })?;
    let (stdin, mut events) = stream.split();

    let pump = if no_stdin || std::io::stdin().is_terminal() {
        // Ohne Eingabe: der Befehl sieht sofort EOF.
        let mut stdin = stdin;
        let _ = stdin.shutdown().await;
        None
    } else {
        Some(tokio::spawn(pump_stdin(stdin)))
    };

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let output = async {
        loop {
            match events.next().await {
                Ok(Some(ExecEvent::Stdout(data))) => {
                    if let Err(e) = write_flush(&mut stdout, &data).await {
                        return Err(local_write_error(e));
                    }
                }
                Ok(Some(ExecEvent::Stderr(data))) => {
                    if let Err(e) = write_flush(&mut stderr, &data).await {
                        return Err(local_write_error(e));
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => return Ok(()),
                Err(e) => return Err(lost(&e)),
            }
        }
    };

    let finished = tokio::select! {
        result = output => Some(result),
        _ = tokio::signal::ctrl_c() => None,
    };
    if let Some(pump) = pump {
        pump.abort();
    }

    match finished {
        None => {
            // Strg-C: Channel schließen (beim Fallenlassen) und mit 130 enden.
            Ok(INTERRUPTED)
        }
        Some(Err(e)) if e.code == BROKEN_PIPE => Ok(BROKEN_PIPE),
        Some(Err(e)) => Err(e),
        Some(Ok(())) => {
            let status = events.exit_status();
            if global.verbose {
                eprintln!("Remote-Status: {status:?}");
            }
            if matches!(status, ExitStatus::Unknown) {
                eprintln!("simple-ssh-cli: Der Server hat keinen Exit-Status gemeldet");
            }
            Ok(exit_code(&status))
        }
    }
}

async fn write_flush<W: AsyncWriteExt + Unpin>(out: &mut W, data: &[u8]) -> std::io::Result<()> {
    out.write_all(data).await?;
    out.flush().await
}

fn local_write_error(e: std::io::Error) -> CliError {
    if e.kind() == ErrorKind::BrokenPipe {
        CliError::new(BROKEN_PIPE, "stdout geschlossen")
    } else {
        CliError::general(format!(
            "Schreiben auf die lokale Ausgabe fehlgeschlagen: {e}"
        ))
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
