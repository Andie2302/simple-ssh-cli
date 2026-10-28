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
use crate::exitcode::{BROKEN_PIPE, INTERRUPTED, LOST, exit_code};
use crate::target::Target;

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
