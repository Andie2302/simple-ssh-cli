//! `shell`: interaktive Shell mit echtem Terminal.
//!
//! Reihenfolge: anmelden und Shell öffnen im normalen Terminalmodus, erst danach Raw-Mode. Ein-
//! und Ausgabe laufen in getrennten Tasks, damit große Einfügungen nicht mit der Ausgabe
//! verklemmen.

use std::io::{ErrorKind, IsTerminal};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use simple_ssh_lib::{ExitStatus, Pty, ShellReader, ShellWriter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::signal::unix::{SignalKind, signal};

use crate::cli::GlobalArgs;
use crate::connect;
use crate::error::CliError;
use crate::escape::{self, Escape, Event};
use crate::exitcode::{BROKEN_PIPE, LOST, exit_code};
use crate::term::{self, RawMode};

/// Wie die Sitzung endete.
enum End {
    /// Server hat die Shell beendet (Status), oder die Verbindung ging verloren.
    Output(Result<ExitStatus, String>),
    /// Lokales stdout wurde geschlossen.
    StdoutClosed,
    /// `~.`
    Disconnect,
    /// Signal von außen (Nummer).
    Signal(i32),
}

pub async fn run(
    global: &GlobalArgs,
    target: &crate::target::Target,
    escape_enabled: bool,
    escape_char: u8,
) -> Result<i32, CliError> {
    let connected = connect::connect(global, target).await?;
    let interactive = std::io::stdin().is_terminal();
    let (cols, rows) = term::terminal_size();
    let pty = Pty {
        term: term::term_name(),
        cols,
        rows,
    };
    let shell = connected
        .session
        .shell(pty)
        .await
        .map_err(|e| CliError::general(format!("Shell konnte nicht gestartet werden: {e}")))?;
    let (reader, writer, control) = shell.split();

    // Erst jetzt wird das Terminal verändert.
    let raw = if interactive {
        Some(RawMode::enable().map_err(|e| {
            CliError::general(format!("Raw-Mode konnte nicht aktiviert werden: {e}"))
        })?)
    } else {
        None
    };

    let mut sigwinch = signal(SignalKind::window_change())
        .map_err(|e| CliError::general(format!("Signalbehandlung fehlgeschlagen: {e}")))?;
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| CliError::general(format!("Signalbehandlung fehlgeschlagen: {e}")))?;
    let mut sighup = signal(SignalKind::hangup())
        .map_err(|e| CliError::general(format!("Signalbehandlung fehlgeschlagen: {e}")))?;

    let activity = Arc::new(AtomicU64::new(0));
    let mut output = tokio::spawn(pump_output(reader, Arc::clone(&activity)));
    let escape = Escape::new(escape_enabled && interactive, escape_char);
    let mut input = tokio::spawn(pump_input(
        writer,
        escape,
        escape_char,
        interactive,
        activity,
    ));
    let winch_control = control.clone();
    let winch = tokio::spawn(async move {
        while sigwinch.recv().await.is_some() {
            let (c, r) = term::terminal_size();
            if winch_control.resize(c, r).is_err() {
                break;
            }
        }
    });

    let end = tokio::select! {
        r = &mut output => match r {
            Ok(end) => end,
            Err(e) => End::Output(Err(format!("interner Fehler: {e}"))),
        },
        _ = &mut input => End::Disconnect,
        _ = sigterm.recv() => End::Signal(15),
        _ = sighup.recv() => End::Signal(1),
    };

    output.abort();
    input.abort();
    winch.abort();
    drop(control);
    // Terminal zurücksetzen, bevor Meldungen erscheinen.
    drop(raw);

    Ok(match end {
        End::Output(Ok(status)) => {
            if global.verbose {
                eprintln!("Remote-Status: {status:?}");
            }
            exit_code(&status)
        }
        End::Output(Err(msg)) => {
            eprintln!("simple-ssh-cli: Verbindung zum Server verloren: {msg}");
            LOST
        }
        End::StdoutClosed => BROKEN_PIPE,
        End::Disconnect => {
            eprintln!("simple-ssh-cli: Verbindung getrennt");
            LOST
        }
        End::Signal(n) => {
            eprintln!("simple-ssh-cli: Signal {n} empfangen, Verbindung getrennt");
            128 + n
        }
    })
}

/// Server → lokales stdout; am Ende der Ausgabe auf den Exit-Status warten.
async fn pump_output(mut reader: ShellReader, activity: Arc<AtomicU64>) -> End {
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                activity.fetch_add(1, Ordering::Relaxed);
                let written = async {
                    stdout.write_all(&buf[..n]).await?;
                    stdout.flush().await
                }
                .await;
                if let Err(e) = written {
                    return if e.kind() == ErrorKind::BrokenPipe {
                        End::StdoutClosed
                    } else {
                        End::Output(Err(format!(
                            "Schreiben auf die Ausgabe fehlgeschlagen: {e}"
                        )))
                    };
                }
            }
            Err(e) => return End::Output(Err(e.to_string())),
        }
    }
    End::Output(reader.wait_exit().await.map_err(|e| e.to_string()))
}

/// Lokales stdin → Server. Endet nur bei `~.`; sonst wartet der Task, bis er abgebrochen wird.
async fn pump_input(
    mut writer: ShellWriter,
    mut escape: Escape,
    escape_char: u8,
    interactive: bool,
    activity: Arc<AtomicU64>,
) {
    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; 4096];
    let mut out = Vec::with_capacity(4096);
    loop {
        match stdin.read(&mut buf).await {
            Ok(0) | Err(_) => {
                if !interactive {
                    send_eof_at_prompts(&mut writer, &activity).await;
                }
                std::future::pending::<()>().await;
            }
            Ok(n) => {
                out.clear();
                let events = escape.feed(&buf[..n], &mut out);
                if !out.is_empty() && writer.write_all(&out).await.is_err() {
                    std::future::pending::<()>().await;
                }
                for ev in events {
                    match ev {
                        Event::Disconnect => return,
                        Event::Help => {
                            let mut err = tokio::io::stderr();
                            let _ = err.write_all(escape::help(escape_char).as_bytes()).await;
                        }
                    }
                }
            }
        }
    }
}

/// Ende der Eingabe ohne Terminal: Strg-D senden, sobald die Shell ruhig ist (sie wartet dann am
/// Prompt; ein sofort gesendetes Strg-D könnte beim Start der Shell verloren gehen). Erneut
/// nur, wenn danach wieder Ausgabe kam (z. B. ein verschachtelter Prompt).
async fn send_eof_at_prompts(writer: &mut ShellWriter, activity: &AtomicU64) {
    const QUIET: Duration = Duration::from_millis(300);
    let mut sent_at = None;
    loop {
        let seen = activity.load(Ordering::Relaxed);
        tokio::time::sleep(QUIET).await;
        let now = activity.load(Ordering::Relaxed);
        if now != seen || sent_at == Some(now) {
            continue;
        }
        if writer.write_all(&[0x04]).await.is_err() || writer.flush().await.is_err() {
            return;
        }
        sent_at = Some(now);
    }
}
