//! Die einzelnen Prüfungen des Selbsttests.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use simple_ssh_lib::sftp::OpenOptions;
use simple_ssh_lib::{Error, ExecEvent, ExitStatus, Pty, Session};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::testdata::{Verifier, write_stream};
use super::{Ctx, Outcome};
use crate::connect;
use crate::error::{CliError, exit};
use crate::fmt;

type BoxFut<'a> = Pin<Box<dyn Future<Output = Outcome> + Send + 'a>>;

pub struct Check {
    pub name: &'static str,
    pub run: for<'a> fn(&'a Ctx) -> BoxFut<'a>,
}

pub fn all() -> Vec<Check> {
    vec![
        Check {
            name: "connection",
            run: connection,
        },
        Check {
            name: "hostkey-pin",
            run: hostkey_pin,
        },
        Check {
            name: "exec",
            run: exec,
        },
        Check {
            name: "bulk-data",
            run: bulk_data,
        },
        Check {
            name: "concurrency",
            run: concurrency,
        },
        Check {
            name: "shell",
            run: shell,
        },
        Check {
            name: "sftp",
            run: sftp,
        },
        Check {
            name: "rekey",
            run: rekey,
        },
        Check {
            name: "keepalive",
            run: keepalive,
        },
        Check {
            name: "conn-loss",
            run: conn_loss,
        },
    ]
}

/// Einfache Anführungszeichen für die Shell des Servers.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn unique_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{:x}{:x}", nanos, std::process::id())
}

pub async fn prepare_workdir(session: &Session, custom: Option<&str>) -> Result<String, CliError> {
    let base = custom.map_or_else(|| "\"$HOME\"".to_string(), quote);
    let command = format!(
        "d={base}/.selftest-{}; mkdir -p \"$d\" && cd \"$d\" && pwd",
        unique_id()
    );
    let out = session
        .exec(&command)
        .await
        .map_err(|e| CliError::general(format!("Arbeitsordner anlegen: {e}")))?;
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.success() || !dir.starts_with('/') || !dir.contains("/.selftest-") {
        return Err(CliError::general(format!(
            "Arbeitsordner konnte nicht angelegt werden ({}): {}",
            custom.unwrap_or("$HOME"),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(dir)
}

pub async fn cleanup_workdir(session: &Session, dir: &str) -> Result<(), String> {
    // Sicherheitsnetz: gelöscht wird nur, was unser Präfix trägt.
    if !dir.starts_with('/') || !dir.contains("/.selftest-") {
        return Err(format!("unerwarteter Pfad {dir}"));
    }
    let out = session
        .exec(&format!("rm -rf -- {}", quote(dir)))
        .await
        .map_err(|e| e.to_string())?;
    if out.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn mib_per_s(bytes: u64, elapsed: Duration) -> String {
    fmt::rate(bytes, elapsed)
}

// ---------------------------------------------------------------- 1. Verbindung

fn connection(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        Outcome::pass(format!(
            "{} als {}; Banner {}; Host-Key {}; Aufbau + Anmeldung {} ms",
            ctx.target.display_addr(),
            ctx.user,
            ctx.session.server_banner(),
            ctx.session.host_key_fingerprint(),
            ctx.connect_time.as_millis()
        ))
    })
}

// ---------------------------------------------------------------- 2. Host-Key-Pinning

fn hostkey_pin(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        let mut global = ctx.global.clone();
        global.fingerprint = Some(format!("SHA256:{}", "A".repeat(43)));
        match connect::connect(&global, &ctx.target).await {
            Err(e) if e.code == exit::CHANGED_HOST => {
                Outcome::pass("falscher Fingerprint wurde abgelehnt")
            }
            Err(e) => Outcome::fail(format!("unerwarteter Fehler: {e}")),
            Ok(_) => Outcome::fail("Verbindung mit falschem Fingerprint wurde akzeptiert"),
        }
    })
}

// ---------------------------------------------------------------- 3. exec

fn exec(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        let s = &ctx.session;
        let mut failures = Vec::new();

        match s.exec("echo hello").await {
            Ok(o) if o.stdout == b"hello\n" && o.exit == ExitStatus::Code(0) => {}
            other => failures.push(format!("echo: {}", describe(&other))),
        }
        match s.exec("echo out; echo err >&2; exit 3").await {
            Ok(o)
                if o.stdout == b"out\n"
                    && o.stderr == b"err\n"
                    && o.exit == ExitStatus::Code(3) => {}
            other => failures.push(format!("stdout/stderr/Exit-Code 3: {}", describe(&other))),
        }
        match s.exec("kill -9 $$").await {
            Ok(o) if matches!(&o.exit, ExitStatus::Signal(n) if n.trim_start_matches("SIG") == "KILL") =>
                {}
            other => failures.push(format!("Signal-Ende: {}", describe(&other))),
        }
        match s.exec("simple_ssh_cli_no_such_command_xyz").await {
            Ok(o) if o.exit == ExitStatus::Code(127) => {}
            other => failures.push(format!("Befehl nicht gefunden (127): {}", describe(&other))),
        }
        match s.exec_with_input("cat", b"stdin-data").await {
            Ok(o) if o.stdout == b"stdin-data" && o.success() => {}
            other => failures.push(format!("stdin an cat: {}", describe(&other))),
        }
        match s.exec("true").await {
            Ok(o) if o.stdout.is_empty() && o.stderr.is_empty() && o.success() => {}
            other => failures.push(format!("leere Ausgabe: {}", describe(&other))),
        }
        Outcome::from_failures(
            failures,
            "6 Fälle: Ausgabe, stderr, Exit-Code, Signal, 127, stdin, leer".into(),
        )
    })
}

fn describe(r: &Result<simple_ssh_lib::ExecOutput, Error>) -> String {
    match r {
        Ok(o) => format!(
            "stdout={:?} stderr={:?} exit={:?}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
            o.exit
        ),
        Err(e) => format!("Fehler {e}"),
    }
}

// ---------------------------------------------------------------- 4. große Datenmengen

/// `cat` auf dem Server: sendet `size` Bytes und prüft, dass genau sie zurückkommen.
async fn cat_roundtrip(session: &Session, size: u64, seed: u64) -> Result<Duration, String> {
    let started = Instant::now();
    let stream = session
        .exec_stream("cat")
        .await
        .map_err(|e| format!("exec_stream: {e}"))?;
    let (mut stdin, mut events) = stream.split();
    let writer = tokio::spawn(async move {
        let result = write_stream(&mut stdin, seed, size).await;
        let _ = stdin.shutdown().await;
        result
    });
    let mut verifier = Verifier::new(seed);
    let mut stderr = Vec::new();
    loop {
        match events.next().await {
            Ok(Some(ExecEvent::Stdout(d))) => verifier.feed(&d),
            Ok(Some(ExecEvent::Stderr(d))) => stderr.extend_from_slice(&d),
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => return Err(format!("Verbindung: {e}")),
        }
    }
    match writer.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("Senden: {e}")),
        Err(e) => return Err(format!("Sende-Task: {e}")),
    }
    let exit = events.exit_status();
    if exit != ExitStatus::Code(0) {
        return Err(format!(
            "cat endete mit {exit:?}: {}",
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    if let Some(at) = verifier.mismatch_at {
        return Err(format!("Daten weichen ab Byte {at} ab"));
    }
    if verifier.received != size {
        return Err(format!(
            "{} statt {size} Bytes zurückerhalten",
            verifier.received
        ));
    }
    Ok(started.elapsed())
}

fn bulk_data(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        match cat_roundtrip(&ctx.session, ctx.size, 0xB01D).await {
            Ok(t) => Outcome::pass(format!(
                "{} hin und zurück in {:.1} s ({} je Richtung, Flow-Control in beide Richtungen)",
                fmt::size(ctx.size),
                t.as_secs_f64(),
                mib_per_s(ctx.size, t)
            )),
            Err(e) => Outcome::fail(e),
        }
    })
}

// ---------------------------------------------------------------- 5. Parallelität

fn concurrency(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        let started = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..8 {
            let session = std::sync::Arc::clone(&ctx.session);
            tasks.spawn(async move {
                let out = session.exec(&format!("sleep 1; echo n{i}")).await;
                (i, out)
            });
        }
        let mut failures = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((i, Ok(o))) if o.stdout == format!("n{i}\n").as_bytes() && o.success() => {}
                Ok((i, other)) => failures.push(format!("Befehl {i}: {}", describe(&other))),
                Err(e) => failures.push(format!("Task: {e}")),
            }
        }
        let elapsed = started.elapsed();
        if elapsed > Duration::from_secs(5) {
            failures.push(format!(
                "8 parallele Befehle brauchten {:.1} s (nacheinander wären es ≥ 8 s)",
                elapsed.as_secs_f64()
            ));
        }

        // Abgebrochener Aufruf lässt die Sitzung nutzbar.
        let cancelled =
            tokio::time::timeout(Duration::from_millis(300), ctx.session.exec("sleep 5")).await;
        if cancelled.is_ok() {
            failures.push("sleep 5 endete unerwartet früh".into());
        }
        match tokio::time::timeout(Duration::from_secs(10), ctx.session.exec("echo ok")).await {
            Ok(Ok(o)) if o.stdout == b"ok\n" => {}
            other => failures.push(format!(
                "Sitzung nach Abbruch nicht nutzbar: {}",
                match other {
                    Ok(r) => describe(&r),
                    Err(_) => "Zeitüberschreitung".to_string(),
                }
            )),
        }
        Outcome::from_failures(
            failures,
            format!(
                "8 Befehle à 1 s in {:.1} s; Abbruch per Frist folgenlos",
                elapsed.as_secs_f64()
            ),
        )
    })
}

// ---------------------------------------------------------------- 6. Shell

async fn read_until(
    reader: &mut simple_ssh_lib::ShellReader,
    seen: &mut String,
    needle: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut buf = [0u8; 4096];
    while !seen.contains(needle) {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, reader.read(&mut buf)).await {
            Ok(Ok(0)) => return Err(format!("Shell endete, bevor `{needle}` erschien")),
            Ok(Ok(n)) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            Ok(Err(e)) => return Err(format!("Lesefehler: {e}")),
            Err(_) => return Err(format!("`{needle}` erschien nicht innerhalb von 15 s")),
        }
    }
    Ok(())
}

fn shell(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        let shell = match ctx.session.shell(Pty::new(80, 24)).await {
            Ok(s) => s,
            Err(e) => return Outcome::fail(format!("Shell konnte nicht gestartet werden: {e}")),
        };
        let (mut reader, mut writer, control) = shell.split();
        let mut seen = String::new();

        if writer.write_all(b"echo r$((6*7))x\n").await.is_err() {
            return Outcome::fail("Schreiben in die Shell fehlgeschlagen");
        }
        if let Err(e) = read_until(&mut reader, &mut seen, "r42x").await {
            return Outcome::fail(format!(
                "Rechnung: {e} (POSIX-Shell auf dem Server vorausgesetzt)"
            ));
        }
        if let Err(e) = control.resize(120, 40) {
            return Outcome::fail(format!("Größenänderung: {e}"));
        }
        if writer.write_all(b"stty size\n").await.is_err() {
            return Outcome::fail("Schreiben in die Shell fehlgeschlagen");
        }
        if let Err(e) = read_until(&mut reader, &mut seen, "40 120").await {
            return Outcome::fail(format!("Größe 40x120 kam nicht an: {e}"));
        }
        if writer.write_all(b"exit 5\n").await.is_err() {
            return Outcome::fail("Schreiben in die Shell fehlgeschlagen");
        }
        match tokio::time::timeout(Duration::from_secs(15), reader.wait_exit()).await {
            Ok(Ok(ExitStatus::Code(5))) => {
                Outcome::pass("PTY, Rechnung (42), Größenänderung (40x120), exit 5 → Status 5")
            }
            Ok(Ok(other)) => Outcome::fail(format!("Exit-Status {other:?} statt Code(5)")),
            Ok(Err(e)) => Outcome::fail(format!("Ende der Shell: {e}")),
            Err(_) => Outcome::fail("Shell beendete sich nicht nach `exit 5`"),
        }
    })
}

// ---------------------------------------------------------------- 7. SFTP

fn sftp(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        let sftp = match ctx.session.sftp().await {
            Ok(s) => s,
            Err(Error::SftpUnavailable(msg)) => {
                return Outcome::skip(format!("Server bietet kein SFTP an: {msg}"));
            }
            Err(e) => return Outcome::fail(format!("SFTP konnte nicht gestartet werden: {e}")),
        };
        let dir = format!("{}/sftp", ctx.workdir);
        let mut failures = Vec::new();
        let mut detail = String::new();

        if let Err(e) = sftp.create_dir(&dir, None).await {
            return Outcome::fail(format!("Verzeichnis anlegen: {e}"));
        }

        // Große Datei: Schreiben und Lesen als Strom, mit Prüfung jedes Bytes.
        let path = format!("{dir}/big.bin");
        let up = {
            let started = Instant::now();
            let (mut tx, mut rx) = tokio::io::duplex(256 * 1024);
            let size = ctx.size;
            let producer = tokio::spawn(async move {
                let r = write_stream(&mut tx, 0x5F7B, size).await;
                drop(tx);
                r
            });
            let result = async {
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&sftp, &path)
                    .await?;
                let n = file.copy_from(0, &mut rx, |_| {}).await?;
                file.close().await?;
                Ok::<u64, Error>(n)
            }
            .await;
            drop(rx);
            let _ = producer.await;
            result.map(|n| (n, started.elapsed()))
        };
        match up {
            Ok((n, t)) if n == ctx.size => {
                detail.push_str(&format!("Schreiben {} ", mib_per_s(n, t)));
            }
            Ok((n, _)) => failures.push(format!("Schreiben: {n} statt {} Bytes", ctx.size)),
            Err(e) => failures.push(format!("Schreiben: {e}")),
        }
        match sftp.metadata(&path).await {
            Ok(m) if m.size == Some(ctx.size) => {}
            Ok(m) => failures.push(format!("Größe auf dem Server {:?}", m.size)),
            Err(e) => failures.push(format!("metadata: {e}")),
        }
        {
            let started = Instant::now();
            let mut verifier = Verifier::new(0x5F7B);
            let result = async {
                let file = sftp.open(&path).await?;
                file.copy_to(0, &mut verifier, |_| {}).await
            }
            .await;
            match result {
                Ok(n) if n == ctx.size && verifier.mismatch_at.is_none() => {
                    detail.push_str(&format!("Lesen {} ", mib_per_s(n, started.elapsed())));
                }
                Ok(n) => failures.push(format!(
                    "Lesen: {n} Bytes, Abweichung bei {:?}",
                    verifier.mismatch_at
                )),
                Err(e) => failures.push(format!("Lesen: {e}")),
            }
        }

        // Attribute.
        match sftp.set_permissions(&path, 0o640).await {
            Ok(()) => match sftp.metadata(&path).await {
                Ok(m) if m.permissions.map(|p| p & 0o777) == Some(0o640) => {}
                Ok(m) => failures.push(format!("chmod 640 ergab {:?}", m.permissions)),
                Err(e) => failures.push(format!("metadata nach chmod: {e}")),
            },
            Err(e) => failures.push(format!("chmod: {e}")),
        }

        // Auflisten: 200 Dateien (mehrere READDIR-Runden).
        let many = format!("{dir}/many");
        match sftp.create_dir(&many, None).await {
            Ok(()) => {
                let mut tasks = tokio::task::JoinSet::new();
                for i in 0..200 {
                    let sftp = sftp.clone();
                    let p = format!("{many}/f{i:03}");
                    tasks.spawn(async move { sftp.write(&p, b"x").await });
                }
                while let Some(r) = tasks.join_next().await {
                    if let Ok(Err(e)) | Err(e) = r.map_err(|e| Error::ConnectionLost(e.to_string()))
                    {
                        failures.push(format!("Datei anlegen: {e}"));
                        break;
                    }
                }
                match sftp.read_dir(&many).await {
                    Ok(entries) => {
                        let count = entries.iter().filter(|e| e.name.starts_with('f')).count();
                        if count != 200 {
                            failures.push(format!("read_dir lieferte {count} statt 200 Einträge"));
                        }
                    }
                    Err(e) => failures.push(format!("read_dir: {e}")),
                }
            }
            Err(e) => failures.push(format!("Verzeichnis anlegen: {e}")),
        }

        // Umbenennen und Fehlerfälle.
        let renamed = format!("{dir}/renamed.bin");
        match sftp.rename(&path, &renamed).await {
            Ok(()) => {
                if !sftp.metadata(&path).await.is_err_and(|e| e.is_not_found()) {
                    failures.push("alter Name existiert nach rename noch".into());
                }
                if sftp.metadata(&renamed).await.is_err() {
                    failures.push("neuer Name fehlt nach rename".into());
                }
            }
            Err(e) => failures.push(format!("rename: {e}")),
        }
        if !sftp
            .metadata(&format!("{dir}/gibt-es-nicht"))
            .await
            .is_err_and(|e| e.is_not_found())
        {
            failures.push("fehlende Datei ergab keinen NoSuchFile".into());
        }
        if sftp.remove_dir(&many).await.is_ok() {
            failures.push("nicht leeres Verzeichnis ließ sich löschen".into());
        }

        // Acht parallele Operationen auf einer Verbindung.
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..8u8 {
            let sftp = sftp.clone();
            let p = format!("{dir}/par{i}");
            tasks.spawn(async move {
                let data = vec![i; 100_000];
                sftp.write(&p, &data).await?;
                let back = sftp.read(&p).await?;
                Ok::<bool, Error>(back == data)
            });
        }
        while let Some(r) = tasks.join_next().await {
            match r {
                Ok(Ok(true)) => {}
                Ok(Ok(false)) => failures.push("parallele Operation lieferte falsche Daten".into()),
                Ok(Err(e)) => failures.push(format!("parallele Operation: {e}")),
                Err(e) => failures.push(format!("Task: {e}")),
            }
        }

        Outcome::from_failures(
            failures,
            format!(
                "{}{}; 200 Einträge, chmod, rename, Fehlerfälle, 8 parallel",
                fmt::size(ctx.size),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {}", detail.trim_end())
                }
            ),
        )
    })
}

// ---------------------------------------------------------------- 8. Schlüsselwechsel

fn rekey(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        let connected = match connect::connect_with(&ctx.global, &ctx.target, |c| {
            c.rekey_after_bytes(256 * 1024)
        })
        .await
        {
            Ok(c) => c,
            Err(e) => return Outcome::fail(format!("zweite Verbindung: {e}")),
        };
        let size = 8 * 1024 * 1024;
        match cat_roundtrip(&connected.session, size, 0x4E4B).await {
            Ok(t) => {
                let n = connected.session.rekey_count();
                if n >= 5 {
                    Outcome::pass(format!(
                        "{n} Schlüsselwechsel bei {} Datenverkehr (Schwelle 256 KiB), Daten intakt in {:.1} s",
                        fmt::size(size * 2),
                        t.as_secs_f64()
                    ))
                } else {
                    Outcome::fail(format!("nur {n} Schlüsselwechsel (erwartet ≥ 5)"))
                }
            }
            Err(e) => Outcome::fail(format!(
                "Übertragung mit Schlüsselwechseln: {e} (Wechsel bisher: {})",
                connected.session.rekey_count()
            )),
        }
    })
}

// ---------------------------------------------------------------- 9. Keepalive

fn keepalive(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        let connected = match connect::connect_with(&ctx.global, &ctx.target, |c| {
            c.keepalive(Duration::from_secs(1), 3)
        })
        .await
        {
            Ok(c) => c,
            Err(e) => return Outcome::fail(format!("zweite Verbindung: {e}")),
        };
        tokio::time::sleep(Duration::from_secs(3)).await;
        match connected.session.exec("echo alive").await {
            Ok(o) if o.stdout == b"alive\n" => {
                Outcome::pass("3 s Leerlauf mit Keepalive (1 s × 3): Verbindung blieb gesund")
            }
            other => Outcome::fail(format!("nach dem Leerlauf: {}", describe(&other))),
        }
    })
}

// ---------------------------------------------------------------- 10. Verbindungsabbruch

fn conn_loss(ctx: &Ctx) -> BoxFut<'_> {
    Box::pin(async move {
        if !ctx.destructive {
            return Outcome::skip(
                "nur mit --destructive (beendet eine eigene SSH-Sitzung per kill -9)",
            );
        }
        let connected = match connect::connect(&ctx.global, &ctx.target).await {
            Ok(c) => c,
            Err(e) => return Outcome::fail(format!("zweite Verbindung: {e}")),
        };
        let first = tokio::time::timeout(
            Duration::from_secs(20),
            connected.session.exec("kill -9 $PPID"),
        )
        .await;
        if first.is_err() {
            return Outcome::fail("exec hing nach dem Abbruch der Verbindung");
        }
        match tokio::time::timeout(Duration::from_secs(10), connected.session.exec("echo x")).await
        {
            Ok(Err(e)) => Outcome::pass(format!("Abbruch wurde gemeldet statt zu hängen ({e})")),
            Ok(Ok(_)) => Outcome::fail("Befehl lief nach dem Abbruch scheinbar erfolgreich"),
            Err(_) => Outcome::fail("Folgebefehl hing nach dem Abbruch"),
        }
    })
}
