//! SFTP-Operationen, gemeinsam für die Einzelbefehle und die interaktive Sitzung.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use simple_ssh_lib::sftp::{Metadata, OpenOptions};
use simple_ssh_lib::{Error, Sftp};
use tokio::io::AsyncWriteExt;

use crate::error::CliError;
use crate::exitcode::LOST;
use crate::fmt::{self, Progress};

/// Verbindung samt aktuellem Verzeichnis auf dem Server.
pub struct Remote {
    pub sftp: Sftp,
    pub cwd: String,
}

pub fn sftp_error(what: &str, e: &Error) -> CliError {
    let code = if matches!(e, Error::ConnectionLost(_)) {
        LOST
    } else {
        1
    };
    let text = match e {
        Error::Sftp { message, status } if !message.is_empty() => {
            format!("{status:?} ({message})")
        }
        other => other.to_string(),
    };
    CliError::new(code, format!("{what}: {text}"))
}

fn io_error(what: &str, e: &std::io::Error) -> CliError {
    CliError::general(format!("{what}: {e}"))
}

fn basename(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path)
}

impl Remote {
    pub async fn new(sftp: Sftp) -> Result<Self, CliError> {
        let cwd = sftp
            .canonicalize(".")
            .await
            .map_err(|e| sftp_error("Arbeitsverzeichnis des Servers", &e))?;
        Ok(Self { sftp, cwd })
    }

    /// Macht einen Pfad absolut (relativ zum aktuellen Verzeichnis).
    pub fn resolve(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_string()
        } else if path == "." || path.is_empty() {
            self.cwd.clone()
        } else {
            format!("{}/{path}", self.cwd.trim_end_matches('/'))
        }
    }

    pub async fn cd(&mut self, path: &str) -> Result<(), CliError> {
        let target = self
            .sftp
            .canonicalize(&self.resolve(path))
            .await
            .map_err(|e| sftp_error(path, &e))?;
        let meta = self
            .sftp
            .metadata(&target)
            .await
            .map_err(|e| sftp_error(path, &e))?;
        if !meta.is_dir() {
            return Err(CliError::general(format!("{path}: kein Verzeichnis")));
        }
        self.cwd = target;
        Ok(())
    }

    pub async fn ls(&self, path: Option<&str>, long: bool, all: bool) -> Result<(), CliError> {
        let path = path.unwrap_or(".");
        let abs = self.resolve(path);
        let meta = self
            .sftp
            .metadata(&abs)
            .await
            .map_err(|e| sftp_error(path, &e))?;
        let mut entries = if meta.is_dir() {
            self.sftp
                .read_dir(&abs)
                .await
                .map_err(|e| sftp_error(path, &e))?
                .into_iter()
                .map(|e| (e.name, e.metadata))
                .collect::<Vec<_>>()
        } else {
            vec![(path.to_string(), meta)]
        };
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, m) in entries {
            if !all && name.starts_with('.') {
                continue;
            }
            if long {
                println!(
                    "{} {:>5} {:>5} {:>10} {} {name}",
                    m.permissions.map_or("??????????".into(), fmt::mode_string),
                    m.uid.map_or("?".into(), |u| u.to_string()),
                    m.gid.map_or("?".into(), |g| g.to_string()),
                    m.size.map_or("?".into(), |s| s.to_string()),
                    m.mtime.map_or("????-??-?? ??:??".into(), fmt::time),
                );
            } else {
                println!("{name}");
            }
        }
        Ok(())
    }

    pub async fn stat(&self, path: &str) -> Result<(), CliError> {
        let m = self
            .sftp
            .metadata(&self.resolve(path))
            .await
            .map_err(|e| sftp_error(path, &e))?;
        print_stat(path, &m);
        Ok(())
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), CliError> {
        self.sftp
            .create_dir(&self.resolve(path), None)
            .await
            .map_err(|e| sftp_error(path, &e))
    }

    pub async fn rmdir(&self, path: &str) -> Result<(), CliError> {
        self.sftp
            .remove_dir(&self.resolve(path))
            .await
            .map_err(|e| sftp_error(path, &e))
    }

    pub async fn rm(&self, path: &str) -> Result<(), CliError> {
        self.sftp
            .remove_file(&self.resolve(path))
            .await
            .map_err(|e| sftp_error(path, &e))
    }

    pub async fn mv(&self, from: &str, to: &str) -> Result<(), CliError> {
        let mut dest = self.resolve(to);
        // Ist das Ziel ein vorhandenes Verzeichnis, wird hineinverschoben.
        if self.sftp.metadata(&dest).await.is_ok_and(|m| m.is_dir()) {
            dest = format!("{}/{}", dest.trim_end_matches('/'), basename(from));
        }
        self.sftp
            .rename(&self.resolve(from), &dest)
            .await
            .map_err(|e| sftp_error(&format!("{from} -> {to}"), &e))
    }

    pub async fn chmod(&self, mode: u32, path: &str) -> Result<(), CliError> {
        self.sftp
            .set_permissions(&self.resolve(path), mode)
            .await
            .map_err(|e| sftp_error(path, &e))
    }

    /// Lädt eine Datei herunter; `local` = `-` schreibt nach stdout.
    pub async fn get(&self, remote: &str, local: Option<&Path>) -> Result<(), CliError> {
        let abs = self.resolve(remote);
        let file = self
            .sftp
            .open(&abs)
            .await
            .map_err(|e| sftp_error(remote, &e))?;
        let meta = file.metadata().await.ok();
        if meta.as_ref().is_some_and(Metadata::is_dir) {
            return Err(CliError::general(format!(
                "{remote}: ist ein Verzeichnis (rekursive Übertragung wird nicht unterstützt)"
            )));
        }
        let total = meta.and_then(|m| m.size);
        let mut progress = Progress::new(basename(remote).to_string(), total);

        if local == Some(Path::new("-")) {
            let mut out = tokio::io::stdout();
            let result = file
                .copy_to(0, &mut out, |n| progress.update(n))
                .await
                .map_err(|e| sftp_error(remote, &e));
            return match result {
                Ok(n) => {
                    progress.finish(n);
                    Ok(())
                }
                Err(e) => {
                    progress.abort();
                    Err(e)
                }
            };
        }

        let mut dest: PathBuf =
            local.map_or_else(|| PathBuf::from(basename(remote)), PathBuf::from);
        if dest.is_dir() {
            dest.push(basename(remote));
        }
        let mut part = dest.clone().into_os_string();
        part.push(".part");
        let part = PathBuf::from(part);
        let mut out = tokio::fs::File::create(&part)
            .await
            .map_err(|e| io_error(&part.display().to_string(), &e))?;
        let result = file
            .copy_to(0, &mut out, |n| progress.update(n))
            .await
            .map_err(|e| sftp_error(remote, &e));
        let flushed = out.flush().await;
        drop(out);
        match result {
            Ok(n) => {
                flushed.map_err(|e| io_error(&part.display().to_string(), &e))?;
                tokio::fs::rename(&part, &dest)
                    .await
                    .map_err(|e| io_error(&dest.display().to_string(), &e))?;
                progress.finish(n);
                Ok(())
            }
            Err(e) => {
                progress.abort();
                let _ = tokio::fs::remove_file(&part).await;
                Err(e)
            }
        }
    }

    /// Lädt eine Datei hoch; `local` = `-` liest von stdin.
    pub async fn put(&self, local: &Path, remote: Option<&str>) -> Result<(), CliError> {
        let from_stdin = local == Path::new("-");
        let name = local.file_name().and_then(|n| n.to_str());
        let remote_name = match (remote, name) {
            (Some(r), _) => r.to_string(),
            (None, Some(n)) if !from_stdin => n.to_string(),
            _ => {
                return Err(CliError::usage(
                    "Beim Lesen von stdin muss das Ziel auf dem Server angegeben werden",
                ));
            }
        };
        let mut dest = self.resolve(&remote_name);
        if let Ok(m) = self.sftp.metadata(&dest).await
            && m.is_dir()
        {
            let base = name
                .filter(|_| !from_stdin)
                .ok_or_else(|| CliError::usage("Das Ziel ist ein Verzeichnis"))?;
            dest = format!("{}/{base}", dest.trim_end_matches('/'));
        }

        let (mut reader, total, mode): (Box<dyn tokio::io::AsyncRead + Unpin + Send>, _, _) =
            if from_stdin {
                (Box::new(tokio::io::stdin()), None, None)
            } else {
                let file = tokio::fs::File::open(local)
                    .await
                    .map_err(|e| io_error(&local.display().to_string(), &e))?;
                let meta = file
                    .metadata()
                    .await
                    .map_err(|e| io_error(&local.display().to_string(), &e))?;
                if meta.is_dir() {
                    return Err(CliError::general(format!(
                        "{}: ist ein Verzeichnis (rekursive Übertragung wird nicht unterstützt)",
                        local.display()
                    )));
                }
                (
                    Box::new(file),
                    Some(meta.len()),
                    Some(meta.permissions().mode() & 0o777),
                )
            };

        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        if let Some(mode) = mode {
            options.mode(mode);
        }
        let file = options
            .open(&self.sftp, &dest)
            .await
            .map_err(|e| sftp_error(&remote_name, &e))?;
        let mut progress = Progress::new(basename(&dest).to_string(), total);
        let result = file.copy_from(0, &mut reader, |n| progress.update(n)).await;
        let closed = file.close().await;
        match (result, closed) {
            (Ok(n), Ok(())) => {
                progress.finish(n);
                Ok(())
            }
            (Err(e), _) | (Ok(_), Err(e)) => {
                progress.abort();
                Err(sftp_error(&remote_name, &e))
            }
        }
    }
}

fn print_stat(path: &str, m: &Metadata) {
    println!("Datei:   {path}");
    println!(
        "Typ:     {}",
        if m.is_dir() {
            "Verzeichnis"
        } else if m.is_symlink() {
            "Symlink"
        } else if m.is_file() {
            "Datei"
        } else {
            "unbekannt"
        }
    );
    if let Some(s) = m.size {
        println!("Größe:   {s} ({})", fmt::size(s));
    }
    if let Some(p) = m.permissions {
        println!("Modus:   {:04o} ({})", p & 0o7777, fmt::mode_string(p));
    }
    if let (Some(u), Some(g)) = (m.uid, m.gid) {
        println!("Besitz:  uid {u}, gid {g}");
    }
    if let Some(t) = m.atime {
        println!("Zugriff: {} UTC", fmt::time(t));
    }
    if let Some(t) = m.mtime {
        println!("Änderung: {} UTC", fmt::time(t));
    }
}
