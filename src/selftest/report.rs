//! Ausgabe der Ergebnisse: Text und JSON.

use std::time::Duration;

use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

pub struct CheckResult {
    pub name: &'static str,
    pub status: Status,
    pub duration: Duration,
    pub detail: String,
}

pub struct Info {
    pub target: String,
    pub user: String,
    pub banner: String,
    pub fingerprint: String,
    pub size: u64,
    pub cleaned: bool,
}

fn line(r: &CheckResult) -> String {
    format!(
        "{}  {:<14} {:>7} ms  {}",
        r.status.label(),
        r.name,
        r.duration.as_millis(),
        r.detail
    )
}

pub fn print_line(r: &CheckResult) {
    println!("{}", line(r));
}

pub fn print_line_stderr(r: &CheckResult) {
    eprintln!("{}", line(r));
}

fn counts(results: &[CheckResult]) -> (usize, usize, usize) {
    let n = |s| results.iter().filter(|r| r.status == s).count();
    (n(Status::Pass), n(Status::Fail), n(Status::Skip))
}

pub fn print_summary(results: &[CheckResult]) {
    let (pass, fail, skip) = counts(results);
    println!();
    println!("{pass} bestanden, {fail} fehlgeschlagen, {skip} übersprungen");
    println!(
        "Nicht von außen prüfbar: ein vom Server ausgelöster Schlüsselwechsel (hängt von dessen \
         RekeyLimit ab). Algorithmen sind fest: curve25519-sha256, ssh-ed25519, \
         chacha20-poly1305@openssh.com."
    );
}

pub fn json(info: &Info, results: &[CheckResult]) -> String {
    let (pass, fail, skip) = counts(results);
    let checks: Vec<_> = results
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "status": r.status.label(),
                "duration_ms": u64::try_from(r.duration.as_millis()).unwrap_or(u64::MAX),
                "detail": r.detail,
            })
        })
        .collect();
    let value = json!({
        "tool": "simple-ssh-cli",
        "version": env!("CARGO_PKG_VERSION"),
        "target": info.target,
        "user": info.user,
        "server_banner": info.banner,
        "host_key": info.fingerprint,
        "algorithms": {
            "kex": "curve25519-sha256",
            "host_key": "ssh-ed25519",
            "cipher": "chacha20-poly1305@openssh.com",
        },
        "data_size_bytes": info.size,
        "workdir_removed": info.cleaned,
        "summary": { "pass": pass, "fail": fail, "skip": skip },
        "checks": checks,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}
