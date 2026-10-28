//! `selftest`: systematische Prüfung der Bibliothek gegen einen echten Server.

mod checks;
mod report;
mod testdata;

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cli::GlobalArgs;
use crate::connect;
use crate::error::CliError;
use crate::target::Target;

pub use report::Status;

/// Ergebnis einer einzelnen Prüfung.
pub struct Outcome {
    pub status: Status,
    pub detail: String,
}

impl Outcome {
    pub fn pass(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            detail: detail.into(),
        }
    }

    pub fn fail(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            detail: detail.into(),
        }
    }

    pub fn skip(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Skip,
            detail: detail.into(),
        }
    }

    /// Pass, wenn keine Teilprüfung fehlschlug, sonst Fail mit allen Meldungen.
    pub fn from_failures(failures: Vec<String>, ok_detail: String) -> Self {
        if failures.is_empty() {
            Self::pass(ok_detail)
        } else {
            Self::fail(failures.join("; "))
        }
    }
}

pub struct Options {
    pub size: u64,
    pub workdir: Option<String>,
    pub json: bool,
    pub destructive: bool,
}

/// Gemeinsamer Zustand der Prüfungen.
pub struct Ctx {
    pub global: GlobalArgs,
    pub target: Target,
    pub session: Arc<simple_ssh_lib::Session>,
    pub user: String,
    pub connect_time: Duration,
    pub size: u64,
    /// Absoluter Arbeitsordner auf dem Server (wird am Ende gelöscht).
    pub workdir: String,
    pub destructive: bool,
}

pub async fn run(global: &GlobalArgs, target: &Target, options: &Options) -> Result<i32, CliError> {
    let started = Instant::now();
    let connected = connect::connect(global, target).await?;
    let connect_time = started.elapsed();
    let session = Arc::new(connected.session);
    let workdir = checks::prepare_workdir(&session, options.workdir.as_deref()).await?;

    let ctx = Ctx {
        global: global.clone(),
        target: target.clone(),
        session: Arc::clone(&session),
        user: connected.user,
        connect_time,
        size: options.size,
        workdir,
        destructive: options.destructive,
    };

    let mut results = Vec::new();
    for check in checks::all() {
        let began = Instant::now();
        let limit = Duration::from_secs(60) + Duration::from_secs(ctx.size / (256 * 1024));
        let outcome = match tokio::time::timeout(limit, (check.run)(&ctx)).await {
            Ok(o) => o,
            Err(_) => Outcome::fail(format!("keine Antwort innerhalb von {} s", limit.as_secs())),
        };
        let result = report::CheckResult {
            name: check.name,
            status: outcome.status,
            duration: began.elapsed(),
            detail: outcome.detail,
        };
        if !options.json {
            report::print_line(&result);
        } else {
            report::print_line_stderr(&result);
        }
        results.push(result);
    }

    let cleaned = checks::cleanup_workdir(&session, &ctx.workdir).await;
    if let Err(e) = &cleaned {
        eprintln!(
            "Warnung: Arbeitsordner {} konnte nicht gelöscht werden: {e}",
            ctx.workdir
        );
    }

    let info = report::Info {
        target: target.display_addr(),
        user: ctx.user.clone(),
        banner: session.server_banner().to_string(),
        fingerprint: session.host_key_fingerprint().to_string(),
        size: options.size,
        cleaned: cleaned.is_ok(),
    };
    if options.json {
        println!("{}", report::json(&info, &results));
    } else {
        report::print_summary(&results);
    }
    let failed = results.iter().any(|r| r.status == Status::Fail);
    Ok(i32::from(failed))
}
