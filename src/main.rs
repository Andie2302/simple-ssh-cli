//! simple-ssh-cli: Kommandozeilenprogramm auf Basis von simple-ssh-lib.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod cli;
mod commands;
mod connect;
mod error;
mod escape;
mod exitcode;
mod fmt;
mod hostkeys;
mod identity;
mod selftest;
mod sftp_ops;
mod signals;
mod target;
mod term;

use clap::Parser;

use cli::{Cli, Command};
use error::{CliError, exit};

/// Führt den Befehl aus und liefert den Exit-Code.
async fn run(cli: Cli) -> Result<i32, CliError> {
    match &cli.command {
        Command::Hostkey { target } => commands::hostkey::run(&cli.global, target)
            .await
            .map(|()| 0),
        Command::Check { target } => commands::check::run(&cli.global, target).await.map(|()| 0),
        Command::Exec {
            target,
            no_stdin,
            command,
        } => commands::exec::run(&cli.global, target, *no_stdin, command).await,
        Command::Sftp { target, action } => {
            commands::sftp::run(&cli.global, target, action.as_ref()).await
        }
        Command::Selftest {
            target,
            size,
            workdir,
            json,
            destructive,
        } => {
            let options = selftest::Options {
                size: *size,
                workdir: workdir.clone(),
                json: *json,
                destructive: *destructive,
            };
            selftest::run(&cli.global, target, &options).await
        }
        Command::Shell {
            target,
            no_escape,
            escape_char,
        } => commands::shell::run(&cli.global, target, !*no_escape, *escape_char).await,
    }
}

/// Liefert den Exit-Code.
async fn real_main() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // clap würde mit 2 beenden; das bedeutet bei uns „Host-Key unbekannt“.
            let code = if e.use_stderr() { exit::USAGE } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("simple-ssh-cli: {e}");
            e.code
        }
    }
}

#[tokio::main]
async fn main() {
    let code = real_main().await;
    std::process::exit(code);
}
