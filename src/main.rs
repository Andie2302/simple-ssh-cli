//! simple-ssh-cli: Kommandozeilenprogramm auf Basis von simple-ssh-lib.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod cli;
mod commands;
mod connect;
mod error;
mod hostkeys;
mod identity;
mod target;

use clap::Parser;

use cli::{Cli, Command};
use error::{CliError, exit};

async fn run(cli: Cli) -> Result<(), CliError> {
    match &cli.command {
        Command::Hostkey { target } => commands::hostkey::run(&cli.global, target).await,
        Command::Check { target } => commands::check::run(&cli.global, target).await,
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
        Ok(()) => 0,
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
