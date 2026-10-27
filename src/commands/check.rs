//! `check`: Verbindung und Anmeldung prüfen.

use std::time::Instant;

use crate::cli::GlobalArgs;
use crate::connect;
use crate::error::CliError;
use crate::target::Target;

pub async fn run(global: &GlobalArgs, target: &Target) -> Result<(), CliError> {
    let started = Instant::now();
    let connected = connect::connect(global, target).await?;
    println!(
        "OK  {}@{}  {}  {}",
        connected.user,
        target.display_addr(),
        connected.session.server_banner(),
        connected.session.host_key_fingerprint()
    );
    if global.verbose {
        eprintln!(
            "Verbindungsaufbau und Anmeldung dauerten {:.0?}",
            started.elapsed()
        );
    }
    Ok(())
}
