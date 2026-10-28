//! Kommandozeilen-Definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::target::Target;

/// SSH-Client auf Basis von simple-ssh-lib (nur ed25519, Public-Key-Anmeldung).
#[derive(Debug, Parser)]
#[command(
    name = "simple-ssh-cli",
    version,
    about = "SSH-Client auf Basis von simple-ssh-lib (nur ed25519, nur Public-Key-Anmeldung)",
    max_term_width = 100
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Optionen, die für alle Befehle gelten (auch hinter dem Befehl angebbar).
#[derive(Debug, Clone, Args)]
pub struct GlobalArgs {
    /// Privater Schlüssel (ed25519, OpenSSH-Format) [Standard: ~/.ssh/id_ed25519]
    #[arg(short = 'i', long, global = true, value_name = "DATEI")]
    pub identity: Option<PathBuf>,

    /// Datei mit der Passphrase des Schlüssels (erste Zeile). Alternativ SSH_KEY_PASSPHRASE
    /// oder Rückfrage im Terminal
    #[arg(long, global = true, value_name = "DATEI")]
    pub passphrase_file: Option<PathBuf>,

    /// known_hosts-Datei dieses Programms [Standard: ~/.config/simple-ssh-cli/known_hosts]
    #[arg(long, global = true, value_name = "DATEI")]
    pub known_hosts: Option<PathBuf>,

    /// Unbekannte Server nach erfolgreicher Anmeldung in known_hosts speichern
    /// (ein geänderter Key wird nie akzeptiert)
    #[arg(long, global = true)]
    pub accept_new: bool,

    /// Erwarteter Fingerprint des Servers; hat Vorrang vor known_hosts, die Datei bleibt unberührt
    #[arg(long, global = true, value_name = "SHA256:...")]
    pub fingerprint: Option<String>,

    /// Frist in Sekunden für Verbindungsaufbau, Handshake und Anmeldung
    #[arg(
        long,
        global = true,
        value_name = "SEKUNDEN",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=3600)
    )]
    pub timeout: u64,

    /// Alle SEKUNDEN eine Lebenszeichen-Anfrage senden; kommt 3 Intervalle lang nichts an, gilt
    /// die Verbindung als tot
    #[arg(
        long,
        global = true,
        value_name = "SEKUNDEN",
        value_parser = clap::value_parser!(u64).range(1..=3600)
    )]
    pub keepalive: Option<u64>,

    /// Ausführlichere Ausgabe auf stderr
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Fingerprint des Servers anzeigen (wie `ssh-keygen -lf`), ohne ihm zu vertrauen
    Hostkey {
        /// [benutzer@]host[:port]
        #[arg(value_name = "ZIEL")]
        target: Target,
    },
    /// Befehl auf dem Server ausführen; Ausgabe und Eingabe laufen live
    ///
    /// Die Wörter des Befehls werden wie bei ssh mit Leerzeichen verbunden und vom Shell des
    /// Servers ausgewertet. Optionen müssen vor dem Befehl stehen. Der Exit-Code ist der des
    /// Remote-Befehls (bei Signal 128+Nummer, 255 bei verlorener Verbindung).
    Exec {
        /// [benutzer@]host[:port]
        #[arg(value_name = "ZIEL")]
        target: Target,

        /// stdin nicht weitergeben: Der Befehl sieht sofort EOF
        #[arg(long)]
        no_stdin: bool,

        /// Befehl und Argumente
        #[arg(
            value_name = "BEFEHL",
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        command: Vec<String>,
    },
    /// Interaktive Shell mit echtem Terminal
    ///
    /// Am Zeilenanfang gilt das Escape-Zeichen (Standard `~`): `~.` trennt die Verbindung,
    /// `~~` sendet ein `~`, `~?` zeigt eine Hilfe. Der Exit-Code ist der der Remote-Shell
    /// (bei Signal 128+Nummer, 255 bei getrennter oder verlorener Verbindung).
    Shell {
        /// [benutzer@]host[:port]
        #[arg(value_name = "ZIEL")]
        target: Target,

        /// Escape-Zeichen abschalten
        #[arg(long)]
        no_escape: bool,

        /// Anderes Escape-Zeichen (ein ASCII-Satzzeichen)
        #[arg(long, value_name = "ZEICHEN", default_value = "~", value_parser = parse_escape_char)]
        escape_char: u8,
    },
    /// Verbindung und Anmeldung prüfen
    Check {
        /// [benutzer@]host[:port]
        #[arg(value_name = "ZIEL")]
        target: Target,
    },
}

fn parse_escape_char(s: &str) -> Result<u8, String> {
    let mut chars = s.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii_punctuation() => Ok(c as u8),
        _ => Err("erwartet wird genau ein ASCII-Satzzeichen".to_string()),
    }
}
