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
    /// SFTP: Einzelbefehl ausführen, ohne Unterbefehl interaktive Sitzung (`sftp>`)
    ///
    /// Übertragungen sind gepipelinet und laufen als Strom (kein Speicherbedarf nach Dateigröße),
    /// mit Fortschritt auf stderr. Verzeichnisse werden nicht rekursiv übertragen.
    Sftp {
        /// [benutzer@]host[:port]
        #[arg(value_name = "ZIEL")]
        target: Target,

        #[command(subcommand)]
        action: Option<SftpAction>,
    },
    /// Bibliothek systematisch gegen den Server prüfen (PASS/FAIL je Prüfung, optional als JSON)
    ///
    /// Prüft Verbindung, Host-Key-Pinning, exec, große Datenmengen, Parallelität, Shell, SFTP,
    /// Schlüsselwechsel und Keepalive. Schreibt nur in einen eigenen Ordner `.selftest-<id>`
    /// (Standard: im Home-Verzeichnis), der am Ende gelöscht wird. Exit-Code 1, wenn eine
    /// Prüfung fehlschlägt.
    Selftest {
        /// [benutzer@]host[:port]
        #[arg(value_name = "ZIEL")]
        target: Target,

        /// Datenmenge für die Übertragungsprüfungen (z.B. 512KiB, 20MiB, 1GiB)
        #[arg(long, value_name = "GRÖSSE", default_value = "20MiB", value_parser = parse_size)]
        size: u64,

        /// Ordner auf dem Server, in dem der Arbeitsordner angelegt wird [Standard: $HOME]
        #[arg(long, value_name = "PFAD")]
        workdir: Option<String>,

        /// Ergebnis als JSON auf stdout (Fortschrittszeilen gehen nach stderr)
        #[arg(long)]
        json: bool,

        /// Auch die Prüfung des Verbindungsabbruchs ausführen (beendet eine eigene Sitzung per kill -9)
        #[arg(long)]
        destructive: bool,
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

/// SFTP-Befehle (einzeln aufrufbar und in der interaktiven Sitzung).
#[derive(Debug, Clone, Subcommand)]
pub enum SftpAction {
    /// Verzeichnis oder Datei auflisten
    Ls {
        /// Ausführliches Format (Rechte, Besitzer, Größe, Zeit in UTC)
        #[arg(short = 'l')]
        long: bool,
        /// Auch Namen mit führendem Punkt zeigen
        #[arg(short = 'a')]
        all: bool,
        /// Pfad auf dem Server [Standard: aktuelles Verzeichnis]
        path: Option<String>,
    },
    /// Datei herunterladen (`-` als Ziel schreibt nach stdout)
    Get {
        remote: String,
        /// Lokales Ziel [Standard: Name der Datei im aktuellen Verzeichnis]
        local: Option<PathBuf>,
    },
    /// Datei hochladen (`-` als Quelle liest von stdin; dann ist das Ziel Pflicht)
    Put {
        local: PathBuf,
        /// Ziel auf dem Server [Standard: Name der Datei]
        remote: Option<String>,
    },
    /// Dateien löschen
    Rm {
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Verzeichnis anlegen
    Mkdir { path: String },
    /// Leeres Verzeichnis löschen
    Rmdir { path: String },
    /// Umbenennen oder verschieben (ein vorhandenes Ziel wird nicht überschrieben)
    Mv { from: String, to: String },
    /// Attribute anzeigen
    Stat { path: String },
    /// Modus setzen (oktal, z.B. 644)
    Chmod {
        #[arg(value_parser = parse_mode)]
        mode: u32,
        path: String,
    },
}

fn parse_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 8)
        .ok()
        .filter(|m| *m <= 0o7777)
        .ok_or_else(|| "erwartet wird ein oktaler Modus bis 7777, z.B. 644".to_string())
}

/// `20MiB`, `512k`, `1GiB`, `1048576` → Bytes (64 KiB bis 2 GiB).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let lower = s.trim().to_ascii_lowercase();
    let split = lower
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(lower.len());
    let (digits, unit) = lower.split_at(split);
    let number: u64 = digits
        .parse()
        .map_err(|_| format!("`{s}` ist keine Größe (Beispiel: 20MiB)"))?;
    let factor: u64 = match unit {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => {
            return Err(format!(
                "unbekannte Einheit `{unit}` (erlaubt: KiB, MiB, GiB)"
            ));
        }
    };
    let bytes = number
        .checked_mul(factor)
        .ok_or_else(|| "Größe zu groß".to_string())?;
    if !(64 * 1024..=2 * 1024 * 1024 * 1024).contains(&bytes) {
        return Err("erlaubt sind 64KiB bis 2GiB".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("20MiB"), Ok(20 * 1024 * 1024));
        assert_eq!(parse_size("512k"), Ok(512 * 1024));
        assert_eq!(parse_size("1GiB"), Ok(1024 * 1024 * 1024));
        assert_eq!(parse_size("65536"), Ok(65536));
        assert!(parse_size("1KiB").is_err());
        assert!(parse_size("3GiB").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("5TB").is_err());
    }
}
