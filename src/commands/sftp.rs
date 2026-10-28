//! `sftp`: Einzelbefehle und interaktive Sitzung.

use std::io::IsTerminal;

use clap::Parser;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use simple_ssh_lib::Error;

use crate::cli::{GlobalArgs, SftpAction};
use crate::connect;
use crate::error::CliError;
use crate::exitcode::INTERRUPTED;
use crate::sftp_ops::Remote;
use crate::target::Target;

pub async fn run(
    global: &GlobalArgs,
    target: &Target,
    action: Option<&SftpAction>,
) -> Result<i32, CliError> {
    let connected = connect::connect(global, target).await?;
    let sftp = connected.session.sftp().await.map_err(|e| match e {
        Error::SftpUnavailable(msg) => CliError::general(format!(
            "Der Server bietet kein SFTP an ({msg}). Ein Ersatz (z.B. SCP) wird nicht versucht"
        )),
        other => crate::sftp_ops::sftp_error("SFTP konnte nicht gestartet werden", &other),
    })?;
    let mut remote = Remote::new(sftp).await?;

    match action {
        Some(action) => {
            tokio::select! {
                r = execute(&mut remote, action) => r.map(|()| 0),
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("simple-ssh-cli: abgebrochen");
                    Ok(INTERRUPTED)
                }
            }
        }
        None => interactive(remote).await,
    }
}

/// Führt einen Befehl aus.
pub async fn execute(remote: &mut Remote, action: &SftpAction) -> Result<(), CliError> {
    match action {
        SftpAction::Ls { long, all, path } => remote.ls(path.as_deref(), *long, *all).await,
        SftpAction::Get {
            remote: path,
            local,
        } => remote.get(path, local.as_deref()).await,
        SftpAction::Put {
            local,
            remote: dest,
        } => remote.put(local, dest.as_deref()).await,
        SftpAction::Rm { paths } => {
            for p in paths {
                remote.rm(p).await?;
            }
            Ok(())
        }
        SftpAction::Mkdir { path } => remote.mkdir(path).await,
        SftpAction::Rmdir { path } => remote.rmdir(path).await,
        SftpAction::Mv { from, to } => remote.mv(from, to).await,
        SftpAction::Stat { path } => remote.stat(path).await,
        SftpAction::Chmod { mode, path } => remote.chmod(*mode, path).await,
    }
}

/// Zusätzliche Befehle der interaktiven Sitzung.
#[derive(Debug, Parser)]
#[command(multicall = true, disable_help_flag = true)]
struct Line {
    #[command(subcommand)]
    command: ReplCommand,
}

#[derive(Debug, clap::Subcommand)]
enum ReplCommand {
    /// Verzeichnis auf dem Server wechseln
    Cd { path: String },
    /// Aktuelles Verzeichnis auf dem Server
    Pwd,
    /// Lokales Verzeichnis wechseln
    Lcd { path: String },
    /// Aktuelles lokales Verzeichnis
    Lpwd,
    /// Sitzung beenden
    #[command(visible_aliases = ["quit", "bye"])]
    Exit,
    #[command(flatten)]
    Action(SftpAction),
}

const COMMANDS: &[&str] = &[
    "cd", "pwd", "lcd", "lpwd", "exit", "quit", "bye", "ls", "get", "put", "rm", "mkdir", "rmdir",
    "mv", "stat", "chmod", "help",
];

/// Vervollständigt nur den Befehlsnamen.
struct CommandHelper;

impl Completer for CommandHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = &line[..pos];
        if prefix.contains(char::is_whitespace) {
            return Ok((pos, Vec::new()));
        }
        let matches = COMMANDS
            .iter()
            .filter(|c| c.starts_with(prefix))
            .map(|c| Pair {
                display: (*c).to_string(),
                replacement: format!("{c} "),
            })
            .collect();
        Ok((0, matches))
    }
}

impl Hinter for CommandHelper {
    type Hint = String;
}
impl Highlighter for CommandHelper {}
impl Validator for CommandHelper {}
impl Helper for CommandHelper {}

enum Input {
    Line(String),
    Interrupted,
    Eof,
}

/// Teilt eine Zeile in Wörter; Anführungszeichen (' und ") und `\` gruppieren bzw. maskieren.
pub fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') | (None, '\\') => {
                let next = chars.next().ok_or("Zeile endet mit \\")?;
                cur.push(next);
                in_word = true;
            }
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return Err("Anführungszeichen nicht geschlossen".to_string());
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

async fn interactive(mut remote: Remote) -> Result<i32, CliError> {
    let tty = std::io::stdin().is_terminal();
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<Input>(1);
    let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();

    // rustyline blockiert; es läuft in einem eigenen Thread und liest erst die nächste Zeile,
    // wenn der Befehl fertig ist.
    std::thread::spawn(move || {
        let Ok(mut editor) = Editor::<CommandHelper, rustyline::history::DefaultHistory>::new()
        else {
            let _ = line_tx.blocking_send(Input::Eof);
            return;
        };
        editor.set_helper(Some(CommandHelper));
        loop {
            let input = match editor.readline("sftp> ") {
                Ok(line) => {
                    let _ = editor.add_history_entry(line.as_str());
                    Input::Line(line)
                }
                Err(ReadlineError::Interrupted) => Input::Interrupted,
                Err(_) => Input::Eof,
            };
            let eof = matches!(input, Input::Eof);
            if line_tx.blocking_send(input).is_err() || eof {
                return;
            }
            if ack_rx.recv().is_err() {
                return;
            }
        }
    });

    let mut code = 0;
    while let Some(input) = line_rx.recv().await {
        match input {
            Input::Eof => break,
            Input::Interrupted => {
                let _ = ack_tx.send(());
            }
            Input::Line(line) => {
                let words = match split_words(&line) {
                    Ok(w) => w,
                    Err(e) => {
                        eprintln!("simple-ssh-cli: {e}");
                        let _ = ack_tx.send(());
                        continue;
                    }
                };
                if words.is_empty() {
                    let _ = ack_tx.send(());
                    continue;
                }
                let words = if words[0] == "help" || words[0] == "?" {
                    vec!["help".to_string()]
                } else {
                    words
                };
                match Line::try_parse_from(&words) {
                    Err(e) => {
                        let _ = e.print();
                        if !tty && e.use_stderr() {
                            code = 64;
                            break;
                        }
                    }
                    Ok(Line { command }) => {
                        let result = tokio::select! {
                            r = run_repl_command(&mut remote, &command) => r,
                            _ = tokio::signal::ctrl_c() => {
                                eprintln!("simple-ssh-cli: abgebrochen");
                                Ok(true)
                            }
                        };
                        match result {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(e) => {
                                eprintln!("simple-ssh-cli: {e}");
                                if e.code == crate::exitcode::LOST {
                                    code = e.code;
                                    break;
                                }
                                // Ohne Terminal (Skript) bricht der erste Fehler die Sitzung ab.
                                if !tty {
                                    code = e.code;
                                    break;
                                }
                            }
                        }
                    }
                }
                let _ = ack_tx.send(());
            }
        }
    }
    Ok(code)
}

/// `Ok(false)` beendet die Sitzung.
async fn run_repl_command(remote: &mut Remote, command: &ReplCommand) -> Result<bool, CliError> {
    match command {
        ReplCommand::Cd { path } => remote.cd(path).await?,
        ReplCommand::Pwd => println!("{}", remote.cwd),
        ReplCommand::Lcd { path } => std::env::set_current_dir(path)
            .map_err(|e| CliError::general(format!("{path}: {e}")))?,
        ReplCommand::Lpwd => match std::env::current_dir() {
            Ok(p) => println!("{}", p.display()),
            Err(e) => return Err(CliError::general(format!("lokales Verzeichnis: {e}"))),
        },
        ReplCommand::Exit => return Ok(false),
        ReplCommand::Action(action) => execute(remote, action).await?,
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_splitting() {
        let w = |s: &str| split_words(s).unwrap();
        assert_eq!(w("ls -l /tmp"), ["ls", "-l", "/tmp"]);
        assert_eq!(w("  get  a   b "), ["get", "a", "b"]);
        assert_eq!(w(r#"put "my file" 'x y'"#), ["put", "my file", "x y"]);
        assert_eq!(w(r"get a\ b"), ["get", "a b"]);
        assert_eq!(w(r#"get "" x"#), ["get", "", "x"]);
        assert!(w("").is_empty());
        assert!(split_words("get 'abc").is_err());
        assert!(split_words("get abc\\").is_err());
    }
}
