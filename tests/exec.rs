//! `exec` gegen einen echten OpenSSH-Server (Skip ohne sshd).

mod common;

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{Scratch, TestSshd};

const FP_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

macro_rules! sshd_or_skip {
    () => {
        match TestSshd::start() {
            Some(s) => s,
            None => {
                eprintln!("sshd/ssh-keygen not available, skipping");
                return;
            }
        }
    };
}

struct Fixture {
    sshd: TestSshd,
    home: Scratch,
}

impl Fixture {
    fn new(name: &str) -> Option<Self> {
        Some(Self {
            sshd: TestSshd::start()?,
            home: Scratch::new(name),
        })
    }

    fn target(&self) -> String {
        format!("{}@127.0.0.1:{}", self.sshd.user, self.sshd.port)
    }

    /// Befehl mit vertrauenswürdigem Fingerprint und dem autorisierten Schlüssel.
    fn command(&self, extra: &[&str], remote: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
        cmd.env_clear()
            .env("HOME", &self.home.dir)
            .env("XDG_CONFIG_HOME", self.home.dir.join("cfg"))
            .args(["--fingerprint", &self.sshd.fingerprint, "-i"])
            .arg(self.sshd.key_plain_path())
            .args(extra)
            .arg("exec")
            .arg(self.target())
            .args(remote);
        cmd
    }
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

fn finish(mut child: Child, limit: Duration) -> Out {
    // Beide Pipes laufend leeren, sonst blockiert das Programm bei großer Ausgabe.
    let stdout = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            panic!("Programm läuft länger als {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Out {
        code: status.code().unwrap_or(-1),
        stdout: stdout
            .map(|t| t.join().unwrap_or_default())
            .unwrap_or_default(),
        stderr: String::from_utf8_lossy(
            &stderr
                .map(|t| t.join().unwrap_or_default())
                .unwrap_or_default(),
        )
        .into_owned(),
    }
}

fn run(mut cmd: Command) -> Out {
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    finish(child, Duration::from_secs(60))
}

fn pattern(len: usize, salt: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(131).wrapping_add(salt) % 251) as u8)
        .collect()
}

#[test]
fn stdout_and_stderr_end_up_on_the_right_streams() {
    let Some(f) = Fixture::new("exec-streams") else {
        return;
    };
    let out = run(f.command(&[], &["echo out; echo err >&2"]));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, "err\n");
}

#[test]
fn command_words_are_joined_like_ssh() {
    let Some(f) = Fixture::new("exec-words") else {
        return;
    };
    let out = run(f.command(&[], &["echo", "a", "b"]));
    assert_eq!(
        (out.code, out.stdout.as_slice()),
        (0, b"a b\n".as_slice()),
        "{}",
        out.stderr
    );
    // Argumente mit führendem Strich gehören zum Befehl.
    let out = run(f.command(&[], &["ls", "-d", "/"]));
    assert_eq!(
        (out.code, out.stdout.as_slice()),
        (0, b"/\n".as_slice()),
        "{}",
        out.stderr
    );
    // `--` ist erlaubt.
    let out = run(f.command(&[], &["--", "echo", "hi"]));
    assert_eq!(
        (out.code, out.stdout.as_slice()),
        (0, b"hi\n".as_slice()),
        "{}",
        out.stderr
    );
    // Ein einzelner String wird von der Remote-Shell ausgewertet.
    let out = run(f.command(&[], &["echo $((6*7)) 'a  b'"]));
    assert_eq!(out.stdout, b"42 a  b\n", "{}", out.stderr);
}

#[test]
fn remote_exit_codes_are_passed_through() {
    let Some(f) = Fixture::new("exec-codes") else {
        return;
    };
    for (script, code) in [
        ("exit 0", 0),
        ("exit 7", 7),
        ("exit 255", 255),
        ("kill -9 $$", 137),
        ("kill -TERM $$", 143),
    ] {
        let out = run(f.command(&[], &[script]));
        assert_eq!(out.code, code, "{script}: {}", out.stderr);
    }
    let out = run(f.command(&[], &["definitely-not-a-command-xyz"]));
    assert_eq!(out.code, 127);
    assert!(
        !out.stderr.is_empty(),
        "die Fehlermeldung der Remote-Shell fehlt"
    );
    let out = run(f.command(&["-v"], &["exit 3"]));
    assert_eq!(out.code, 3);
    assert!(out.stderr.contains("Remote-Status"), "{}", out.stderr);
}

#[test]
fn output_is_visible_while_the_command_is_still_running() {
    let Some(f) = Fixture::new("exec-live") else {
        return;
    };
    let started = Instant::now();
    let mut child = f
        .command(&[], &["echo first; sleep 3; echo second"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    lines.read_line(&mut line).unwrap();
    assert_eq!(line, "first\n");
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "first line after {:?}",
        started.elapsed()
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "Befehl lief schon durch"
    );
    line.clear();
    lines.read_line(&mut line).unwrap();
    assert_eq!(line, "second\n");
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn stdin_is_passed_through_live_and_binary_safe() {
    let Some(f) = Fixture::new("exec-stdin") else {
        return;
    };
    // Alle 256 Bytewerte, viele Male: nichts darf verändert werden.
    let data: Vec<u8> = (0..3_000_000usize).map(|i| (i % 256) as u8).collect();
    let mut child = f
        .command(&[], &["cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let feed = data.clone();
    let writer = std::thread::spawn(move || {
        stdin.write_all(&feed).unwrap();
    });
    let out = finish(child, Duration::from_secs(60));
    writer.join().unwrap();
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout.len(), data.len());
    assert!(out.stdout == data, "Daten verändert");

    // `wc -c` zählt genau die gesendeten Bytes.
    let mut child = f
        .command(&[], &["wc -c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pattern(123_457, 5))
        .unwrap();
    let out = finish(child, Duration::from_secs(30));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "123457",
        "{}",
        out.stderr
    );
}

#[test]
fn echo_happens_before_the_input_ends() {
    let Some(f) = Fixture::new("exec-interactive") else {
        return;
    };
    let mut child = f
        .command(&[], &["cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    stdin.write_all(b"ping\n").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    assert_eq!(
        line, "ping\n",
        "die Antwort muss vor dem Ende der Eingabe kommen"
    );
    drop(stdin);
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn no_stdin_option_gives_the_command_an_empty_input() {
    let Some(f) = Fixture::new("exec-nostdin") else {
        return;
    };
    // Die Eingabe-Pipe bleibt offen; ohne --no-stdin würde `cat` ewig warten.
    let mut child = f
        .command(&[], &["--no-stdin", "cat; echo done"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _keep_open = child.stdin.take().unwrap();
    let out = finish(child, Duration::from_secs(20));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout, b"done\n");
}

#[test]
fn a_command_that_stops_reading_early_does_not_block_the_cli() {
    let Some(f) = Fixture::new("exec-early") else {
        return;
    };
    let mut child = f
        .command(&[], &["head -c 10 | wc -c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let big = pattern(50_000_000, 1);
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&big); // bricht mit Broken Pipe ab, sobald das CLI endet
    });
    let out = finish(child, Duration::from_secs(40));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "10");
    drop(writer); // der Schreib-Thread darf im Hintergrund auslaufen
}

#[test]
fn forty_megabytes_of_output_land_in_a_file_intact() {
    let Some(f) = Fixture::new("exec-big") else {
        return;
    };
    let target = f.home.dir.join("out.bin");
    let file = File::create(&target).unwrap();
    let child = f
        .command(&[], &["head -c 40000000 /dev/zero"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = finish(child, Duration::from_secs(60));
    assert_eq!(out.code, 0, "{}", out.stderr);
    let bytes = std::fs::read(&target).unwrap();
    assert_eq!(bytes.len(), 40_000_000);
    assert!(bytes.iter().all(|&b| b == 0));
}

#[test]
fn closing_local_stdout_early_ends_the_cli_quietly() {
    let Some(f) = Fixture::new("exec-pipe") else {
        return;
    };
    let mut child = f
        .command(&[], &["yes"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut head = vec![0u8; 1024];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut head)
        .unwrap();
    assert!(head.starts_with(b"y\ny\n"));
    drop(child.stdout.take()); // wie `| head -c 1024`
    let out = finish(child, Duration::from_secs(20));
    assert_eq!(out.code, 141, "{}", out.stderr);
    assert!(
        out.stderr.is_empty(),
        "keine Fehlermeldung bei geschlossener Ausgabe: {}",
        out.stderr
    );
}

#[test]
fn ctrl_c_closes_the_channel_and_exits_with_130() {
    let Some(f) = Fixture::new("exec-sigint") else {
        return;
    };
    let child = f
        .command(&[], &["sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let out = finish(child, Duration::from_secs(10));
    assert_eq!(out.code, 130, "{}", out.stderr);
}

#[test]
fn nothing_runs_on_the_server_when_the_host_key_is_not_trusted() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("exec-untrusted");
    let marker = home.dir.join("marker");
    let marker_cmd = format!("touch {}", marker.display());
    let target = format!("{}@127.0.0.1:{}", sshd.user, sshd.port);
    let base = |extra: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
        cmd.env_clear()
            .env("HOME", &home.dir)
            .env("XDG_CONFIG_HOME", home.dir.join("cfg"))
            .arg("-i")
            .arg(sshd.key_plain_path())
            .args(extra)
            .arg("exec")
            .arg(&target)
            .arg(&marker_cmd);
        run(cmd)
    };

    // unbekannt
    let out = base(&[]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(!Path::new(&marker).exists());
    // geändert
    let kh = home.dir.join("kh");
    std::fs::write(&kh, format!("[127.0.0.1]:{} {FP_A}\n", sshd.port)).unwrap();
    let out = base(&["--known-hosts", kh.to_str().unwrap(), "--accept-new"]);
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(!Path::new(&marker).exists());
    // falscher Schlüssel
    let out = {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
        cmd.env_clear()
            .env("HOME", &home.dir)
            .args(["--fingerprint", &sshd.fingerprint, "-i"])
            .arg(sshd.key_unauthorized_path())
            .arg("exec")
            .arg(&target)
            .arg(&marker_cmd);
        run(cmd)
    };
    assert_eq!(out.code, 4, "{}", out.stderr);
    assert!(!Path::new(&marker).exists());

    // Zur Gegenprobe: mit passendem Fingerprint läuft derselbe Befehl.
    let out = base(&["--fingerprint", &sshd.fingerprint]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(Path::new(&marker).exists());
}

#[test]
fn connection_loss_gives_255_and_a_message() {
    let Some(f) = Fixture::new("exec-lost") else {
        return;
    };
    let child = f
        .command(&[], &["kill -9 $PPID"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = finish(child, Duration::from_secs(20));
    assert_eq!(out.code, 255, "{}", out.stderr);
    assert!(out.stderr.contains("Verbindung"), "{}", out.stderr);
}

#[test]
fn keepalive_option_is_accepted_and_does_not_disturb() {
    let Some(f) = Fixture::new("exec-keepalive") else {
        return;
    };
    let out = run(f.command(&["--keepalive", "1"], &["sleep 2; echo ok"]));
    assert_eq!(
        (out.code, out.stdout.as_slice()),
        (0, b"ok\n".as_slice()),
        "{}",
        out.stderr
    );
}

#[test]
fn missing_command_is_a_usage_error() {
    let Some(f) = Fixture::new("exec-usage") else {
        return;
    };
    let out = run(f.command(&[], &[]));
    assert_eq!(out.code, 64, "{}", out.stderr);
}
