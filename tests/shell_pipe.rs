//! `shell` ohne Terminal (stdin/stdout sind Pipes) gegen einen echten OpenSSH-Server.

mod common;

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{Scratch, TestSshd};

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

    fn command(&self, trust: bool) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
        cmd.env_clear()
            .env("HOME", &self.home.dir)
            .env("XDG_CONFIG_HOME", self.home.dir.join("cfg"));
        if trust {
            cmd.args(["--fingerprint", &self.sshd.fingerprint]);
        }
        cmd.arg("-i")
            .arg(self.sshd.key_plain_path())
            .arg("shell")
            .arg(format!("{}@127.0.0.1:{}", self.sshd.user, self.sshd.port));
        cmd
    }
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Startet das Programm, schickt `input` an stdin und schließt es dann.
fn run(mut cmd: Command, input: &[u8], limit: Duration) -> Out {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
        // stdin wird hier geschlossen
    });
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stderr.read_to_end(&mut b);
        b
    });
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            panic!("Programm läuft länger als {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Out {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned(),
        stderr: String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned(),
    }
}

#[test]
fn commands_run_and_the_exit_code_is_passed_through() {
    let Some(f) = Fixture::new("shell-pipe-basic") else {
        return;
    };
    let out = run(
        f.command(true),
        b"echo hello-$((6*7))\nexit 5\n",
        Duration::from_secs(30),
    );
    assert_eq!(out.code, 5, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("hello-42"), "{}", out.stdout);
}

#[test]
fn end_of_input_sends_ctrl_d_and_ends_the_shell() {
    let Some(f) = Fixture::new("shell-pipe-eof") else {
        return;
    };
    let out = run(
        f.command(true),
        b"echo still-here\n",
        Duration::from_secs(20),
    );
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("still-here"), "{}", out.stdout);
}

#[test]
fn term_comes_from_the_environment_with_a_fallback() {
    let Some(f) = Fixture::new("shell-pipe-term") else {
        return;
    };
    let out = run(
        f.command(true),
        b"echo TERM=[$TERM]\nexit\n",
        Duration::from_secs(30),
    );
    assert!(
        out.stdout.contains("TERM=[xterm-256color]"),
        "{}",
        out.stdout
    );

    let mut cmd = f.command(true);
    cmd.env("TERM", "vt100");
    let out = run(cmd, b"echo TERM=[$TERM]\nexit\n", Duration::from_secs(30));
    assert!(out.stdout.contains("TERM=[vt100]"), "{}", out.stdout);
}

#[test]
fn unknown_host_key_gives_2_and_runs_nothing() {
    let Some(f) = Fixture::new("shell-pipe-unknown") else {
        return;
    };
    let marker = f.home.dir.join("ran");
    let input = format!("touch {}\nexit\n", marker.display());
    let out = run(f.command(false), input.as_bytes(), Duration::from_secs(30));
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    assert!(!marker.exists());
}

#[test]
fn wrong_key_gives_4() {
    let Some(f) = Fixture::new("shell-pipe-auth") else {
        return;
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
    cmd.env_clear()
        .env("HOME", &f.home.dir)
        .args(["--fingerprint", &f.sshd.fingerprint, "-i"])
        .arg(f.sshd.key_unauthorized_path())
        .arg("shell")
        .arg(format!("{}@127.0.0.1:{}", f.sshd.user, f.sshd.port));
    let out = run(cmd, b"exit\n", Duration::from_secs(30));
    assert_eq!(out.code, 4, "{}", out.stderr);
    assert!(out.stdout.is_empty());
}

#[test]
fn connection_loss_gives_255_and_a_message() {
    let Some(f) = Fixture::new("shell-pipe-lost") else {
        return;
    };
    let out = run(f.command(true), b"kill -9 $PPID\n", Duration::from_secs(30));
    assert_eq!(out.code, 255, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stderr.contains("simple-ssh-cli:"), "{}", out.stderr);
}

#[test]
fn large_input_and_output_do_not_deadlock() {
    let Some(f) = Fixture::new("shell-pipe-large") else {
        return;
    };
    // 300 KB Eingabe in `cat > /dev/null`, dann viel Ausgabe.
    let mut input = Vec::new();
    input.extend_from_slice(b"cat > /dev/null\n");
    for _ in 0..4000 {
        input.extend_from_slice(&[b'x'; 75]);
        input.push(b'\n');
    }
    input.extend_from_slice(&[0x04]);
    input.extend_from_slice(b"seq 1 100000\nexit 0\n");
    let out = run(f.command(true), &input, Duration::from_secs(60));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("100000"), "Ausgabe unvollständig");
}
