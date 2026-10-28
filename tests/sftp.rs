//! `sftp` (Einzelbefehle und Sitzung über Pipe) gegen einen echten OpenSSH-Server.

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{Options, Scratch, TestSshd};

struct Fixture {
    sshd: TestSshd,
    home: Scratch,
    /// Arbeitsverzeichnis auf dem Server (derselbe Rechner, also auch lokal erreichbar).
    remote: Scratch,
    /// Lokales Arbeitsverzeichnis des Programms.
    local: Scratch,
}

impl Fixture {
    fn new(name: &str) -> Option<Self> {
        Self::with(name, Options::default())
    }

    fn with(name: &str, opts: Options) -> Option<Self> {
        Some(Self {
            sshd: TestSshd::start_with(opts)?,
            home: Scratch::new(&format!("{name}-home")),
            remote: Scratch::new(&format!("{name}-remote")),
            local: Scratch::new(&format!("{name}-local")),
        })
    }

    fn command(&self, trust: bool, rest: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
        cmd.env_clear()
            .env("HOME", &self.home.dir)
            .env("XDG_CONFIG_HOME", self.home.dir.join("cfg"))
            .current_dir(&self.local.dir);
        if trust {
            cmd.args(["--fingerprint", &self.sshd.fingerprint]);
        }
        cmd.arg("-i")
            .arg(self.sshd.key_plain_path())
            .arg("sftp")
            .arg(format!("{}@127.0.0.1:{}", self.sshd.user, self.sshd.port))
            .args(rest);
        cmd
    }

    fn rp(&self, name: &str) -> String {
        self.remote.path(name)
    }

    fn lp(&self, name: &str) -> String {
        self.local.path(name)
    }
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Out {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

fn run_with(mut cmd: Command, input: &[u8]) -> Out {
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
    });
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t1 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t2 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if started.elapsed() > Duration::from_secs(90) {
            let _ = child.kill();
            panic!("Programm läuft zu lange");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Out {
        code: status.code().unwrap_or(-1),
        stdout: t1.join().unwrap_or_default(),
        stderr: String::from_utf8_lossy(&t2.join().unwrap_or_default()).into_owned(),
    }
}

fn run(f: &Fixture, rest: &[&str]) -> Out {
    run_with(f.command(true, rest), b"")
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(131) % 251) as u8)
        .collect()
}

#[test]
fn ls_lists_sorted_and_hides_dotfiles() {
    let Some(f) = Fixture::new("sftp-ls") else {
        return;
    };
    std::fs::write(f.rp("b.txt"), b"bb").unwrap();
    std::fs::write(f.rp("a.txt"), b"a").unwrap();
    std::fs::write(f.rp(".hidden"), b"").unwrap();
    std::fs::create_dir(f.rp("sub")).unwrap();

    let out = run(&f, &["ls", &f.remote.dir.to_string_lossy()]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.text(), "a.txt\nb.txt\nsub\n");

    let out = run(&f, &["ls", "-a", &f.remote.dir.to_string_lossy()]);
    assert!(out.text().contains(".hidden"), "{}", out.text());

    let out = run(&f, &["ls", "-l", &f.remote.dir.to_string_lossy()]);
    let text = out.text();
    assert!(text.contains(" 2 "), "{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with('d') && l.ends_with(" sub"))
    );
    assert!(
        text.lines()
            .any(|l| l.starts_with("-rw") && l.ends_with(" a.txt"))
    );

    let out = run(&f, &["ls", &f.rp("a.txt")]);
    assert_eq!(out.text().trim_end(), f.rp("a.txt"));
}

#[test]
fn put_and_get_roundtrip_large_file_byte_exact() {
    let Some(f) = Fixture::new("sftp-xfer") else {
        return;
    };
    let data = pattern(7 * 1024 * 1024 + 321);
    std::fs::write(f.lp("src.bin"), &data).unwrap();

    let out = run(&f, &["put", "src.bin", &f.rp("dst.bin")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("dst.bin: 7.0 MiB"), "{}", out.stderr);
    assert_eq!(std::fs::read(f.rp("dst.bin")).unwrap(), data);

    let out = run(&f, &["get", &f.rp("dst.bin"), "back.bin"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(f.lp("back.bin")).unwrap(), data);
    assert!(!std::path::Path::new(&f.lp("back.bin.part")).exists());

    // Ohne Ziel: Name der Datei im aktuellen Verzeichnis; Ziel ist ein Verzeichnis.
    let out = run(&f, &["get", &f.rp("dst.bin")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(f.lp("dst.bin")).unwrap(), data);
    std::fs::create_dir(f.lp("dir")).unwrap();
    let out = run(&f, &["get", &f.rp("dst.bin"), "dir"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(f.lp("dir/dst.bin")).unwrap(), data);

    // Upload in ein vorhandenes Verzeichnis übernimmt den Dateinamen.
    std::fs::create_dir(f.rp("updir")).unwrap();
    let out = run(&f, &["put", "src.bin", &f.rp("updir")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(f.rp("updir/src.bin")).unwrap(), data);
}

#[test]
fn upload_keeps_the_file_mode() {
    let Some(f) = Fixture::new("sftp-mode") else {
        return;
    };
    std::fs::write(f.lp("run.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(f.lp("run.sh"), std::fs::Permissions::from_mode(0o750)).unwrap();
    let out = run(&f, &["put", "run.sh", &f.rp("run.sh")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let mode = std::fs::metadata(f.rp("run.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777 & !0o022, 0o750 & !0o022);
}

#[test]
fn stdin_and_stdout_streams() {
    let Some(f) = Fixture::new("sftp-stdio") else {
        return;
    };
    let data = pattern(1_500_000);
    let out = run_with(f.command(true, &["put", "-", &f.rp("in.bin")]), &data);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(f.rp("in.bin")).unwrap(), data);

    let out = run(&f, &["get", &f.rp("in.bin"), "-"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout, data);

    // Von stdin ohne Ziel ist ein Bedienfehler.
    let out = run_with(f.command(true, &["put", "-"]), b"x");
    assert_eq!(out.code, 64, "{}", out.stderr);
}

#[test]
fn file_management_commands() {
    let Some(f) = Fixture::new("sftp-manage") else {
        return;
    };
    let d = f.rp("newdir");
    assert_eq!(run(&f, &["mkdir", &d]).code, 0);
    assert!(std::path::Path::new(&d).is_dir());

    std::fs::write(f.rp("x.txt"), b"hello").unwrap();
    std::fs::write(f.rp("y.txt"), b"").unwrap();
    let out = run(&f, &["mv", &f.rp("x.txt"), &f.rp("z.txt")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!std::path::Path::new(&f.rp("x.txt")).exists());
    // Verschieben in ein Verzeichnis.
    let out = run(&f, &["mv", &f.rp("z.txt"), &d]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(format!("{d}/z.txt")).unwrap(), b"hello");

    let out = run(&f, &["chmod", "600", &format!("{d}/z.txt")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let mode = std::fs::metadata(format!("{d}/z.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    let out = run(&f, &["stat", &format!("{d}/z.txt")]);
    let text = out.text();
    assert!(text.contains("Größe:   5"), "{text}");
    assert!(text.contains("0600"), "{text}");

    // Nicht leeres Verzeichnis lässt sich nicht löschen; danach rm und rmdir.
    let out = run(&f, &["rmdir", &d]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains(&d), "{}", out.stderr);
    let out = run(&f, &["rm", &format!("{d}/z.txt"), &f.rp("y.txt")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(run(&f, &["rmdir", &d]).code, 0);
    assert!(!std::path::Path::new(&d).exists());
}

#[test]
fn errors_name_the_path_and_leave_no_partial_files() {
    let Some(f) = Fixture::new("sftp-errors") else {
        return;
    };
    let out = run(&f, &["get", &f.rp("missing"), "out.bin"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("missing"), "{}", out.stderr);
    assert!(out.stderr.contains("NoSuchFile"), "{}", out.stderr);
    assert!(!std::path::Path::new(&f.lp("out.bin")).exists());
    assert!(!std::path::Path::new(&f.lp("out.bin.part")).exists());

    let out = run(&f, &["put", "nope.bin", &f.rp("x")]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("nope.bin"), "{}", out.stderr);

    // Verzeichnisse werden nicht rekursiv übertragen.
    std::fs::create_dir(f.rp("d")).unwrap();
    let out = run(&f, &["get", &f.rp("d"), "d"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("Verzeichnis"), "{}", out.stderr);

    // Ungültiger Modus ist ein Bedienfehler.
    let out = run(&f, &["chmod", "999", &f.rp("d")]);
    assert_eq!(out.code, 64, "{}", out.stderr);
}

#[test]
fn missing_sftp_subsystem_is_reported_without_fallback() {
    let Some(f) = Fixture::with(
        "sftp-nosub",
        Options {
            sftp: false,
            ..Options::default()
        },
    ) else {
        return;
    };
    let out = run(&f, &["ls"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("kein SFTP"), "{}", out.stderr);
}

#[test]
fn unknown_host_key_gives_2_and_transfers_nothing() {
    let Some(f) = Fixture::new("sftp-unknown") else {
        return;
    };
    std::fs::write(f.lp("a.txt"), b"x").unwrap();
    let out = run_with(f.command(false, &["put", "a.txt", &f.rp("a.txt")]), b"");
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(!std::path::Path::new(&f.rp("a.txt")).exists());
}

#[test]
fn session_over_a_pipe_runs_commands_and_tracks_directories() {
    let Some(f) = Fixture::new("sftp-repl") else {
        return;
    };
    std::fs::create_dir(f.rp("sub")).unwrap();
    std::fs::write(f.rp("sub/inner.txt"), b"inner").unwrap();
    std::fs::write(f.lp("up.txt"), b"uploaded").unwrap();
    let script = format!(
        "cd {}\npwd\nls\ncd sub\npwd\nls\nget inner.txt got.txt\nput up.txt\nlcd /\nlpwd\nexit\n",
        f.remote.dir.display()
    );
    let out = run_with(f.command(true, &[]), script.as_bytes());
    assert_eq!(out.code, 0, "{}\n{}", out.text(), out.stderr);
    let text = out.text();
    let remote = std::fs::canonicalize(&f.remote.dir).unwrap();
    assert!(text.contains(&format!("{}\n", remote.display())), "{text}");
    assert!(text.contains("sub\n"), "{text}");
    assert!(
        text.contains(&format!("{}/sub\n", remote.display())),
        "{text}"
    );
    assert!(text.contains("inner.txt\n"), "{text}");
    assert_eq!(std::fs::read(f.lp("got.txt")).unwrap(), b"inner");
    assert_eq!(std::fs::read(f.rp("sub/up.txt")).unwrap(), b"uploaded");
    assert!(text.lines().any(|l| l == "/"), "{text}");
}

#[test]
fn session_with_quoted_names_and_help() {
    let Some(f) = Fixture::new("sftp-quote") else {
        return;
    };
    std::fs::write(f.rp("with space.txt"), b"s").unwrap();
    let script = format!(
        "get \"{}\" 'local name.txt'\nhelp\nexit\n",
        f.rp("with space.txt")
    );
    let out = run_with(f.command(true, &[]), script.as_bytes());
    assert_eq!(out.code, 0, "{}\n{}", out.text(), out.stderr);
    assert_eq!(std::fs::read(f.lp("local name.txt")).unwrap(), b"s");
    assert!(out.text().contains("chmod"), "{}", out.text());
}

#[test]
fn script_stops_at_the_first_error_and_end_of_input_ends_the_session() {
    let Some(f) = Fixture::new("sftp-script") else {
        return;
    };
    let script = format!(
        "mkdir {}\nrmdir {}\nmkdir {}\n",
        f.rp("one"),
        f.rp("nope"),
        f.rp("two")
    );
    let out = run_with(f.command(true, &[]), script.as_bytes());
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(std::path::Path::new(&f.rp("one")).is_dir());
    assert!(!std::path::Path::new(&f.rp("two")).exists());

    // Eingabeende ohne `exit` beendet die Sitzung mit 0.
    let out = run_with(f.command(true, &[]), b"pwd\n");
    assert_eq!(out.code, 0, "{}", out.stderr);

    // Unbekannter Befehl: Bedienfehler.
    let out = run_with(f.command(true, &[]), b"frobnicate\n");
    assert_eq!(out.code, 64, "{}", out.stderr);
}
