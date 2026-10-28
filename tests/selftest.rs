//! `selftest` gegen einen echten OpenSSH-Server.

mod common;

use std::process::{Command, Stdio};

use common::{Options, Scratch, TestSshd};

struct Fixture {
    sshd: TestSshd,
    home: Scratch,
    work: Scratch,
}

impl Fixture {
    fn new(name: &str, opts: Options) -> Option<Self> {
        Some(Self {
            sshd: TestSshd::start_with(opts)?,
            home: Scratch::new(&format!("{name}-home")),
            work: Scratch::new(&format!("{name}-work")),
        })
    }

    fn command(&self, trust: bool, extra: &[&str]) -> Command {
        self.command_in(trust, self.work.dir.as_os_str(), extra)
    }

    fn command_in(&self, trust: bool, workdir: &std::ffi::OsStr, extra: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
        cmd.env_clear()
            .env("HOME", &self.home.dir)
            .env("XDG_CONFIG_HOME", self.home.dir.join("cfg"));
        if trust {
            cmd.args(["--fingerprint", &self.sshd.fingerprint]);
        }
        cmd.arg("-i")
            .arg(self.sshd.key_plain_path())
            .arg("selftest")
            .arg(format!("{}@127.0.0.1:{}", self.sshd.user, self.sshd.port))
            .args(["--size", "2MiB", "--workdir"])
            .arg(workdir)
            .args(extra);
        cmd
    }
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(mut cmd: Command) -> Out {
    let out = cmd.stdin(Stdio::null()).output().expect("Programm starten");
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn leftovers(f: &Fixture) -> Vec<String> {
    std::fs::read_dir(&f.work.dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn full_run_passes_and_cleans_up() {
    let Some(f) = Fixture::new("selftest-full", Options::default()) else {
        return;
    };
    let out = run(f.command(true, &[]));
    if std::env::var_os("SHOW_SELFTEST").is_some() {
        eprintln!("{}", out.stdout);
    }
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    for name in [
        "connection",
        "hostkey-pin",
        "exec",
        "bulk-data",
        "concurrency",
        "shell",
        "sftp",
        "rekey",
        "keepalive",
    ] {
        assert!(
            out.stdout
                .lines()
                .any(|l| l.starts_with("PASS") && l.contains(name)),
            "{name} nicht bestanden:\n{}",
            out.stdout
        );
    }
    assert!(
        out.stdout
            .lines()
            .any(|l| l.starts_with("SKIP") && l.contains("conn-loss")),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("9 bestanden, 0 fehlgeschlagen, 1 übersprungen")
    );
    assert!(leftovers(&f).is_empty(), "übrig: {:?}", leftovers(&f));
}

#[test]
fn json_output_is_valid_and_complete() {
    let Some(f) = Fixture::new("selftest-json", Options::default()) else {
        return;
    };
    let out = run(f.command(true, &["--json", "--destructive"]));
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("kein gültiges JSON ({e}):\n{}", out.stdout));
    assert_eq!(v["tool"], "simple-ssh-cli");
    assert_eq!(v["summary"]["pass"], 10);
    assert_eq!(v["summary"]["fail"], 0);
    assert_eq!(v["summary"]["skip"], 0);
    assert_eq!(v["data_size_bytes"], 2 * 1024 * 1024);
    assert_eq!(v["workdir_removed"], true);
    assert!(v["host_key"].as_str().unwrap().starts_with("SHA256:"));
    assert!(v["server_banner"].as_str().unwrap().starts_with("SSH-2.0-"));
    let checks = v["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 10);
    assert!(checks.iter().all(|c| c["status"] == "PASS"));
    assert!(checks.iter().all(|c| c["duration_ms"].is_u64()));
    // Fortschrittszeilen gehen nach stderr.
    assert!(out.stderr.contains("PASS"), "{}", out.stderr);
    assert!(leftovers(&f).is_empty());
}

#[test]
fn server_without_sftp_gives_skip_not_fail() {
    let Some(f) = Fixture::new(
        "selftest-nosftp",
        Options {
            sftp: false,
            ..Options::default()
        },
    ) else {
        return;
    };
    let out = run(f.command(true, &[]));
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert!(
        out.stdout
            .lines()
            .any(|l| l.starts_with("SKIP") && l.contains("sftp") && l.contains("kein SFTP")),
        "{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("0 fehlgeschlagen, 2 übersprungen"),
        "{}",
        out.stdout
    );
}

#[test]
fn unknown_host_key_stops_before_any_check() {
    let Some(f) = Fixture::new("selftest-unknown", Options::default()) else {
        return;
    };
    let out = run(f.command(false, &[]));
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    assert!(leftovers(&f).is_empty());
}

#[test]
fn bad_size_is_a_usage_error() {
    let Some(f) = Fixture::new("selftest-size", Options::default()) else {
        return;
    };
    let mut cmd = f.command(true, &[]);
    cmd.args(["--size", "5TB"]);
    let out = run(cmd);
    assert_eq!(out.code, 64, "{}", out.stderr);
}

#[test]
fn unusable_workdir_is_an_error_with_a_message() {
    let Some(f) = Fixture::new("selftest-workdir", Options::default()) else {
        return;
    };
    let out = run(f.command_in(true, "/proc/simple-ssh-cli-nope".as_ref(), &[]));
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(out.stderr.contains("Arbeitsordner"), "{}", out.stderr);
}
