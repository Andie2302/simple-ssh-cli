//! Das Programm als Ganzes gegen einen echten OpenSSH-Server (Skip ohne sshd).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{KEY_PASSPHRASE, Scratch, TestSshd};

const FP_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Startet das Programm mit leerer Umgebung; `home` dient als HOME und Konfigurationsbasis.
fn run(home: &Path, args: &[&str], envs: &[(&str, &str)]) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
    cmd.env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("cfg"))
        .stdin(Stdio::null())
        .args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("start binary");
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn known_hosts_path(home: &Path) -> PathBuf {
    home.join("cfg").join("simple-ssh-cli").join("known_hosts")
}

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

fn target(sshd: &TestSshd) -> String {
    format!("{}@127.0.0.1:{}", sshd.user, sshd.port)
}

fn label(sshd: &TestSshd) -> String {
    format!("[127.0.0.1]:{}", sshd.port)
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

// ------------------------------------------------------------------ hostkey

#[test]
fn hostkey_prints_the_fingerprint_that_ssh_keygen_shows() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-hostkey");
    let out = run(&home.dir, &["hostkey", &target(&sshd)], &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(
        out.stdout,
        format!("256 {} {} (ED25519)\n", sshd.fingerprint, label(&sshd))
    );
    assert!(out.stderr.contains("unbekannt"), "{}", out.stderr);
    assert!(
        !known_hosts_path(&home.dir).exists(),
        "hostkey darf nichts speichern"
    );
}

#[test]
fn hostkey_reports_whether_the_key_is_known_or_changed() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-hostkey-status");
    let file = known_hosts_path(&home.dir);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();

    std::fs::write(&file, format!("{} {}\n", label(&sshd), sshd.fingerprint)).unwrap();
    let out = run(&home.dir, &["hostkey", &target(&sshd)], &[]);
    assert_eq!(out.code, 0);
    assert!(out.stderr.contains("bekannt"), "{}", out.stderr);

    std::fs::write(&file, format!("{} {FP_A}\n", label(&sshd))).unwrap();
    let out = run(&home.dir, &["hostkey", &target(&sshd)], &[]);
    assert_eq!(out.code, 0, "hostkey zeigt Abweichungen nur an");
    assert!(out.stderr.contains("ABWEICHEND"), "{}", out.stderr);
}

// -------------------------------------------------------------------- check

#[test]
fn unknown_host_is_refused_with_code_2_and_nothing_is_saved() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-unknown");
    let key = sshd.key_plain_path();
    let out = run(&home.dir, &["-i", s(&key), "check", &target(&sshd)], &[]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(out.stderr.contains(&sshd.fingerprint), "{}", out.stderr);
    assert!(out.stderr.contains("--accept-new"), "{}", out.stderr);
    assert!(out.stdout.is_empty());
    assert!(!known_hosts_path(&home.dir).exists());
}

#[test]
fn accept_new_saves_the_host_after_login_with_private_permissions() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-accept");
    let key = sshd.key_plain_path();
    let out = run(
        &home.dir,
        &["--accept-new", "-i", s(&key), "check", &target(&sshd)],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout
            .starts_with(&format!("OK  {}@127.0.0.1:{}", sshd.user, sshd.port)),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("SSH-2.0-OpenSSH"));
    assert!(out.stdout.contains(&sshd.fingerprint));

    let file = known_hosts_path(&home.dir);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{} {}\n", label(&sshd), sshd.fingerprint)
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    // Ab jetzt ist der Server bekannt: kein Flag mehr nötig, die Datei bleibt gleich.
    let before = std::fs::read(&file).unwrap();
    let out = run(&home.dir, &["-i", s(&key), "check", &target(&sshd)], &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(std::fs::read(&file).unwrap(), before);
}

#[test]
fn changed_key_is_refused_with_code_3_even_with_accept_new() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-changed");
    let file = known_hosts_path(&home.dir);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let content = format!("# alt\n{} {FP_A}\n", label(&sshd));
    std::fs::write(&file, &content).unwrap();
    let key = sshd.key_plain_path();

    for extra in [&[][..], &["--accept-new"][..]] {
        let mut args = extra.to_vec();
        args.extend(["-i", s(&key), "check"]);
        let t = target(&sshd);
        args.push(&t);
        let out = run(&home.dir, &args, &[]);
        assert_eq!(out.code, 3, "{}", out.stderr);
        assert!(
            out.stderr.contains(FP_A) && out.stderr.contains(&sshd.fingerprint),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains("geändert"), "{}", out.stderr);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            content,
            "Datei darf sich nie ändern"
        );
    }
}

#[test]
fn pinned_fingerprint_overrides_the_file_and_leaves_it_alone() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-pinned");
    let key = sshd.key_plain_path();

    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            &sshd.fingerprint,
            "-i",
            s(&key),
            "check",
            &target(&sshd),
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!known_hosts_path(&home.dir).exists());

    // Auch mit --accept-new wird mit --fingerprint nichts gespeichert.
    let out = run(
        &home.dir,
        &[
            "--accept-new",
            "--fingerprint",
            &sshd.fingerprint,
            "-i",
            s(&key),
            "check",
            &target(&sshd),
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!known_hosts_path(&home.dir).exists());

    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            FP_A,
            "-i",
            s(&key),
            "check",
            &target(&sshd),
        ],
        &[],
    );
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(out.stderr.contains("--fingerprint"), "{}", out.stderr);

    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            "kaputt",
            "-i",
            s(&key),
            "check",
            &target(&sshd),
        ],
        &[],
    );
    assert_eq!(out.code, 64, "{}", out.stderr);
}

#[test]
fn failed_login_does_not_store_the_host() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-authfail");
    let key = sshd.key_unauthorized_path();
    let out = run(
        &home.dir,
        &["--accept-new", "-i", s(&key), "check", &target(&sshd)],
        &[],
    );
    assert_eq!(out.code, 4, "{}", out.stderr);
    assert!(out.stderr.contains("abgelehnt"), "{}", out.stderr);
    assert!(
        !known_hosts_path(&home.dir).exists(),
        "nach fehlgeschlagener Anmeldung wird nichts gespeichert"
    );
}

#[test]
fn unknown_user_is_an_auth_failure() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-baduser");
    let key = sshd.key_plain_path();
    let t = format!("nobody-such-user@127.0.0.1:{}", sshd.port);
    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            &sshd.fingerprint,
            "-i",
            s(&key),
            "check",
            &t,
        ],
        &[],
    );
    assert_eq!(out.code, 4, "{}", out.stderr);
}

#[test]
fn options_may_follow_the_command() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-order");
    let key = sshd.key_plain_path();
    let out = run(
        &home.dir,
        &[
            "check",
            &target(&sshd),
            "--fingerprint",
            &sshd.fingerprint,
            "-i",
            s(&key),
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
}

#[test]
fn default_user_comes_from_the_environment() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-envuser");
    let key = sshd.key_plain_path();
    let t = format!("127.0.0.1:{}", sshd.port);
    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            &sshd.fingerprint,
            "-i",
            s(&key),
            "check",
            &t,
        ],
        &[("USER", &sshd.user)],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    // Ohne USER und ohne Benutzer im Ziel gibt es eine klare Fehlermeldung.
    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            &sshd.fingerprint,
            "-i",
            s(&key),
            "check",
            &t,
        ],
        &[],
    );
    assert_eq!(out.code, 64, "{}", out.stderr);
    assert!(out.stderr.contains("Benutzername"), "{}", out.stderr);
}

// ------------------------------------------------------------------ Schlüssel

#[test]
fn passphrase_from_environment_and_file() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-pass");
    let key = sshd.key_encrypted_path();
    let t = target(&sshd);
    let base = [
        "--fingerprint",
        sshd.fingerprint.as_str(),
        "-i",
        s(&key),
        "check",
        t.as_str(),
    ];

    let out = run(&home.dir, &base, &[("SSH_KEY_PASSPHRASE", KEY_PASSPHRASE)]);
    assert_eq!(out.code, 0, "{}", out.stderr);

    let out = run(&home.dir, &base, &[("SSH_KEY_PASSPHRASE", "falsch")]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("Falsche Passphrase"), "{}", out.stderr);

    let pass_file = home.dir.join("pass.txt");
    std::fs::write(&pass_file, format!("{KEY_PASSPHRASE}\n")).unwrap();
    let with_file = [
        "--fingerprint",
        sshd.fingerprint.as_str(),
        "-i",
        s(&key),
        "--passphrase-file",
        s(&pass_file),
        "check",
        t.as_str(),
    ];
    let out = run(&home.dir, &with_file, &[]);
    assert_eq!(out.code, 0, "{}", out.stderr);

    // Keine Quelle und kein Terminal: erklärende Fehlermeldung statt Hänger.
    let out = run(&home.dir, &base, &[]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("Passphrase"), "{}", out.stderr);
    assert!(out.stderr.contains("SSH_KEY_PASSPHRASE"), "{}", out.stderr);
}

#[test]
fn missing_or_invalid_key_files_are_explained() {
    let home = Scratch::new("cli-badkey");
    let missing = home.dir.join("gibt-es-nicht");
    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            FP_A,
            "-i",
            s(&missing),
            "check",
            "anna@127.0.0.1:1",
        ],
        &[],
    );
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("gibt-es-nicht") && out.stderr.contains("nicht lesbar"),
        "{}",
        out.stderr
    );

    let garbage = home.dir.join("garbage");
    std::fs::write(&garbage, "das ist kein Schlüssel").unwrap();
    let out = run(
        &home.dir,
        &[
            "--fingerprint",
            FP_A,
            "-i",
            s(&garbage),
            "check",
            "anna@127.0.0.1:1",
        ],
        &[],
    );
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("keine gültige OpenSSH-Schlüsseldatei"),
        "{}",
        out.stderr
    );

    // Ohne --identity wird ~/.ssh/id_ed25519 unter HOME gesucht.
    let out = run(
        &home.dir,
        &["--fingerprint", FP_A, "check", "anna@127.0.0.1:1"],
        &[],
    );
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains(".ssh/id_ed25519"), "{}", out.stderr);
}

// ------------------------------------------------------------- known_hosts-Datei

#[test]
fn a_broken_known_hosts_file_is_reported_with_the_line_number() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-brokenkh");
    let file = home.dir.join("kh");
    std::fs::write(&file, format!("{} {FP_A}\nkaputte zeile\n", label(&sshd))).unwrap();
    let key = sshd.key_plain_path();
    let out = run(
        &home.dir,
        &[
            "--known-hosts",
            s(&file),
            "-i",
            s(&key),
            "check",
            &target(&sshd),
        ],
        &[],
    );
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("Zeile 2"), "{}", out.stderr);
}

#[test]
fn custom_known_hosts_path_is_used() {
    let sshd = sshd_or_skip!();
    let home = Scratch::new("cli-customkh");
    let file = home.dir.join("meine").join("kh");
    let key = sshd.key_plain_path();
    let out = run(
        &home.dir,
        &[
            "--known-hosts",
            s(&file),
            "--accept-new",
            "-i",
            s(&key),
            "check",
            &target(&sshd),
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(file.exists());
    assert!(!known_hosts_path(&home.dir).exists());
}

// ------------------------------------------------------------ Bedienung, Fehler

#[test]
fn usage_errors_exit_with_64_and_help_with_0() {
    let home = Scratch::new("cli-usage");
    for args in [
        vec!["check"],
        vec!["check", "host:99999"],
        vec!["check", "::1"],
        vec!["--timeout", "0", "check", "h"],
        vec!["unbekannter-befehl"],
        vec![],
    ] {
        let out = run(&home.dir, &args, &[]);
        assert_eq!(out.code, 64, "{args:?}: {}", out.stderr);
    }
    for args in [vec!["--help"], vec!["check", "--help"], vec!["--version"]] {
        let out = run(&home.dir, &args, &[]);
        assert_eq!(out.code, 0, "{args:?}");
        assert!(!out.stdout.is_empty());
    }
}

#[test]
fn refused_connection_is_a_clear_error() {
    let home = Scratch::new("cli-refused");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ed25519_plain");
    let t = format!("anna@127.0.0.1:{port}");
    let out = run(
        &home.dir,
        &["--fingerprint", FP_A, "-i", s(&key), "check", &t],
        &[],
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("fehlgeschlagen"), "{}", out.stderr);
    let out = run(&home.dir, &["hostkey", &t], &[]);
    assert_eq!(out.code, 1, "{}", out.stderr);
}

#[test]
fn silent_server_hits_the_timeout() {
    let home = Scratch::new("cli-silent");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _holder = std::thread::spawn(move || {
        let _conn = listener.accept();
        std::thread::sleep(Duration::from_secs(20));
    });
    let key = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ed25519_plain");
    let t = format!("anna@127.0.0.1:{port}");

    let started = Instant::now();
    let out = run(
        &home.dir,
        &[
            "--timeout",
            "1",
            "--fingerprint",
            FP_A,
            "-i",
            s(&key),
            "check",
            &t,
        ],
        &[],
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("Zeitüberschreitung"), "{}", out.stderr);
    assert!(started.elapsed() < Duration::from_secs(10));

    let out = run(&home.dir, &["--timeout", "1", "hostkey", &t], &[]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("Zeitüberschreitung"), "{}", out.stderr);
}
