//! Canary test for the real binary: runs `lootr` with an empty environment
//! plus dummy secrets, `HOME` and the working directory in a temp dir (never
//! against the developer's real home), in every output mode, and fails if a
//! dummy secret or the canary shows up on stdout, stderr or in `--output`.

// Test code: the harness starts the binary under test (lootr itself never
// does) and may panic on setup errors.
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::unwrap_used
)]

use std::path::Path;
use std::process::{Command, Output};

use lootr::testing::find_leaks;

const TOKEN: &str = "acme_LOOTRCANARY_5f4dcc3b5aa765d61d8327deb882cf99";
const PASSWORD: &str = "correct-horse-LOOTRCANARY-battery";
const MULTILINE: &str = "line-one-LOOTRCANARY\nline-two-LOOTRCANARY\n";

const CONFIG: &str = r#"
version = 1

[[source]]
id = "env"
kind = "env"
names = ["*"]

[[type]]
name = "acme_api_key"
pattern = '^acme_[A-Za-z0-9_]{20,}$'

[[rule]]
id = "acme-key"
type = "acme_api_key"
when = "true"
severity = "high"
message = "ACME key in {location} ({length} bytes, {charset}, {entropy} bits)"
remediation = "Remove {name} from the environment"

[[rule]]
id = "long-env-value"
type = "env_var"
when = 'name != "HOME" && length > 16 && size(classified_as) == 0'
severity = "low"
message = "{name}: {length} bytes, {entropy} bits"

[[rule]]
id = "broken"
type = "env_var"
when = 'name == "MULTI" && entropy > "high"'
severity = "info"
"#;

fn run(dir: &Path, args: &[&str]) -> Output {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(dir.join("lootr.toml"), CONFIG).unwrap();
    Command::new(env!("CARGO_BIN_EXE_lootr"))
        .args(["--no-default", "--config", "lootr.toml"])
        .args(args)
        .env_clear()
        .env("HOME", &home)
        .env("ACME_TOKEN", TOKEN)
        .env("DB_PASSWORD", PASSWORD)
        .env("MULTI", MULTILINE)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn assert_no_leaks(what: &str, output: &str) {
    let leaks = find_leaks(output, &[TOKEN, PASSWORD, MULTILINE]);
    assert!(leaks.is_empty(), "{what}: {leaks:#?}\n{output}");
}

/// Every output format with every output flag.
const MODES: &[&[&str]] = &[
    &[],
    &["--emit-facts"],
    &["--quiet", "--emit-facts"],
    &["--redact-paths"],
    &["--summary-only"],
    &["--redact-paths", "--summary-only"],
    &["--format", "sarif"],
    &["--format", "sarif", "--redact-paths"],
    &["--format", "sarif", "--summary-only"],
    &["--format", "markdown"],
    &["--format", "markdown", "--redact-paths"],
    &["--format", "markdown", "--summary-only"],
    &["--format", "markdown", "--fail-on", "info"],
];

/// Parses the report of a run in any format; JSON and SARIF must parse.
fn check_format(args: &[&str], stdout: &str) {
    let format = args
        .iter()
        .position(|a| *a == "--format")
        .map(|i| args[i + 1])
        .unwrap_or("json");
    match format {
        "markdown" => assert!(stdout.starts_with("## lootr report\n"), "{stdout}"),
        "sarif" => {
            let v: serde_json::Value = serde_json::from_str(stdout).unwrap();
            assert_eq!(v["version"], "2.1.0");
            let run = &v["runs"][0];
            assert_eq!(run["tool"]["driver"]["name"], "lootr");
            assert_eq!(
                run.get("results").is_none(),
                args.contains(&"--summary-only"),
                "{args:?}"
            );
        }
        _ => {
            let v: serde_json::Value = serde_json::from_str(stdout).unwrap();
            assert_eq!(v["schema_version"], 1);
        }
    }
}

#[test]
fn the_binary_never_prints_secrets() {
    let dir = tempfile::tempdir().unwrap();
    for args in MODES {
        let out = run(dir.path(), args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        // `broken` orders an int against a string: a rule error, exit 2.
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert_no_leaks("stdout", &stdout);
        assert_no_leaks("stderr", &stderr);
        check_format(args, &stdout);
        if args.is_empty() || args.contains(&"--emit-facts") {
            let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(report["summary"]["findings"], 3, "{stdout}");
            assert_eq!(report["rule_errors"][0]["rule"], "broken");
        }
    }
}

#[test]
fn the_output_file_is_private_and_clean() {
    let dir = tempfile::tempdir().unwrap();
    for (format, name) in [
        ("json", "report.json"),
        ("sarif", "report.sarif"),
        ("markdown", "report.md"),
    ] {
        let mut args = vec!["--format", format, "--output", name];
        if format == "json" {
            args.push("--emit-facts");
        }
        let out = run(dir.path(), &args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        let path = dir.path().join(name);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_no_leaks(name, &text);
        check_format(&args, &text);
        assert_no_leaks("stderr", &String::from_utf8_lossy(&out.stderr));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

// ---- the built-in types and the default policy -------------------------------

const SSH_KEY: &str = include_str!("../test-envs/ssh/unencrypted/home/.ssh/dummy_id_ed25519");
const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoiYXBpIiwic3ViIjoiTE9PVFJDQU5BUlktc3ViamVjdCIsInNjb3BlIjoicmVhZDpwYWNrYWdlcyB3cml0ZTpwYWNrYWdlcyIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.LOOTRCANARY-Xq7Lm2Pz9Rk4Wt8Vn3Hb6Jc1Ds5Gf0";
const DOTENV_SECRET: &str = "LOOTRCANARY-q8Wn2Xc5Vb7Mz1Lk4Hs6Jd9Pf3Gt";

/// Standard base64 (Docker `auth` fields).
fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                A[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Credential files of every M3 document type and extractor in the temp
/// home and project. Returns the secret parts (from the canary on) that
/// must not show up anywhere. Well-known prefixes are concatenated at run
/// time, so the source never contains a whole dummy key.
fn credential_files(home: &Path, project: &Path) -> Vec<String> {
    let s = |name: &str| format!("LOOTRCANARY{name}0123456789abcdef");
    let akia = format!("{}{}", "AKIA", "LOOTRCANARY23456");
    let npm = format!("{}LOOTRCANARYcanaryNpmToken0123456789a", "npm_");
    let glpat = format!("{}{}", "glpat-", s("Gitlab"));
    let gho = lootr::testing::github_token("gho_", "LOOTRCANARYcanaryGhHosts012345");
    let ghp = lootr::testing::github_token("ghp_", "LOOTRCANARYcanaryGitCred012345");
    let pypi = format!("{}{}", "pypi-AgEIcHlwaS5vcmc", s("Pypi"));
    let hub = format!("{}{}", "dckr_pat_", s("Hub"));
    // Passwords with unencoded `#`, `?`, `/` (hand-edited git-credentials).
    let hostile = s("GitHostile");
    write(
        &home.join(".aws/credentials"),
        &format!(
            "[default]\naws_access_key_id = {akia}\naws_secret_access_key = {}\n",
            s("AwsSecret")
        ),
    );
    write(
        &home.join(".config/gcloud/application_default_credentials.json"),
        &format!(
            r#"{{"type":"service_account","project_id":"p","private_key":"-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n","client_email":"sa@p.iam.gserviceaccount.com"}}"#,
            s("GcpKey")
        ),
    );
    write(
        &home.join(".azure/msal_token_cache.json"),
        &format!(
            r#"{{"AccessToken":{{"k":{{"secret":"{JWT}"}}}},"RefreshToken":{{"r":{{"secret":"{}"}}}}}}"#,
            s("AzRefresh")
        ),
    );
    write(
        &home.join(".kube/config"),
        &format!(
            "apiVersion: v1\nclusters: []\nusers:\n- name: u\n  user:\n    token: {JWT}\n    password: {}\n",
            s("KubePw")
        ),
    );
    write(
        &home.join(".docker/config.json"),
        &format!(
            r#"{{"auths":{{"https://index.docker.io/v1/":{{"auth":"{}"}}}}}}"#,
            base64(format!("octo:{hub}").as_bytes())
        ),
    );
    write(
        &home.join(".npmrc"),
        &format!("//registry.npmjs.org/:_authToken={npm}\n"),
    );
    write(
        &home.join(".pypirc"),
        &format!("[pypi]\nusername = __token__\npassword = {pypi}\n"),
    );
    write(
        &home.join(".netrc"),
        &format!("machine example.org login u password {}\n", s("Netrc")),
    );
    write(
        &home.join(".git-credentials"),
        &format!(
            "https://u:{ghp}@github.com\nhttps://oauth2:{glpat}@gitlab.example\n\
             https://userLOOTRCANARY:{hostile}#{hostile}@github.com/x\n\
             https://userLOOTRCANARY:{hostile}?{hostile}@gitlab.example\n\
             https://userLOOTRCANARY:{hostile}/{hostile}@gitlab.example:8443\n\
             https://userLOOTRCANARY:1234#{hostile}@github.com\n"
        ),
    );
    write(
        &home.join(".config/gh/hosts.yml"),
        &format!("github.com:\n    oauth_token: {gho}\n    user: octo\n"),
    );
    write(
        &home.join(".cargo/credentials.toml"),
        &format!("[registry]\ntoken = \"{}\"\n", s("Cargo")),
    );
    write(&project.join("deploy/server.key"), SSH_KEY);
    write(
        &project.join(".github/workflows/ci.yml"),
        "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: make}]\n",
    );
    let mut secrets: Vec<String> = [
        "AwsSecret",
        "GcpKey",
        "AzRefresh",
        "KubePw",
        "Hub",
        "Netrc",
        "Cargo",
        "Pypi",
        "Gitlab",
        "GitHostile",
    ]
    .iter()
    .map(|n| s(n))
    .collect();
    secrets.extend([
        akia[4..].to_string(),
        npm[4..].to_string(),
        gho[4..].to_string(),
        ghp[4..].to_string(),
        base64(format!("octo:{hub}").as_bytes()),
    ]);
    secrets
}

/// A temp home with an SSH key and credential files of every type, a git
/// project with a `.env`, a key and a workflow, and tokens in the
/// environment; runs with the default config (probes off: they look at the
/// real machine). Returns the secrets to look for.
fn run_default(dir: &Path, args: &[&str]) -> (Output, Vec<String>) {
    let home = dir.join("home");
    let project = dir.join("project");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(home.join(".ssh/dummy_id_ed25519"), SSH_KEY).unwrap();
    let classic = lootr::testing::github_token("ghp_", "LOOTRCANARYcanaryTok0123456789");
    let app = lootr::testing::github_token("ghs_", "LOOTRCANARYcanaryApp0123456789");
    let openai = format!(
        "{}LOOTRCANARY0123456789T3BlbkFJLOOTRCANARY0123456789",
        "sk-proj-"
    );
    std::fs::write(
        project.join(".env"),
        format!("GH_TOKEN={classic}\nID_TOKEN={JWT}\nSECRET_KEY='{DOTENV_SECRET}'\n"),
    )
    .unwrap();
    // An embedded secret in a source file: exercises content scanning. The
    // GitLab token is not present anywhere else, so the finding can only come
    // from the `content` source (file.py#L<line>).
    let glpat = format!("{}{}", "glpat-", "LOOTRCANARYgitlabEmbedded01");
    write(
        &project.join("app.py"),
        &format!("def connect():\n    token = \"{glpat}\"\n    return token\n"),
    );
    let mut files = credential_files(&home, &project);
    files.push(glpat[6..].to_string());
    let common = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-envs/common.toml");
    let out = Command::new(env!("CARGO_BIN_EXE_lootr"))
        .arg("--config")
        .arg(&common)
        .args(args)
        .env_clear()
        .env("HOME", &home)
        .env("GITHUB_TOKEN", &app)
        .env("ID_TOKEN", JWT)
        .env("API_SECRET", PASSWORD)
        .env("OPENAI_API_KEY", &openai)
        .current_dir(&project)
        .output()
        .unwrap();
    let mut secrets: Vec<String> = SSH_KEY
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::to_string)
        .collect();
    secrets.extend([
        classic,
        app,
        JWT.into(),
        DOTENV_SECRET.into(),
        PASSWORD.into(),
        openai[8..].to_string(),
    ]);
    secrets.append(&mut files);
    (out, secrets)
}

#[test]
fn the_default_policy_never_prints_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let extra: &[&[&str]] = &[
        &["--fail-on", "info", "--emit-facts"],
        &["types"],
        &["explain", "github-classic-token"],
        &["explain", "workflow-write-all"],
        &["policy", "check"],
    ];
    for args in MODES.iter().chain(extra) {
        let (out, secrets) = run_default(dir.path(), args);
        let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        for (what, text) in [("stdout", &stdout), ("stderr", &stderr)] {
            let leaks = find_leaks(text, &secrets);
            assert!(leaks.is_empty(), "{args:?} {what}: {leaks:#?}\n{text}");
        }
        if args
            .first()
            .is_some_and(|a| ["types", "explain", "policy"].contains(a))
        {
            assert_eq!(out.status.code(), Some(0), "{stderr}");
            continue;
        }
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        check_format(args, &stdout);
        if args.contains(&"--redact-paths") {
            let home = dir.path().join("home");
            for text in [&stdout, &stderr] {
                assert!(!text.contains(&*home.to_string_lossy()), "{args:?}\n{text}");
                assert!(!text.contains(".ssh"), "{args:?}\n{text}");
            }
        }
        if args
            .iter()
            .any(|a| *a == "--format" || *a == "--summary-only")
        {
            continue;
        }
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let rules: Vec<&str> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["rule"].as_str().unwrap())
            .collect();
        for rule in [
            "ssh-key-unencrypted",
            "github-classic-token",
            "dotenv-token-not-gitignored",
            "dotenv-secret-not-gitignored",
            "github-token",
            "jwt-long-lived",
            "env-secret-like",
            "aws-long-lived-key",
            "gcp-service-account-key",
            "azure-cached-tokens",
            "kubeconfig-static-credentials",
            "docker-inline-credentials",
            "npmrc-inline-token",
            "pypirc-inline-token",
            "netrc-password",
            "git-credentials-store",
            "gh-token-in-file",
            "gitlab-token",
            "api-key",
            "config-secret-like",
            "pem-private-key-in-git-repo",
            "workflow-untrusted-trigger-default-permissions",
        ] {
            assert!(rules.contains(&rule), "{rule} missing: {rules:?}");
        }
    }
}

/// A secrets file given as config by mistake (`--config .env`, an include
/// of `~/.git-credentials`, `policy check`): exit 2, and the error names the
/// file and position but never echoes its content.
#[test]
fn config_errors_never_echo_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let ghp = lootr::testing::github_token("ghp_", "LOOTRCANARYcanaryCfgErr012345");
    write(
        &dir.path().join(".env"),
        &format!("GH_TOKEN={ghp}\nDB_PASSWORD={PASSWORD}\n"),
    );
    write(
        &dir.path().join("vars.toml"),
        &format!("version = 1\nDB_PASSWORD = \"{PASSWORD}\"\n"),
    );
    write(
        &home.join(".git-credentials"),
        &format!("https://alice:{PASSWORD}@github.com\n"),
    );
    write(
        &dir.path().join("inc.toml"),
        "version = 1\ninclude = [\"home/.git-credentials\"]\n",
    );
    let secrets = [ghp.as_str(), PASSWORD];
    for args in [
        &["--config", ".env"][..],
        &["--config", "vars.toml"],
        &["--config", "inc.toml"],
        &["policy", "check", ".env"],
        &["--format", "markdown", "--config", ".env"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_lootr"))
            .args(["--no-default"])
            .args(args)
            .env_clear()
            .env("HOME", &home)
            .current_dir(dir.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        for text in [&stdout, &stderr] {
            let leaks = find_leaks(text, &secrets);
            assert!(leaks.is_empty(), "{args:?}: {leaks:#?}\n{text}");
            assert!(!text.contains("alice"), "{args:?}\n{text}");
        }
        assert!(stderr.contains("line "), "{args:?}: {stderr}");
    }
}
