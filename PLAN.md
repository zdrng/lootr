# lootr — Plan

lootr shows what a process can reach with the rights of the current user when it runs without a
sandbox: SSH keys, cloud and registry credentials, tokens in environment variables and `.env`
files, CI workflow permissions, privilege-escalation paths. It does not stop at "this exists":
every artifact is interpreted into **facts** (e.g. `encrypted = false`, `bits = 2048`,
`kind = "classic"`), and a **policy** written in CEL decides what is acceptable. The result is a
structured report with location, type, severity and a remediation.

Target users: CI/CD pipelines (open source and companies) and companies that check developer
machines against their own policy.

lootr is itself an attack surface: it runs where the secrets are. Security of the tool comes
before features (see [Security model](#security-model)).

## Principles

- **One goal: collect facts and evaluate them against a policy.** lootr does not try to be clever
  about the environment. Which sources are scanned, what is excluded, what is acceptable: all of
  that is configuration. No hardcoded special cases (e.g. no built-in exclusion of `~/Documents`
  because of macOS permission prompts; a company that wants that writes it into its config).
- **Abstract and config-driven.** The binary knows **types** (how to recognize and interpret an
  SSH key, a GitHub token, a JWT, a kubeconfig, ...). The config says **where** values come from
  and **what** is acceptable. A GitHub token is evaluated the same way whether it sits in
  `$GH_TOKEN`, in a `.env` file or in `~/.config/gh/hosts.yml`.
- **Offline, read only.** No network, no subprocesses, no writes except the report. lootr never
  verifies a credential against its service (so e.g. GitHub token scopes are out of reach; that is
  accepted).
- **Pipes and filters.** Typed data flows through fixed stages; only the first stages touch the
  system, evaluation and report are pure functions.
- **Secrets never leave the collector.** Raw values are interpreted inside the collector and
  dropped; facts only carry derived, non-secret data.
- **Config is as trusted as code.** A config/policy runs with lootr's access to secret values (via
  custom patterns). Third-party policy packs must be reviewed like a dependency.
- **Simple.** Plain functions, blocking I/O, no async runtime, one binary crate with modules.
  Same conventions as `mendr` (Rust 2024, clap, serde, thiserror, Nix flake, report on stdout,
  progress on stderr).

## Non-goals

- Printing, storing or decrypting secret values.
- Network access of any kind: no online verification of tokens, no cloud metadata endpoint, no
  policy download.
- Accessing browser, keychain or password stores (no types for them).
- Fixing anything (`chmod`, rotation, ...). lootr recommends, it never changes the system.
- Being a compliance product (framework mappings, evidence collection, approval workflows).
  Rules may carry tags like `cis = "5.2.1"`, nothing more.
- Being a general server hardening audit (Lynis/OpenSCAP territory).
- A Turing-complete scripting layer. Rules are CEL expressions; anyone who needs more takes
  `--emit-facts` and processes the JSON elsewhere (jq, OPA, ...).

## How a run works

```
 Source ──► Extractor ──► Type ──► Fact ──► Policy (CEL) ──► Finding ──► Report
 env, file,  dotenv, yaml,  github_token,  attributes   rules per type   + waivers   JSON / SARIF /
 probe       json, ini …    ssh_key, jwt …                                            Markdown, exit code
 ───────────── collector: touches the system, sees secrets ─────────────   ──── pure functions ────
```

1. **Load config**: built-in default layer, then each `--config` layer in order. Validate
   everything: unknown types, CEL syntax, identifiers not in the type's schema → exit 2 before
   scanning.
2. **Discover** (sources): expand every source into candidates: env var names matching globs,
   file paths matching globs (no symlink follow, depth and size limits), probes.
3. **Collect**:
   - a file source with a **document type** (e.g. `ssh_private_key`, `kubeconfig`) opens the file
     securely, lets the type sniff it and parses it;
   - a file source with an **extractor** (e.g. `dotenv`) splits the file into named values;
   - every value (from env, extractor or a document type like kubeconfig) is run through the
     **value types** (`github_token`, `jwt`, custom regex types, ...) and always produces a
     generic fact for its container (`env_var`, `dotenv_entry`);
   - every result becomes a `Fact`; raw bytes are zeroized and dropped before the fact leaves.
4. **Evaluate**: for each fact, run the rules of its type (CEL), produce findings, apply waivers.
5. **Report**: render, write to stdout (or `--output`), set exit code.

## Architecture (layers)

```
 ┌──────────────────────────────────────────────────────────────┐
 │ presentation   cli/ (clap, wiring, exit codes)  report/      │
 ├──────────────────────────────────────────────────────────────┤
 │ service        scan pipeline: discover → collect → evaluate  │  depends only on repository
 │                (no I/O of its own, testable with fakes)      │  traits + domain
 ├──────────────────────────────────────────────────────────────┤
 │ repository     the data layer: every byte lootr sees comes   │  traits + real impls + fakes
 │                from here (files, env, process info, config)  │
 ├──────────────────────────────────────────────────────────────┤
 │ domain         model, SecretBuf, types (pure interpreters),  │  no I/O at all
 │                extractors, policy model                       │
 └──────────────────────────────────────────────────────────────┘
   os/ (infra): hardening, secure open — used only by repository impls and cli
```

Rules:
- Dependencies point downwards only. `domain` depends on nothing in the crate.
- Only `repository` implementations and `os` touch the system. The service layer receives
  repositories as trait objects / generics, so every service test runs on in-memory fakes.
- Types and extractors are pure functions over `SecretBuf` → they live in `domain` and are fuzzed
  directly.

### Module layout

```
src/
  main.rs                 entry: hardening, then cli::run
  lib.rs                  module tree (a lib target so fuzz targets and tests can call the pure parts)
  testing.rs              canary helpers (CANARY, find_leaks) for unit, integration and fixture tests
  cli/
    mod.rs                clap args, execute() (testable with fake repositories), exit codes
    progress.rs           cargo-style progress lines on stderr
    wiring.rs             builds real repositories, probe list, type registry
  report/
    mod.rs                Report model (format independent), summary, exit code, path mapping
    paths.rs              `~` normalization and --redact-paths (one mapper for every format and stderr)
    json.rs  sarif.rs  markdown.rs
  service/
    scan.rs               ScanService: runs the pipeline, returns ScanResult
    discover.rs           sources → candidates (env globs, path globs, probes, limits)
    collect.rs            candidate → SecretBuf → extractor / document type → value types → facts
    evaluate.rs           facts + rules → findings (rule selection, waivers, placeholders)
    cel.rs                CEL compile + schema check + evaluation (only sees facts)
    config.rs             ConfigService: layering, includes, locked rules, validation against type schemas
    default.toml          built-in default config layer (include_str!)
    git.rs                git work tree + .gitignore checks for file facts (reads via FileRepository)
    probe/                Probe trait + list of built-in probes; process.rs, unix_socket.rs
  repository/
    mod.rs                traits: FileRepository, EnvRepository, SystemRepository, ConfigRepository
    fs.rs                 real file access (secure open, walk, metadata) via os/
    env.rs                real process environment
    system.rs             uid, groups, sockets, /proc (probes)
    config.rs             reads config files (local only)
    fake.rs               in-memory implementations for tests
  domain/
    model.rs              Fact, AttrValue, Ident, PublicText, Location, Finding, Severity, FsError, Skipped (serde)
    secret.rs             SecretBuf / SecretSlice: fixed capacity, zeroize on drop, no Debug/Display/Serialize
    config.rs             config data structures (serde) and validated config (Source, Rule, Waiver)
    glob.rs               globs → linear-time regex, `~`/relative path expansion
    gitignore.rs          .gitignore patterns → globs (pure; files are read by service/git.rs)
    codec.rs              incremental base64 into SecretBuf, CRC32, base62
    template.rs           message placeholders
    time.rs               UTC dates (waiver expiry), RFC 3339 timestamps, hour differences
    types/
      mod.rs              DocumentType / ValueType traits, registry, attribute schemas, generic attributes
      custom.rs           regex-defined value types from config
      creds.rs            helpers shared by the credential-file types (inline_tokens, hosts, URL hosts)
      ssh_key.rs  github_token.rs  jwt.rs  aws.rs  gcp.rs  azure.rs  kubeconfig.rs  docker_config.rs
      npmrc.rs  pypirc.rs  netrc.rs  git_credentials.rs  gh_hosts.rs  pem.rs  github_workflow.rs
      gitlab_token.rs  api_key.rs   one file per type (aws.rs: aws_credentials + aws_access_key_id)
      waiver.rs           the `waiver` fact type (one fact per configured waiver, made by evaluate)
    extract/              Extractor trait; dotenv, ini, json, yaml, toml → (key, value)
    format/               shared parsers with limits: yaml.rs (bounded tree over saphyr-parser events),
                          json.rs (serde_json helpers, SecretValue, serde walker), ini.rs
  os/
    hardening.rs          core dumps off, PR_SET_DUMPABLE
    open.rs               O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC + fstat, directory listing, report file
fuzz/                     cargo-fuzz targets (separate workspace): ssh_key, jwt (+ github_token), dotenv,
                          yaml, json, ini, toml, lines (netrc, git_credentials, pem), values
tests/
  canary.rs               runs the binary (empty env, temp HOME) in every output mode, checks for leaks
  fixtures.rs             runs the binary against every test environment
  ci_files.rs             action/workflow files: actions pinned by SHA (or listed `TODO(pin)`), no `${{ }}`
                          in action scripts, release targets = action targets
  docs.rs                 docs/types.json == `lootr types --json` (LOOTR_UPDATE_DOCS=1 rewrites)
action.yml                GitHub Action (composite): download release, verify provenance, run, upload SARIF
.github/workflows/        ci.yml (checks, fuzz smoke, reproducible musl builds, containers), audit.yml
                          (daily), fuzz.yml (nightly, every target), release.yml (tags: build, attest, publish)
scripts/release.sh        reproducible release builds, archives, SBOM, checksums (in `nix develop .#release`)
supply-chain/             cargo-vet config, audits, imports
docs/                     threat model, config/CEL/report references, types.json, dependency review,
                          external review checklist
examples/
  company/                baseline (locked rules) + team layer + project waivers, README walkthrough
  ci/                     GitHub Actions and GitLab CI examples
test-envs/                fake homes/env with dummy artifacts + expected.json (fast, no containers);
                          common.toml (disables host-dependent probes for every env)
containers/               container scenarios (see below)
  base/Containerfile      builds lootr inside a Rust image, copies it into a slim runtime image
  base/entrypoint.sh      scenario hooks (setup as root, generated env file, drop to a user)
  base/gen-github-token   dummy GitHub tokens with valid checksums (POSIX sh, CRC32 via gzip)
  scenarios/<name>/
    Containerfile         FROM lootr-base; creates users, files, env, sockets for one environment
    lootr.toml            optional scenario config
    expected.json         expected findings
  run.sh                  builds base + scenarios, runs lootr in each container, diffs results
THIRD_PARTY.md            attribution for derived material (gitleaks token formats)
```

## Core concepts

### Sources

| Kind | Selects | Produces |
|---|---|---|
| `env` | variable names by glob/regex | one value per variable |
| `file` | paths by glob, `~` expanded, `exclude` honored | a document (with `type`) or values (with `extract`) |
| `probe` | built-in system checks by name (`process`, `unix_socket`, `proc_environ`, ...); optional `paths`/`exclude` globs and `path-vars` (env vars with directory lists, `PATH`) for probes that inspect file system objects (sockets, writable dirs/files) | facts directly |

### Types

Two kinds, both compiled into the binary (plus custom value types from config). The traits are
object safe (`&self`) so the registry can hold built-in and config-defined types alike; types work
on `SecretSlice`s (borrowed views into the `SecretBuf`, never copies):

```rust
trait DocumentType {                               // a whole file: ssh key, kubeconfig, workflow
    fn name(&self) -> &'static str;
    fn doc(&self) -> &'static str;
    fn schema(&self) -> &'static [AttrSpec];       // attribute names, value kinds, docs, optional
    fn sniff(&self, head: &[u8]) -> bool;          // cheap check on the first bytes
    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError>;
}                                                  // may emit facts and nested values (kubeconfig token → jwt)

trait ValueType {                                  // a single value: github token, jwt, aws key id
    fn name(&self) -> &str;
    fn doc(&self) -> &str;
    fn schema(&self) -> &[AttrSpec];
    fn classify(&self, value: SecretSlice<'_>) -> Option<Attrs>;  // format, prefix, checksum, structure
}

trait Extractor {                                  // splits a file into named values: dotenv, ini, ...
    fn name(&self) -> &'static str;
    fn entry_type(&self) -> &'static str;          // generic fact per entry: "dotenv_entry"
    fn extract<'a>(&self, doc: SecretSlice<'a>, out: &mut Vec<Entry<'a>>) -> Result<(), ParseError>;
}
```

`ParseError` carries only a `&'static str`, so it can never contain file content. Probes register
their fact types (`FactType { name, doc, schema }`) in the same registry. New types, extractors
and probes are registered in `Registry::builtin(now)` / `service::probe::builtin()` (`now` = scan
start, for time-dependent attributes such as JWT expiry; tests pass a fixed time).

File-based facts also get generic attributes from `FileMeta`: `mode`, `world_readable`,
`group_readable`, `owner_is_self`, `age_days`, `size`, plus the git context `in_git_repo` (a parent
directory has `.git`) and `gitignored` (the repository's `.gitignore` files and
`.git/info/exclude` ignore it; read without git; global excludes and the index are not
considered). In messages `{mode}` renders in octal (`0644`).

**Custom value types** from config only match by regex and get generic attributes (`length`,
`entropy`, `charset`). `entropy` is an integer: the estimated entropy of the value in bits (length ×
Shannon entropy per byte), so `entropy >= 128` reads as "looks like a 128-bit key":

```toml
[[type]]
name = "acme_api_key"
pattern = '^acme_[A-Za-z0-9]{32}$'
```

`lootr types` lists every type with its attributes, so policy authors know what they can use.

### Facts

```rust
struct Fact {
    type_: TypeName,                   // "github_token"
    location: Location,                // File { path, key_path? } | Env { name } | Probe { name }
    source: Ident,                     // config source id
    attrs: BTreeMap<&'static str, AttrValue>,
}

enum AttrValue {
    Bool(bool),
    Int(i64),
    Sym(&'static str),                 // closed vocabulary from the binary: "classic", "rsa", "write"
    Name(Ident),                       // validated identifier: env var names, permission scopes, job ids
    Text(PublicText),                  // non-secret text: JWT issuer, kube context name
    Path(DisplayPath),
    List(Vec<AttrValue>),
    Map(BTreeMap<Ident, AttrValue>),   // e.g. workflow permissions
}
```

How secrets are kept out:

- There is no plain `String` variant. `Sym` is `&'static str` and can only come from constants in
  the binary.
- `Ident` and `PublicText` have one constructor each, named `from_non_secret(...)`, length-capped
  (`Ident`: 1-128 bytes of `[A-Za-z0-9_-./:@+%]`; `PublicText`: 256 chars, control characters
  replaced, invisible Unicode format characters such as bidi overrides and zero-width spaces
  escaped visibly as `\u{202e}` (also in `DisplayPath` and Markdown code spans)).
  Every call is a visible review point; types that parse secret material (tokens, keys) may not
  call it on the secret part.
- **Canary test**: every test environment's secrets contain a canary string (`LOOTRCANARY`,
  `lootr::testing::CANARY`). A test runs all output formats plus `--emit-facts` and fails if a
  canary (or a substring of 8+ chars of any dummy secret) appears anywhere (`testing::find_leaks`;
  used by `cli` unit tests on fakes, `tests/canary.rs` on the real binary, and `containers/run.sh`).
- No hashes of secrets as facts (short tokens can be brute forced offline).

### Policy (CEL)

Rules are selected by type; `when` is a CEL expression over the fact's attributes plus
`location` (map: `kind` = `file`/`env`/`probe`, `path`, `key_path`, `name` as present), `source`
and `type`. Attributes are also available as the map `attrs`, because CEL's `has()` only works on
field selections: optional attributes are tested with `has(attrs.lifetime_hours)`.

- CEL is not Turing complete: no loops, no side effects, evaluation always terminates. It is used
  for the same purpose in Kubernetes admission policies, Google IAM and Envoy.
- Implementation: the `cel` crate (cel-rust), decided in M1, see below.
- At load time every expression is compiled and every referenced identifier is checked against
  the type's schema. Unknown attribute → config error with file, rule id and attribute.
- Runtime evaluation errors (e.g. type mismatch) are reported as `rule_error` and make the run exit
  2. They never silently pass.
- CEL only ever sees facts, never raw values.
- Load-time check (`service/cel.rs`): the compiled AST is walked; every free identifier must be an
  attribute of the type (incl. file attributes) or `type`/`source`/`location`/`attrs`, every
  `attrs.<x>` must name an attribute, comprehension variables are scoped to their macro, and only
  standard-library functions are allowed (`size`, `matches`, `contains`, `startsWith`,
  `endsWith`, conversions, ...).

**CEL engine decision (M1): `cel` 0.15 (github.com/cel-rust/cel-rust), `default-features =
false, features = ["regex"]`.**

- Candidates: `cel` (the maintained successor of `cel-interpreter`/`cel-parser`, which stopped
  at 0.10 in 2025), `cel-cxx` (FFI to the C++ implementation: needs a C++ toolchain and `unsafe`
  FFI, rejected), `rust-cel-parser` (parser only, a single 0.1 release).
- `cel`: MIT, actively maintained (releases through 2026), widely used (~4M downloads, used by
  `kube-cel`), pure Rust. With only the `regex` feature its dependencies are `antlr4rust` (BSD-3,
  parser runtime; pulls `parking_lot`, `uuid` with default features = `std` only and no RNG,
  `murmur3`, `typed-arena`, `bit-set`), `nom`, `lazy_static`, `pastey`, `serde`, `thiserror`,
  `regex`. No network, no async; dependency build scripts only probe the compiler (libc, rustix,
  serde, ...). `chrono`/`chrono-tz`/`base64` are avoided by disabling default features (no
  `timestamp`/`duration` in rules; dates are attributes like `age_days` instead).
- Regex engine: `matches()` uses the `regex` crate (linear time).
- Limits: `has()` needs a field selection (hence `attrs`); heterogeneous `==` returns `false`
  (CEL spec) while ordering across types (`<`, `>`) is an error (→ `rule_error`). The interpreter
  itself is not hardened against pathological expressions, so the load-time check bounds them
  (security review F5): at most 4096 bytes, bracket/unary nesting 32, AST depth 64,
  comprehensions nested at most 2 deep, list/map literals of at most 256 elements (≈256² steps per
  fact at worst). Config is trusted; the limits keep a mistake from hanging a CI job.

### Findings

```rust
struct Finding {
    rule: Ident,
    severity: Severity,                // info | low | medium | high | critical
    fact: Fact,
    message: String,                   // template rendered with placeholders
    remediation: String,
    tags: BTreeMap<Ident, Ident>,
    waived: Option<Waiver>,
}
```

Placeholders in `message`/`remediation`: `{path}`, `{name}`, `{type}`, `{rule}`, `{source}`,
`{location}` and any attribute of the type (`{{`/`}}` for literal braces; unknown placeholders are
config errors; a missing optional attribute renders as `-`). Without `message` the default is
`{type} at {location} matches rule {rule}`.

## Config

One file format (`lootr.toml`) for sources, custom types, rules and waivers. Layers are applied in
order: built-in default → `--config a.toml` → `--config b.toml` (e.g. company baseline, then
project).

```toml
version = 1

[scan]
max-file-size = "1MiB"
max-depth = 16
one-file-system = true
exclude = []                              # empty by default; e.g. ["~/Library/**"]

# ---- sources: where values come from -------------------------------------------

[[source]]
id = "process-env"
kind = "env"
names = ["*"]                             # every value is classified by the value types

[[source]]
id = "dotenv"
kind = "file"
paths = ["./**/.env", "./**/.env.*"]
extract = "dotenv"                        # each entry is classified like an env var

[[source]]
id = "ssh"
kind = "file"
paths = ["~/.ssh/*", "~/Documents/**"]    # a company that keeps keys in Documents adds it here
type = "ssh_private_key"                  # sniff() skips everything that is not a key

[[source]]
id = "workflows"
kind = "file"
paths = ["./.github/workflows/*.yml", "./.github/workflows/*.yaml"]
type = "github_workflow"

[[source]]
id = "process"
kind = "probe"
probes = ["process"]

[[source]]
id = "container-sockets"
kind = "probe"
probes = ["unix_socket"]
paths = ["/var/run/docker.sock", "/run/containerd/containerd.sock", "~/.docker/run/docker.sock"]

# ---- custom types ----------------------------------------------------------------

[[type]]
name = "acme_api_key"
pattern = '^acme_[A-Za-z0-9]{32}$'

# ---- rules: what is acceptable -----------------------------------------------------

[[rule]]
id = "ssh-key-unencrypted"
type = "ssh_private_key"
when = '!encrypted'
severity = "high"
message = "SSH private key {path} is not encrypted"
remediation = "Set a passphrase (ssh-keygen -p -f {path}) or move the key to ssh-agent / a hardware token"
tags = { cis = "5.2.x" }
locked = true                             # later layers may not disable, weaken or waive it

[[rule]]
id = "ssh-key-weak"
type = "ssh_private_key"
when = '(key_type == "rsa" && bits < 3072) || key_type == "dsa"'
severity = "medium"
remediation = "Create an ed25519 key and rotate {path}"

[[rule]]
id = "github-classic-token"
type = "github_token"
when = 'kind == "classic" && checksum_valid'
severity = "high"
message = "Classic GitHub token visible in {location}"
remediation = "Replace with a fine-grained token with minimal permissions"

[[rule]]
id = "jwt-long-lived"
type = "jwt"
when = 'has(attrs.lifetime_hours) && lifetime_hours > 24'
severity = "medium"

[[rule]]
id = "workflow-packages-write"
type = "github_workflow"
when = 'permissions["packages"] == "write" || default_permissions == "write-all"'
severity = "high"
remediation = "Set `permissions:` explicitly and grant packages: write only to the publishing job"

[[rule]]
id = "deploy-token-in-env"
type = "env_var"
when = 'name.matches("^(CI|DEPLOY)_.*TOKEN$") && length > 20'
severity = "low"

[[rule]]
id = "acme-key-anywhere"
type = "acme_api_key"
when = 'true'                             # the exposure itself is the finding
severity = "high"

# ---- accepted exceptions -------------------------------------------------------------

[[waiver]]
rule = "ssh-key-unencrypted"
path = "~/.ssh/ci_deploy"                 # glob; and/or `name = "ENV_VAR"` (env var / key path)
reason = "Hardware-bound deploy key, rotated weekly"
expires = 2027-01-31                      # expired waivers are ignored and reported
```

- **Layering**: a later layer can add sources/types/rules/waivers, override a source or rule by
  `id` (field by field: only the fields it sets; `tags` merged key by key) or disable it
  (`enabled = false`), unless the rule is `locked`. An override (no `kind`/`type`) of an id no
  earlier layer defines is a config error. A locked rule may only get a higher severity or a new
  message, remediation or tags from later layers; disabling, unlocking, changing `type`/`when`
  (whitespace aside) and lowering the severity are config errors that name the file, the rule, the
  locking layer and each attempted change. Only the locking layer may waive a locked rule (later
  and earlier layers may not). Custom types override by `name`. `[scan]` settings override one by
  one, `exclude` and `fail-on-skipped` lists are appended.
- **Locked inputs** (security review F4): a locked rule is only as strong as what it sees. Later
  layers may extend but not weaken (a) sources, custom types and `[scan]` marked `locked = true`
  and (b) implicitly everything a locked rule depended on in the locking layer: `[scan]`, every
  custom type, and every source that can produce facts of the rule's type (same document type,
  extractor entry type, env sources for `env_var`, probe sources for probe facts, every source
  for a value type). Weakening = disable/unlock, change kind/type/extract, drop a path/name/
  probe/path-var, add an exclude, change a pattern, lower `max-file-size`/`max-depth`, turn
  `one-file-system` on. Errors name the layer, the input and the lock. Consequence, documented
  in README and the config reference: policy that a pull request must not weaken has to come from
  outside the repository and lock what it enforces; an in-repository config (and its waivers) is
  controlled by every PR author.
- **Skipped entries are visible** (F7/F8/F9): nothing a source selects is dropped silently. Besides
  unreadable/special files: `depth_limit`, `other_fs` (directories the walk did not enter),
  `symlink_root` (a glob's literal prefix that is a symlink which may not be followed),
  `not_recognized` (a literally named file its document type does not sniff), `binary` and
  `truncated` (`content` scanner; foreign environments over 256 KiB). `[scan] fail-on-skipped =
  [reasons | "*"]` turns chosen reasons into a failed run (exit 1, `summary.failing_skipped`);
  config, not a flag, so the policy layer that needs it decides (and cannot be weakened: the list
  is only appended).
- **Waivers**: `rule` + optional `path` glob and/or `name`, `reason`, optional `expires` (UTC
  date). Expired waivers are ignored, listed in `expired_waivers`, warned about and reported as
  findings of the default rule `waiver-expired`; every waiver is also a `waiver` fact (see above).
- **Includes**: only local files, relative to the including file, applied as layers before the
  including file. No URLs; cycles and nesting deeper than 16 are errors.
- **Paths**: `~` = home, relative = current directory. Globs: `*`/`?` within one component (they
  match dotfiles), `**` any number of components, `[abc]`/`[!abc]`, `\x` literal. Compiled to
  `regex` (linear time).
- All config problems are collected and reported together (`<file>: rule `x`: ...`), exit 2.
- **CLI**: `--config <path>` (repeatable), `--no-default`, `--fail-on <severity>`,
  `--format json|sarif|markdown`, `--output <file>`, `--redact-paths`, `--summary-only`,
  `--emit-facts` (JSON only, not with `--summary-only`). Subcommands: `lootr types`,
  `lootr explain <rule>`, `lootr policy check [files]` (default + `--config` + files; reads only the
  config files, no env, no home: `~` in waiver paths expands to a placeholder).

Exit codes: 0 = no unwaived finding at or above `--fail-on` (default `high`), 1 = such findings
or a skipped entry with a `fail-on-skipped` reason, 2 = error (invalid config, rule error).

## Security model

### Threat model

| Threat | Countermeasure |
|---|---|
| Secret leaks via report, logs, debug output | Fact model without plain strings; `SecretBuf` without `Debug`/`Display`/`Serialize`; canary test |
| Secret leaks via core dump, ptrace | Process hardening at startup |
| lootr exfiltrates (bug or compromised dependency) | No network code in the binary, enforced by lints and `cargo-deny` |
| Malicious files in the scanned tree (symlink races, FIFOs, huge files, parser bombs) | Secure open, size/depth limits, fuzzed parsers |
| Malicious policy guessing secrets via many custom patterns (oracle) | Documented: config is as trusted as code; custom types are listed in the report header |
| Policy causing hangs | CEL terminates by design; regex crate is linear time |
| Supply chain attack on lootr releases | Few dependencies, audits, signed reproducible releases, pinned action |
| Report as a map for attackers | Path normalization, `--redact-paths`, `--summary-only` |

### Handling secrets in memory

- Raw bytes are read into a `SecretBuf` with fixed capacity allocated up front (bounded by
  `max-file-size`), so the buffer never reallocates and leaves no copies behind.
- `SecretBuf` uses `zeroize` (no `secrecy`: the wrapper adds nothing over a private field):
  zeroized on drop (whole capacity), access only through an explicit `expose()`, no trait that
  could print, serialize or clone it (enforced at compile time). Extractors hand out
  `SecretSlice`s of the same buffer, not copies. Env values are copied into a `SecretBuf` one at a
  time and the intermediate `OsString` is zeroized.
- Types read only what they need. SSH keys: the OpenSSH format stores cipher name, KDF and the
  **public** key before the encrypted part, so `encrypted`, `key_type` and `bits` come from
  non-secret bytes. PEM: header lines only. JWT: header and payload only, the signature is never
  decoded.
- Regex matching uses `regex::bytes` (linear time, no ReDoS) directly on the buffer.
- No memory locking (`mlock`) in v1: secrets live for milliseconds, macOS encrypts swap, most CI
  runners have no swap, and it would require `unsafe`.
- Honest limit, documented in the README: zeroizing is best effort. Kernel page cache and library
  internals may keep copies. The goal is to keep exposure minimal and short-lived.

### Process hardening (startup, before any file is opened)

- `setrlimit(RLIMIT_CORE, 0)`: no core dumps.
- Linux: `prctl(PR_SET_DUMPABLE, 0)`: no dumps, no ptrace by other processes of the same user.

### Secure file access

- `lstat` first (never open anything but a regular file: opening a device can have side
  effects), then `open` with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_NOCTTY`; afterwards `fstat`
  on the descriptor (not the path) to avoid TOCTOU. Only regular files are read; FIFOs, sockets,
  devices are reported by metadata only (`skipped` in the report, with a reason). `O_NOFOLLOW`
  covers the last component only; the `*_beneath` functions (M6) resolve the part below a
  source's trusted literal prefix component by component with `openat` + `O_NOFOLLOW`, so a
  symlink planted in a parent directory is refused (one swap between discover and collect
  remains, documented).
- Size check on the descriptor before reading; read at most `max-file-size`.
- Directory walk does not follow symlinks; `one-file-system` by default. Exceptions, each with
  checks (security review F6/F7/F10):
  - a glob's literal prefix whose **last** component is a symlink (`~/.ssh -> dotfiles/ssh`) is
    followed once, if the link belongs to the scanning user or root and points to a real,
    non-excluded directory; else it is reported as skipped (`symlink_root`). The prefix comes
    from the trusted config and its parent components are already resolved by the kernel, so
    this adds no new trust; reported paths keep the configured prefix;
  - `*_within` (Kubernetes projected volumes, `token -> ..data/token`): links are resolved with
    `openat`/`readlinkat` below a held directory fd and followed only while the target is
    relative and stays inside that directory (at most 8 links); anything else is `symlink`;
  - the `writable` probe judges a symlink's target with `stat` (nothing is opened).
- One file reached through two paths of a source (`/var/run` -> `/run`, hard links) is
  collected once, by `(dev, ino)` from `fstat`.
- Config files (trusted) may be symlinks but are `stat`ed first and opened `O_NONBLOCK`: only
  regular files up to 1 MiB, never a FIFO or device; the text is held in a `SecretBuf`. TOML
  errors show only position and a fixed description (never file text: a `.env` passed as
  `--config` must not land in a CI log).
- The report file: `lstat` first, then `O_CREAT | O_NOFOLLOW | O_NONBLOCK`, `fstat` again; an
  existing path must be a regular file of the effective user; `fchmod 0600` before truncating.
- Errors (permission denied, vanished files) are normal results, not failures: "not readable" is a
  fact too. Nothing selected is dropped silently: limits, partial scans and unfollowed prefixes
  are `skipped` entries with a reason, and `[scan] fail-on-skipped` can fail the run on them.

### Code rules (enforced in CI)

- `#![forbid(unsafe_code)]` for the whole crate. OS calls go through `rustix` (safe wrappers).
- `clippy.toml` `disallowed-methods` / `disallowed-types`: `std::process::Command`, `std::net::*`,
  `std::env::set_var`, `dbg!`, `println!`/`eprintln!` outside `main.rs` and `report/`.
- `#![deny(clippy::unwrap_used, clippy::expect_used)]` outside tests.
- `cargo-deny`: ban network and async crates (`reqwest`, `ureq`, `hyper`, `tokio`, `curl`, ...),
  GPL-3.0-compatible license allowlist, only crates.io as source, duplicate versions flagged.
- `cargo-audit` on every CI run and daily.
- Every parser and extractor has a fuzz target; YAML/JSON get depth and alias limits. Fuzzing runs
  on the flake's stable toolchain with `cargo fuzz run -s none <target>` (libFuzzer without
  AddressSanitizer, which needs nightly and adds little to a crate without `unsafe`); CI runs
  every target for 30 s.

### Supply chain and releases

- Minimal dependency set; every new dependency needs a reason in the PR.
- Static musl binaries (Linux), universal binary (macOS), reproducible builds.
- Signed with Sigstore/cosign, SLSA provenance, SBOM (CycloneDX).
- GitHub Action that downloads a release by version and verifies the signature; docs tell users to
  pin it by commit SHA.
- `SECURITY.md` with disclosure process.

### Release artifacts (contract between M5's action/examples and M7's release workflow)

Defined in M5 (`action.yml`, `examples/ci/`), produced by M7. A release for tag `v<version>`
(SemVer, `v` prefix) is built by `.github/workflows/release.yml` on GitHub-hosted runners and
has these assets:

| Asset | Content |
|---|---|
| `lootr-<version>-<target>.tar.gz` | directory `lootr-<version>-<target>/` with `lootr` (executable), `LICENSE`, `README.md`, `THIRD_PARTY.md` |
| `lootr-<version>-<target>.tar.gz.sigstore.json` | Sigstore bundle (v0.3) with the SLSA provenance v1 attestation of the archive (`actions/attest-build-provenance`), keyless, GitHub OIDC; the signing certificate names `https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v<version>` |
| `SHA256SUMS` | SHA-256 of every archive (for manual checks; the attestation binds the digest) |
| `lootr-<version>.cdx.json` (+ `.sigstore.json`) | CycloneDX SBOM (and its attestation) |

`<target>`: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `universal-apple-darwin`.
Download URL: `https://github.com/<owner>/<repo>/releases/download/v<version>/<asset>`.

Verification (the action does this before unpacking; it uses `gh`, falling back to `cosign`):

```sh
gh attestation verify lootr-<v>-<t>.tar.gz --bundle lootr-<v>-<t>.tar.gz.sigstore.json \
  --repo <owner>/<repo> --signer-workflow <owner>/<repo>/.github/workflows/release.yml \
  --source-ref refs/tags/v<v> --deny-self-hosted-runners
cosign verify-blob-attestation --bundle lootr-<v>-<t>.tar.gz.sigstore.json --new-bundle-format \
  --type slsaprovenance1 --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v<v> \
  lootr-<v>-<t>.tar.gz
```

One attestation is both the signature and the SLSA provenance (no separate `cosign sign-blob`
signature). Changing names, the archive layout or the signer workflow path breaks the action;
change `action.yml`, `examples/ci/` and this table together. Neither command has been run against
a real release yet (none exists): M7 must test the action end to end on a tag.

## Types (initial set)

Document types:

| Type | Key attributes |
|---|---|
| `ssh_private_key` | `format` (openssh/pem/pkcs8), `encrypted`, `cipher`, `kdf`, `kdf_rounds`?, `key_type`, `bits`? (absent where only secret bytes would tell: encrypted PEM/PKCS#8, PEM EC) |
| `pem` | `kind` (private_key/certificate/certificate_request/public_key/other: the most sensitive block), `encrypted` (all private keys), `private_keys`, `certificates`, `key_type`? |
| `aws_credentials` | `profiles`, `long_lived_keys` (`AKIA`), `session_keys` (`ASIA`), `secret_keys`, `sso_profiles`, `role_profiles`, `credential_process` (counted, never run); emits key id, secret key, session token as values |
| `gcp_credentials` | `kind` (service_account/authorized_user/external_account/external_account_authorized_user/impersonated_service_account), `account`? (service account e-mail), `project`?; emits private key, refresh token, client secret as values |
| `azure_profile` | `kind` (profile/msal_token_cache/legacy_token_cache/service_principals), `has_cached_tokens`, `access_tokens`, `refresh_tokens`, `service_principal_secrets`, `subscriptions`; emits cached tokens (→ `jwt`) and secrets as values |
| `kubeconfig` | `contexts`, `current_context`?, `clusters`, `users`, `static_tokens`, `token_files`, `basic_auth`, `client_certs`, `embedded_client_keys`, `exec_auth`, `exec_commands`, `auth_providers`, `insecure_skip_tls`; emits tokens, passwords, auth-provider tokens and exec env values as values (→ `jwt`) |
| `docker_config` | `inline_auths`, `hosts`, `creds_store`?, `cred_helpers`; emits the decoded password of `auth`, identity/registry tokens as values |
| `npmrc`, `pypirc`, `netrc`, `git_credentials`, `gh_hosts` | `inline_tokens`, `hosts` (+ `env_refs` for npmrc, `default_entry` for netrc); emit tokens/passwords as values (decoded where base64 or percent-encoded) |
| `github_workflow` | one fact per job (`jobs.<id>`): `job`, `triggers`, `permissions` (effective map scope → read/write/none), `write_scopes`, `default_permissions` (read-all/write-all/none/repository), `permissions_source` (job/workflow/repository) |

`?` = optional attribute (rules test it with `has(attrs.x)`).

Value types:

| Type | Key attributes |
|---|---|
| `env_var` / `dotenv_entry` / `config_entry` (generic, always) | `name`, `length`, `entropy`, `classified_as` (list of type names) |
| `github_token` | `kind` (classic/fine_grained/app/oauth/refresh), `prefix`, `checksum_valid`? (`gh?_` tokens of standard length) |
| `gitlab_token` | `kind` (access_token/oauth_app_secret/deploy/runner/runner_registration/ci_job/trigger/feed/incoming_mail/agent/scim/feature_flags_client), `prefix` |
| `aws_access_key_id` | `kind` (long_lived `AKIA` / session `ASIA`) |
| `jwt` | `alg`, `issuer`?, `audience`?, `scopes`?, `expires_in_hours`?, `lifetime_hours`?, `expired` |
| `api_key`: well-known API keys (Slack, Stripe, OpenAI, Anthropic, npm, PyPI, Docker Hub, Google, SendGrid, Hugging Face, DigitalOcean, Shopify, HashiCorp Vault, Terraform Cloud, RubyGems) | `service`, `kind`, `live`? (Stripe); no format has a checksum lootr can verify |
| custom (`[[type]]` in config) | `length`, `entropy`, `charset` |

Probes:

| Type | Key attributes |
|---|---|
| `process` | `uid`, `is_root`, `groups` (all group names; docker/lxd/disk/wheel/sudo/admin matter), `in_container` |
| `unix_socket` | `kind` (docker/containerd/podman/buildkit/other), `accessible` (from mode + groups, no connect), `rootful`, `owner_is_self`, `mode`, `group`; at the source's `paths` |
| `proc_environ` | `foreign_processes`, `readable_environ`, `names` (comm of readable foreign processes); values classified → `github_token`/`jwt`/… at `probe:proc_environ:<name>` (Linux) |
| `writable_path_dir` | `dir`, `writable`, `world_writable`, `group_writable`, `owner_is_self`, `mode` (PATH dirs, shared caches) |
| `writable_file` | `writable`, `world_writable`, `group_writable`, `parent_writable`, `parent_world_writable`, `parent_group_writable`, `owner_is_self`, `mode` (shell rc, git hooks) |
| `suid_binary` | `setuid`, `setgid`, `owner_is_root`, `owner_is_self`, `writable`, `world_writable`, `mode`, `capabilities` (Linux file caps) |
| `kube_service_account` | `namespace`?, `has_ca`; the token is classified → `jwt` |

Config facts (made by the evaluate step, not by a source):

| Type | Key attributes |
|---|---|
| `waiver` | one fact per configured waiver, at `<config file>#[[waiver]] #n`: `waived_rule`, `reason`, `expires`?, `expired`, `expires_in_days`?, `matched` (findings it waived in this run), `waived_path`?, `waived_name`? |

The built-in default config ships sources and rules for these types at their standard locations.
It is just a config layer: `--no-default` replaces it.

## Test environments

`test-envs/<group>/<name>/` contains a fake home (`home/`), optional `workdir/`, `env.toml`
(environment variables, file modes, `.git` dirs to create, renames, sockets to create, extra
args, machine-dependent attributes to ignore), optional `lootr.toml` and `expected.json` (the
normalized report with `--emit-facts`). `tests/fixtures.rs` copies the environment into a temp
dir, runs the binary with `HOME` pointed at the fake home and an empty environment plus
`env.toml`, applies `test-envs/common.toml` (disables the host-dependent probe sources) before the
environment's `lootr.toml`, checks stdout/stderr for leaks and diffs the report;
`LOOTR_UPDATE_FIXTURES=1` rewrites `expected.json`.

Dummy secrets are generated once (`ssh-keygen`, `openssl`), committed, clearly marked (`DUMMY —
test only`, file names `dummy_*`), carry the canary string where the format allows it (SSH key
comments, JWT signatures and unread claims, token random parts). Never real secrets. Tokens with a
checksum are **not** committed in valid form: `{{github_token:<prefix>:<random>}}` placeholders
are expanded by the harness (`lootr::testing::github_token`), so secret scanners never see a
checksum-valid token. Other well-known formats are written as `{{token:<prefix>:<rest>}}` (split at
the last `:`, so no whole `AKIA…`, `sk_live_…`, `xoxb-…` is committed) and base64 auth fields as
`{{base64:<a>:<b>}}`; other `{{…}}` text (workflow expressions) is left alone. `env.toml`
`secrets = [...]` adds encoded secrets to the leak check, which also takes, in every file, the text
from each canary to the end of its token. Container scenarios concatenate prefixes at build time.

Unit tests for services run against the fake repositories (in-memory files, env, uid).

### Container scenarios

Real environments (Linux users, groups, file modes, sockets, root vs. non-root, `/proc`) cannot
be faked convincingly and must not be tested on the developer's machine. `containers/` holds one
scenario per environment:

- `containers/base/Containerfile`: multi-stage; builds lootr in a Rust image, copies the binary into
  a slim Debian runtime image (`lootr-base`). No host toolchain needed.
- `containers/scenarios/<name>/Containerfile`: `FROM lootr-base`; sets up the environment. Dummy
  secrets are generated at build time (`ssh-keygen`, `openssl`, `gen-github-token`), so no keys
  are committed for container tests. Hooks in `/usr/local/lib/lootr-scenario/`: `setup` (runs
  first, e.g. as root to create sockets, which cannot live in an image layer), `env` (generated
  `KEY=value` lines exported to lootr); `LOOTR_SCENARIO_USER` drops to a user with `setpriv`.
- `containers/run.sh [scenario...]`: works with `podman` or `docker` (auto-detected), builds the base
  and the scenarios, runs `lootr --format json` inside each container as the scenario's user,
  normalizes the output (timestamps, versions, `age_days`, `expires_in_hours`,
  `expires_in_days`, and `size` because generated keys vary by a few bytes) and diffs it against
  `expected.json`. Also greps the output for the canary, and runs every scenario again as SARIF,
  Markdown, `--redact-paths` and `--summary-only` (same exit code, no canary, valid structure, no
  home directory when redacted). Scenario images build with the repository root as context; an
  `args` hook appends arguments (e.g. `--config` layers). Exit code ≠ 0 if any scenario fails.
  `--update` rewrites `expected.json`.

Scenarios (grow with the milestones): `clean-user` (nothing to find), `ssh-keys`, `ci-runner`
(GitHub Actions–like env with tokens, workflows), `docker-group` (user in `docker` group with
socket), `root`, `dotenv-project`, `cloud-creds`, `kubernetes-pod` (service account token),
`company-policy` (layered config with locked rules and waivers), `procfs` (foreign process
environ readable), `hostile-files` (symlink loops, FIFOs, huge files, deep trees, YAML bombs).

## License

GPL-3.0-only (like Lynis). Anyone may use lootr, also commercially and on company machines;
distributed modifications must stay GPL. Dependencies must be GPL-3.0-compatible (MIT, Apache-2.0,
BSD, ISC, Zlib, MPL-2.0, ...), enforced by `cargo-deny`. Pattern sets taken from other projects
(e.g. gitleaks, MIT) keep their attribution in `THIRD_PARTY.md`.

## Milestones

### M0 — Setup
- [x] `git init`
- [x] `cargo init` (edition 2024), `.gitignore`, `license = "GPL-3.0-only"`, `LICENSE`
- [x] Nix flake (Rust toolchain, `cargo-deny`, `cargo-audit`, `cargo-fuzz`)
- [x] Lints: `#![forbid(unsafe_code)]`, `clippy.toml` with disallowed methods/types, deny `unwrap`/`expect`
- [x] `deny.toml`: banned crates (network/async), GPL-compatible license allowlist, crates.io only
- [x] CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny check`, `cargo audit`
- [x] Scheduled CI: `cargo audit` daily
- [x] `README.md` (goal, non-goals, honest limits), `SECURITY.md`
- [x] Layered skeleton: `cli/`, `report/`, `service/`, `repository/`, `domain/`, `os/` with module docs
- [x] `containers/base/Containerfile` + `containers/run.sh` (podman/docker auto-detect) + `clean-user` scenario

### M1 — Secure core
- [x] `model.rs`: `Fact`, `AttrValue`, `Ident`/`PublicText` (`from_non_secret`), `DisplayPath`, `Location`, `Finding`, `Severity`
- [x] `secret.rs`: `SecretBuf` (fixed capacity, zeroize on drop, sub-slices, no Debug/Display/Serialize) + tests
- [x] `os/hardening.rs`: process hardening (core dumps off, `PR_SET_DUMPABLE`)
- [x] `os/open.rs`: secure open (`O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, `fstat` on fd, regular files only, size limit)
- [x] `repository/`: `FileRepository`, `EnvRepository`, `SystemRepository`, `ConfigRepository` traits, real impls, in-memory fakes
- [x] `types/mod.rs`: `DocumentType`/`ValueType` traits, registry, attribute schemas, generic file attributes
- [x] `config.rs`: sources, custom types, rules, waivers; layering, includes, validation with readable errors
- [x] Review and pick the CEL crate (dependencies, maintenance, regex engine, license)
- [x] `service/cel.rs`: compile, schema check of identifiers, evaluation over facts, `rule_error`
- [x] `service/evaluate.rs` + `service/config.rs`: rule selection per type, override/disable by id, `locked`, waivers with expiry, placeholders
- [x] `discover.rs`: env globs, path globs, `~`, excludes, depth limit, no symlink follow, one-file-system
- [x] `collect.rs`: document types, extractors, value classification, generic `env_var` facts
- [x] `report/json.rs`: versioned report schema (`schema_version`, tool version, run info, custom types used, findings, summary)
- [x] CLI + exit codes, progress on stderr
- [x] Canary test harness
- [x] Unit tests with `FakeEnv` for discover, collect, policy

Notes from M1 (for later milestones):
- Already done beyond M1: custom regex types (`types/custom.rs`), the generic `env_var` type,
  `--fail-on`, `--output` (mode 0600, no symlink), `--emit-facts` (adds a `facts` array to the
  report; M4 may still change its shape), `--quiet`.
- The built-in default layer (`service/default.toml`) only has the `process-env` source; M2 adds
  sources and rules for the new types.
- Test-only types (`test_doc`, `test_token`, extractor `lines`) live in
  `domain/types/mod.rs::test_types` / `domain/extract/mod.rs::test_extractors`.
- `ScanService` reports stage lines through the `service::scan::Progress` trait; `cli::execute`
  takes all repositories (`cli::wiring::Deps`), so whole runs are unit tested on fakes.

### M2 — First types and default policy
- [x] `ssh_private_key`: OpenSSH header parser (public part only), PEM/PKCS#8 header detection
- [x] `env_var` (generic), `github_token` (prefixes + CRC32 checksum), `jwt` (header/payload only), custom regex types
- [x] `dotenv` extractor → `dotenv_entry` + value classification; git repo / `.gitignore` check without git subprocess
- [x] Probes: `process`, `unix_socket` (docker/containerd/podman, access from mode + groups)
- [x] Built-in default config (sources + rules), embedded with `include_str!`
- [x] `lootr types`, `lootr explain <rule>`
- [x] Fuzz targets: ssh key, jwt, dotenv
- [x] Test envs: `ssh/unencrypted`, `ssh/encrypted-ed25519`, `ssh/weak-rsa`, `ssh/in-documents` (custom source), `env/github-tokens`, `env/jwt`, `env/custom-type`, `dotenv/committed`, `docker-socket`
- [x] `tests/fixtures.rs` harness
- [x] Container scenarios: `ssh-keys`, `ci-runner`, `docker-group`, `root`, `dotenv-project`

Notes from M2 (for later milestones):
- Deviations: probe sources take `paths`/`exclude` (socket locations are config, not code; the
  `unix_socket` probe only looks at the matched paths); `in_git_repo`/`gitignored` are generic
  file attributes (every file fact, not only dotenv entries); extra attributes beyond the tables
  above are listed with `lootr types`. `SystemRepository` gained `euid()` and `group_name()`
  (from `/etc/group` only, never NSS). `{mode}` renders in octal.
- SSH keys: OpenSSH bodies are decoded only up to the end of the first public key; PEM/PKCS#8
  only up to the public modulus / algorithm identifier (`domain::codec::Base64Reader` decodes on
  demand). A test replaces the OpenSSH private section with invalid base64 to prove it.
- GitHub token checksum: CRC32 of the 30 random characters, base62 `0-9A-Za-z`, zero padded to 6.
  This follows the published format description but was not verified against a real (revoked)
  token, since lootr's tests must stay offline; verify before relying on `checksum_valid` in
  locked policy. Fine-grained tokens have no `checksum_valid`.
- JWT: header and the registered claims (`iss`, `aud`, `exp`, `iat`, `nbf`, `scope`/`scp`) only.
  Issuer, audience and scopes are reported as text by design, so test data must not put the
  canary there (the `ci-runner` scenario caught exactly that in a dummy token).
- Default policy: 18 rules (`lootr explain <id>`); a secret-name heuristic for env/dotenv values
  that no type classifies (`env-secret-like`, `dotenv-secret-*`). Nothing is locked.
- M3: new document types plug into the same sources; kubeconfig/gh_hosts can emit nested values
  (`Emitter::value`/`owned_value`) that are classified by `github_token`/`jwt` automatically.

### M3 — Cloud, developer credentials, CI
- [x] `aws_credentials` / AWS config, `aws_access_key_id`
- [x] `gcp_credentials`, `azure_profile`
- [x] `kubeconfig` (YAML with depth/alias limits), emits tokens as values
- [x] `docker_config`: inline auths vs `credsStore` / `credHelpers`
- [x] `npmrc`, `pypirc`, `netrc`, `git_credentials`, `gh_hosts`, `pem`
- [x] `github_workflow`: effective permissions per job, triggers
- [x] Value types: `gitlab_token`, well-known API key formats
- [x] Extractors: `ini`, `json`, `yaml`, `toml` for custom file sources
- [x] Default rules for all of them
- [x] Fuzz target per parser/extractor
- [x] Test env per type
- [x] Container scenarios: `cloud-creds`, `kubernetes-pod` (extended in M6)

Notes from M3 (for later milestones):
- **YAML: `saphyr-parser` 0.1** (MIT/Apache-2.0, pure Rust, no `unsafe` in its sources; deps
  `arraydeque` (MIT/Apache, a small ring buffer with `unsafe` internals) and `thiserror`). Rejected:
  `serde_yaml` (archived, `unsafe-libyaml` = C translated to unsafe Rust), `serde_yml` /
  `serde_norway` (same libyaml lineage), `yaml-rust2` (more dependencies; its loader copies the
  anchored subtree for every alias, i.e. expands aliases before lootr could limit them). saphyr-parser only emits events, so
  `domain/format/yaml.rs` builds the tree with lootr's own limits: depth 64, 100 000 nodes, at most
  64 documents, and aliases are references (a DAG) whose **expanded** size is summed while
  building: more than 200 000 expanded nodes is a parse error (billion laughs fails fast, see
  `test-envs/kube/alias-bomb`); a recursive alias is an error. saphyr hands out owned strings; the
  loader keeps a slice of the file where the span equals the value and wipes the string,
  otherwise moves it into a `SecretBuf`. Measured worst cases at 1 MiB: < 1 s for all five YAML
  consumers together.
- **JSON: `serde_json`** (present; recursion limit 128). Types deserialize into their own structs;
  secret fields are `format::json::SecretValue` (borrowed slice when unescaped, wiped copy
  otherwise), unknown fields are skipped without copying. **TOML: `toml`** (present; nesting
  limit ~80, `visit_borrowed_str` / owned strings moved into `SecretBuf`). **INI** (AWS, pypirc,
  npmrc, gradle, `ini` extractor) and netrc/git-credentials: own small parsers (no crate needed;
  never fail, values are slices). Parser error messages (which can quote input) are always
  replaced by static `ParseError` text. Best effort: serde_json/saphyr scratch buffers are not
  wiped.
- Deviations: well-known API keys are **one** value type `api_key` with `service` + `kind` (one rule
  covers them all; services can be singled out); no format got `checksum_valid` (none documented
  precisely enough: npm/Grafana/GitLab checksums were left out on purpose). `gitlab_token` kinds
  follow GitLab's prefix table: `glpat-` is `access_token` (personal, project and group tokens share
  it). The four config extractors share one entry type `config_entry`; extractor keys are dotted
  paths (`section.key`, `a.b.0.c`) with characters an `Ident` cannot hold replaced by `_`; more than
  10 000 entries per file is a parse error. `Entry::value` is a `NestedValue` (escaped JSON/TOML/YAML
  strings are wiped copies). Document types may emit facts with zero counts (e.g. `.npmrc` without
  tokens): the file exists, rules decide. `pem` reuses the `ssh_private_key` parser per private key
  block. `github_workflow` models `read-all`/`write-all` as every scope read/write (`id-token` has no
  read, `models` no write level), an explicit map (also `{}`) as unlisted scopes `none`, and no
  `permissions` anywhere as `permissions_source = "repository"` with an empty map (the repository
  default is not visible offline). YAML 1.1 booleans (`yes`/`on`) count as true where Kubernetes
  reads them.
- Default config: 23 sources, 62 rules (`lootr explain <id>`). Sources: `pem` (`./**/*.pem`,
  `./**/*.key`, client TLS dirs; not `~/.ssh`), `aws`, `gcp`, `azure`, `kubeconfig`,
  `docker-config` (also Podman's `~/.config/containers/auth.json`), `npmrc` (home and project),
  `pypirc`, `netrc`, `git-credentials`, `gh-hosts`, `workflows`, and extractor sources for cargo
  (toml), Terraform and Composer (json), RubyGems and Yarn (yaml), Gradle (ini). Credential values
  inside documents are classified by the value types, so e.g. a `ghp_` token in `.netrc` or a
  Docker `auth` reports as `github-classic-token`; document-level rules report storage (plain text,
  readable by others, committed). Nothing is locked.
- `containers/run.sh` now fails on an empty report (an image ending in `USER x` cannot `setpriv`).
  `kubernetes-pod` copies the projected service account token to
  `/var/run/secrets/kubernetes.io/serviceaccount/` in its `setup` hook (`/run` is a tmpfs); the
  default config does not read it yet (M6), the scenario covers it through the job's kubeconfig.
- Open for later: the service account token file source (M6); `~/.docker/config.json`
  `proxies` / `HttpHeaders`, `pip.conf` / `settings.xml` / URL-embedded credentials
  (`https://user:pw@host` as a value type); Podman's `$XDG_RUNTIME_DIR/containers/auth.json` (needs
  env-derived paths); the `pem`, `npmrc` and `yarnrc` sources walk `./**` separately (discovery
  does not share walks between sources).

### M4 — Company policies
- [x] Layering edge cases: override chains, `locked` violations as config errors with clear messages
- [x] Waivers: path globs, expiry, expired waivers reported as their own finding
- [x] `lootr policy check <files>`: validate without scanning (for policy repos in CI)
- [x] `--emit-facts`: raw facts as JSON for external tools
- [x] Rule tags in report (e.g. `cis`, internal control ids)
- [x] Example company setup in `examples/` (baseline + team override + waivers)
- [x] Container scenario: `company-policy`

Notes from M4 (for later milestones):
- Locks: tested over four layers (default → baseline → team → project) and over the real default
  layer (`credential-file-readable-*`). Messages: `<file>: rule \`x\` is locked by <layer>; this
  layer tries to disable it (\`enabled = false\`), change its condition from \`a\` to \`b\`, lower
  its severity from high to low. ...`. Deviation: waivers for a locked rule are allowed only in the
  locking layer itself (also rejected from *earlier* layers, so a wrong layer order cannot slip a
  waiver in); waivers in files *included* by the locking file count as other layers. Overrides of
  unknown ids are errors; `tags` merge per key instead of being replaced.
- Expired waivers as findings: every waiver becomes a `waiver` fact after the other facts were
  evaluated (so `matched` is known) and runs through the rules of type `waiver`. Default rule
  `waiver-expired` (low); the company example adds `waiver-without-expiry` and `waiver-unused`.
  `expired_waivers` (now with the path glob as written) and the stderr warning stay.
- `policy check` prints layers, locked rules (with the locking layer) and waivers with days left;
  expired waivers are warnings, not errors (exit 0). `explain` shows `locked yes (by <layer>)`.
- `--emit-facts` kept its shape (`facts` in the JSON report, now also `waiver` facts, paths
  `~`-normalized); documented in `report/json.rs` and the README. It requires `--format json`.
- Tags: every default rule has a `category` tag from a fixed own vocabulary (no CIS numbers: none
  verified). `summary.by_rule` was added to the JSON summary (layout-compatible, `schema_version`
  stays 1 since nothing is released).
- `company-policy` builds from the repository root (all scenarios do now) and copies
  `examples/company/`; the example's waiver dates are far in the future (2030) except one expired
  on purpose, because fixtures and scenarios run on the real clock.

### M5 — Output and CI integration
- [x] SARIF output (GitHub code scanning)
- [x] Markdown output (PR comments, job summary)
- [x] `--redact-paths`, `--summary-only`, `~` normalization of paths
- [x] `--fail-on <severity>` (done in M1)
- [x] GitHub Action (download release, verify signature, run, upload SARIF)
- [x] Examples: GitHub Actions, GitLab CI

Notes from M5 (for later milestones):
- Paths are mapped once in `Report::new` (`report/paths.rs`), so JSON, SARIF, Markdown and the
  stderr lines agree. `~` normalization is always on (`run.home` stays absolute); CEL, waivers and
  messages are rendered with absolute paths first and mapped afterwards (the location path is
  replaced in the rendered text). `--redact-paths` keeps working-directory paths as `./rel`,
  numbers all others (`~/<redacted:1>`), redacts everything when cwd is `/`, home or above home.
- SARIF: written with `serde_json::json!` (no new dependency). Structure is checked by a test-only
  validator against the 2.1.0 schema's required/allowed properties, enums, URI syntax and
  `ruleIndex`/`uriBaseId` references (`report::sarif::tests::check_sarif`), used on unit samples
  and on full default-policy runs; `containers/run.sh` checks SARIF with jq. Not validated with a
  full JSON-schema engine (no schema download, no new dependency). Non-repository files use
  absolute `file://` URIs; GitHub only displays results with repository files.
- Markdown escapes by putting every value from scan or config into code spans (mentions, links,
  HTML in PR comments are not possible).
- The action uses no third-party actions at all (SARIF upload via `gh api` to the code scanning
  REST endpoint, category via `automationDetails.id`), so nothing needed a SHA; the examples pin
  `actions/checkout` with the SHA already used in CI. Placeholders left (marked TODO): the
  action's own `OWNER/lootr@<sha>` and `version` in `examples/ci/github-actions.yml`; in
  `examples/ci/gitlab-ci.yml` the release, cosign version + SHA-256 and the image digest.
  The action runs lootr twice (SARIF, then Markdown) when both are enabled.
- Open for M6: the privilege-escalation and lateral probes (`proc_environ`, writable `PATH`
  dirs/rc files/git hooks, SUID/capabilities, service account token source), the `openat`-based
  walk for parent-directory symlink races, content scanning of arbitrary files, the
  `hostile-files` and `procfs` scenarios. Redaction of attribute text (issuers, context names) is
  not done; reconsider if M6 adds path-like text attributes (use `AttrValue::Path` for them, which
  is mapped).
- Canary coverage: `tests/canary.rs` runs 13 format/flag modes (plus `types`, `explain`,
  `policy check`) on the test config and the default policy; `cli` unit tests run every format ×
  flag on fakes with the SARIF validator; `containers/run.sh` runs every scenario in 7 extra modes.

### M6 — Privilege escalation and lateral visibility
- [x] `proc_environ`: readable `/proc/<pid>/environ` and `cmdline` of other processes (Linux)
- [x] `writable_path_dir`, writable shell rc files, writable git hooks
- [x] SUID/SGID binaries and file capabilities in configured paths
- [x] Kubernetes service account token (`/var/run/secrets/kubernetes.io/...`, → `jwt`)
- [x] Content scanning of arbitrary files with value types (embedded secrets in source code)
- [x] Shared cache dirs in CI (cache poisoning surface)
- [x] Container scenarios: `procfs`, `hostile-files`

Notes from M6 (for later milestones):
- **Reading foreign process memory is within the promise.** lootr already reads
  secrets from files and the environment into memory to interpret them; a foreign
  process's `/proc/<pid>/environ` (readable only for the same user, when the target
  is dumpable) is the same kind of read, and being able to do it is exactly the
  lateral-visibility finding. As with files, the content is interpreted in memory
  only: its **values** are classified by the value types (so another job's GitHub
  token is found) but the content never becomes a fact. The `proc_environ` summary
  fact reports counts and the readable processes' `comm` names only; per-value facts
  are located at `probe:proc_environ:<name>` (the process name, or its pid if it has
  none — reports never carry the volatile pid). `cmdline` is not read: it rarely
  holds secrets that `environ` does not and would add noise.
- **`SystemRepository` grew** `pid()`, `processes()` (pids + `comm` from `/proc`) and
  `read_proc_environ()` (via a new `os::open::read_proc`, because `/proc` files report
  size 0 and cannot go through the size-bounded regular read). `ProbeContext` now
  carries the type `registry`, so a probe that reads a secret value (`proc_environ`,
  `kube_service_account`) classifies it through the value types with
  `service::probe::classify_value` — the same path `collect` uses for env vars.
- **Writability** is judged from mode, owner and groups (never by writing), like the
  `unix_socket` probe. The `writable` probe emits a `writable_path_dir` fact for a
  directory and a `writable_file` fact for anything else (with the writability of its
  parent directory, since a writable directory lets a file be replaced). It only emits
  a fact when the object is writable by someone other than its owner (world/group), so
  an ordinary private rc file or a root-owned PATH dir produces nothing. PATH dirs,
  shared CI caches, shell rc files and git hooks are all **config paths** over this one
  probe, not special cases in code. Discovery hands a probe source every matching path
  **including directories** (file sources never get directories) plus the absolute
  entries of its `path-vars` (`PATH`, read through the `EnvRepository` and taken as
  literal paths; empty/relative/non-UTF-8 entries are dropped, `exclude` applies).
- **SUID/SGID** come from the mode bits; **file capabilities** from the
  `security.capability` xattr via `rustix::fs::lgetxattr` (Linux only, gated by `cfg`;
  macOS reports only the setuid/setgid bits, documented). lootr deliberately does not
  inventory every system binary (a non-goal: Lynis/OpenSCAP territory); the default
  `suid` source points at the directories untrusted code can reach, and the probe only
  emits a fact for a setuid/setgid binary or one carrying capabilities.
- **Kubernetes service account token** is a `kube_service_account` **probe** (not a
  document type: it reads the sibling `namespace` and `ca.crt` next to the `token`).
  The source's `paths` point at the token file (a matching directory is ignored).
  The token is classified → `jwt`, so a long-lived/non-expiring bound token is caught by
  the ordinary `jwt` rules; namespace and CA presence are facts.
- **Content scanning** is the `content` extractor over configured globs. It tokenizes
  each line (runs of `[A-Za-z0-9_.+/~-]`; `=`/`:` split runs), skips binary files (NUL in
  the first 8 KiB), honours `max-file-size`, and — unlike the other extractors — emits no
  generic fact per run (`Extractor::generic_entry` → `false`), only the runs a value type
  recognized, located at `file#L<line>`. So an embedded GitHub token in `app.py` is a
  `github_token` fact at `app.py#L2` and is caught by the existing token rules.
- **`openat` walk (hardening).** `os::open` gained `read_dir_beneath` / `read_regular_beneath`
  / `metadata_beneath`: they open a source's trusted literal prefix (`root`) by path, then
  resolve the relative part component by component with `openat` and `O_NOFOLLOW | O_DIRECTORY`,
  so a symlink planted in any parent directory below `root` is refused, not followed. `discover`
  threads `root` into each candidate and `collect` reads through these; the `FileRepository`
  trait has default `*_beneath` methods (path-join) so the in-memory fake is unchanged. This
  closes the parent-directory race the earlier milestones left open (the last-component-only
  limit). `#![forbid(unsafe_code)]` holds (rustix `openat` is a safe wrapper).
- Default config grew to **31 sources** and these rules: `proc-environ-readable`,
  `writable-path-dir-world`, `writable-cache-dir-group`, `writable-startup-file`,
  `suid-sgid-writable`, `suid-not-root-owned`, `file-capabilities`,
  `kube-service-account-token` (`lootr explain <id>`). `common.toml` disables the probes
  that read the real machine (`proc-environ`, `path-dirs`, `suid`, `kube-service-account`)
  for the host fixtures; the `~`/`./`-only writable sources stay on.
- New fuzz target `content`. New container scenarios `procfs` and `hostile-files`.
- Open for later: foreign `cmdline` parsing; reading file capabilities on macOS; a real
  device-node case in `hostile-files` (needs CAP_MKNOD); threading an open fd from
  `discover` to `collect` to close the last discover→collect race (collect re-resolves
  from `root` with `openat`, so only a swap between the two stages remains, documented).

### M7 — Release hardening and 1.0
- [x] Static musl builds (x86_64, aarch64), macOS universal binary (built and checked locally;
      the release workflow has not run on GitHub yet)
- [ ] Reproducible builds verified in CI (partial: verified locally for all three targets; the CI
      job in `ci.yml` and the double build in `release.yml` are written but have never run)
- [ ] cosign signatures, SLSA provenance, CycloneDX SBOM (asset names and verification as in
      "Release artifacts"; test `action.yml` end to end on the first tag) (partial: workflow
      written, SBOM generated locally; attestation and the action test only run on GitHub;
      `actions/attest-build-provenance` is a `TODO(pin)`)
- [ ] Continuous fuzzing on a schedule (partial: `fuzz.yml` written; it cannot start until
      `actions/upload-artifact` is pinned, `TODO(pin)`)
- [x] `cargo-vet` (or equivalent review record) for all dependencies
- [x] Threat model document, report/config/CEL reference documentation
- [ ] External review before 1.0 (checklist: `docs/review-checklist.md`)

Notes from M7 (for later milestones):
- **Release toolchain:** `nix develop .#release` (`flake.nix`): official Rust 1.98.1 binaries
  via `oxalica/rust-overlay` (pinned in `flake.lock`, version pinned explicitly) with the std of
  all four targets, GNU tar/gzip, coreutils, `cargo-cyclonedx` 0.5.9 from nixpkgs. A
  `mkShellNoCC`, but rust-overlay's toolchain still brings Nix's clang on macOS, so
  `scripts/release.sh` sets the linkers explicitly: `rust-lld` for musl (bundled self-contained
  musl crt/libc: static on any host, no C toolchain, cross-arch works), `/usr/bin/cc` (Xcode) for
  both Darwin targets (only `/usr/lib/libSystem.B.dylib` and `/usr/lib/libiconv.2.dylib`; with
  Nix's cc the binary would reference `/nix/store`). `MACOSX_DEPLOYMENT_TARGET=11.0` (the Nix
  shell would leak 14.0). x86_64 musl is static-pie, aarch64 musl static (rustc defaults).
- **Reproducibility:** `[profile.release]` gained `debug = false`, `strip = true` (with the
  existing `codegen-units = 1`, `lto`, `panic = "abort"`); the script adds `--locked`,
  `CARGO_INCREMENTAL=0`, `--remap-path-prefix` for source dir → `/lootr`, target dir → `/target`,
  cargo home → `/cargo` (most specific last: the last matching flag wins), and on macOS
  `-C link-arg=-Wl,-S`: without it ld64 hashes the debug map (absolute object paths) into
  `LC_UUID` before rustc strips, so two directories gave different binaries (48 bytes: UUID +
  code signature). Archives: `tar --sort=name --format=gnu --mtime=@$SOURCE_DATE_EPOCH --owner=0
  --group=0 --numeric-owner`, modes set by `install`, `gzip -9 -n`. Nix shells force
  `SOURCE_DATE_EPOCH=315532800`, so the script takes `LOOTR_SOURCE_DATE_EPOCH` (the release
  workflow passes the commit time) or the last commit time first. `scripts/release.sh reproduce`
  builds twice from copies in `…/a/src-a/lootr` and `…/bb/src-bb/lootr` (different path
  lengths) with separate target dirs and compares SHA-256. The SBOM is deterministic too (its
  timestamp is `SOURCE_DATE_EPOCH`).
- **Verified locally** (aarch64-darwin host, podman): both musl targets and the universal binary
  reproduce bit for bit; `file`: static(-pie), stripped; `readelf`: no `INTERP`, no `NEEDED`;
  `ldd` (Debian): "not a dynamic executable" / "statically linked"; the aarch64 binary runs in
  `debian:trixie-slim` (`--version`, `types`), the x86_64 one in `alpine` (amd64 emulation);
  `lipo`: x86_64 + arm64, `minos 11.0`, `LC_UUID` present; the arm64 slice runs on the host
  (`--version`), the x86_64 slice was not run (no Rosetta). No host paths in the binaries
  (`strings`). Workflows: `actionlint` (with shellcheck) clean, all YAML parses (PyYAML).
- **release.yml** (on `v*` tags): `check` (tag = Cargo.toml version, fmt/clippy/test/deny/vet),
  `build` matrix (both musl on `ubuntu-24.04` via rust-lld, universal on `macos-15`; each runs
  `reproduce` and a smoke test: static, only `/usr/lib` dylibs, `--version` and `policy check`
  under `env -i` with an empty HOME), `sbom`, then `publish` (the only job with `contents: write`,
  `id-token: write`, `attestations: write`; runs no build code): `SHA256SUMS`, one
  `attest-build-provenance` call per archive and for the SBOM, bundles copied to
  `<asset>.sigstore.json`, every bundle verified with the action's exact `gh attestation verify`
  call, then `gh release create --verify-tag` (prerelease for `-` versions). Finally `action`
  runs `uses: ./` with `repository: ${{ github.repository }}` on `ubuntu-24.04`,
  `ubuntu-24.04-arm` (public repositories) and `macos-15` against the published release:
  the end-to-end test of the contract (exit code 0 or 1 accepted, Markdown report must exist).
  The SBOM gets a build provenance attestation (not an `attest-sbom` binding to the archives);
  it covers all platforms (`--target all`, a superset of the release targets) incl. build deps.
- **Pinning:** no SHA was looked up online. Reused: `actions/checkout`, `cachix/install-nix-action`.
  `TODO(pin)` (all-zero SHA, the workflow fails until filled in):
  `actions/attest-build-provenance`, `actions/upload-artifact`, `actions/download-artifact`
  (`tests/ci_files.rs::pin_placeholders_are_listed` keeps the list exact). Dependabot cannot
  update a zero SHA: fill them in by hand.
- **fuzz.yml:** nightly and on demand, a matrix over `cargo fuzz list` (all targets), 20 min each
  (`-timeout=10 -rss_limit_mb=2048`), crash inputs uploaded on failure; no corpus persistence
  (fuzz/corpus is gitignored). The CI smoke run now also loops over `cargo fuzz list` (it missed
  `content`).
- **cargo-vet** 0.10.2 (added to the dev shell): `cargo vet init` worked offline; 93 exemptions,
  no imports (fetching audit sets needs the network: see `docs/dependencies.md`). `cargo vet
  --locked` runs in CI and before a release. `docs/dependencies.md` is the human review record of
  the direct dependencies (purpose, license, `unsafe` counts, build-time code).
- **Docs:** `docs/threat-model.md`, `config-reference.md`, `cel.md` (every example rule passes
  `lootr policy check`), `report-schema.md`, `types.json` (+ `tests/docs.rs`), `dependencies.md`,
  `review-checklist.md`; README links them.
- **Found while documenting (open, not fixed in M7):**
  - `~` normalization compares strings: with a symlinked HOME/cwd (macOS `/var` vs
    `/private/var`) paths stay absolute.
  - `namespace` is a CEL reserved word: rules must write `attrs.namespace`
    (`kube_service_account`).
  - Env source `names` take globs only (the table above says glob/regex); `optional.of/none` are
    allowlisted but rejected at load time; invalid regex literals in `matches()`, non-bool `when`
    results and `attrs["x"]` lookups are only caught at run time (`rule_error`), not by
    `policy check`; a waiver's `name` also matches the file name of whole-file facts.
  - SARIF has no `automationDetails` (the action adds it); `Finding.waived` is an
    `AppliedWaiver { reason, expires }`; `examples/company/README.md` still says 23 sources /
    65 rules (now 31 / 71).
- Open: pin the three actions, push the first tag (e.g. `v0.1.0`) and watch `release.yml`
  end to end; fill the placeholders in `examples/ci/` (owner, SHA of the action, versions,
  cosign SHA-256, image digest); `cargo vet import` audit sets; the external review.

### Later
- [ ] Windows (ACLs, `%USERPROFILE%`; Credential Manager excluded per non-goals)
- [ ] Isolation module (sandbox/container detection), coordinated with mendr
