# Threat model

lootr runs where the secrets are: on developer machines and in CI jobs, with the rights of the
user whose credentials it inventories. It reads SSH keys, tokens, cloud credentials and other
processes' environments in order to interpret them. A bug in lootr, a compromised dependency or a
tampered release can therefore expose exactly what lootr is meant to protect. This document
describes what lootr protects, against whom, how (as built, M0 to M7), and what remains open.

Related: [SECURITY.md](../SECURITY.md) (reporting), [config-reference.md](config-reference.md),
[report-schema.md](report-schema.md), [dependencies.md](dependencies.md),
[review-checklist.md](review-checklist.md).

## Assets

| Asset | Where it lives during a run |
|---|---|
| Secret values (key material, tokens, passwords, env values) | Scanned files, the process environment, `/proc/<pid>/environ` of the user's other processes; inside lootr only in `SecretBuf`s |
| Facts derived from secrets (format, length, entropy, checksum validity, issuer, expiry) | Reports, stdout/stderr |
| The map of where credentials are (paths, env var names, users, groups) | Reports, job summaries, code scanning |
| The integrity of the scanned system | lootr writes nothing but the report |
| The integrity of the lootr binary that users run | GitHub releases, the GitHub Action |

## Trust boundaries and actors

| Actor | Trusted? | Notes |
|---|---|---|
| The user running lootr | yes | lootr has their rights, nothing more |
| Config / policy files (`--config`, includes) | **as trusted as code** | A policy can define regex types that test secret values (an oracle) and can disable rules. Third-party policy packs must be reviewed like a dependency |
| Scanned files and directory trees | **untrusted** | May be planted by an attacker: symlink races, FIFOs, devices, huge files, parser bombs, deep trees |
| Environment values, foreign process environments | **untrusted content** | Read and classified, never printed |
| Readers of the report (PR comments, job summaries, code scanning, ticket systems) | partially | May see paths and attribute text; must never see secrets |
| Other local users | untrusted | Must not gain access through lootr (no dumps, no ptrace on Linux, report written `0600`) |
| root, the kernel, the hypervisor | out of scope | Can read lootr's memory at any time |
| Dependencies (crates) | reviewed, pinned | Locked versions, `cargo-deny`, `cargo-audit`, `cargo-vet` |
| Toolchain, GitHub, Sigstore, the runner image | trusted | See [Release integrity](#release-integrity) |

## Threats and countermeasures (as built)

| # | Threat | Countermeasure | Verified by |
|---|---|---|---|
| T1 | Secret leaks via report, logs, error or debug output | `Fact` has no plain string variant: `Sym` (static), `Ident`/`PublicText` only via `from_non_secret`, `DisplayPath`; `SecretBuf`/`SecretSlice` have no `Debug`/`Display`/`Serialize`/`Clone`; `ParseError` carries only `&'static str`; parser error messages that could quote input are replaced (config TOML errors too: position and a fixed description only, so a `.env` passed as `--config` is not echoed); credential URLs are split by one parser, so user info never becomes a host or key path; invisible Unicode format characters (bidi overrides, zero-width) are escaped visibly in report text; `println!`/`eprintln!` only in `main.rs`/`report/` (clippy) | Canary test over every format and flag (`tests/canary.rs`, incl. hostile `.git-credentials` lines and secrets files given as config, `cli` unit tests on fakes, every container scenario in 7 modes); fixture tests check stdout/stderr for any 8-byte substring of a dummy secret |
| T2 | Secrets reconstructable from facts | No hashes of secrets as facts; JWT signature never decoded; SSH/PEM parsers decode only public parts; `entropy` is an integer estimate | Unit tests (invalid base64 in the private section is never touched) |
| T3 | Secret leaks via core dump or ptrace | `RLIMIT_CORE = 0`; Linux `PR_SET_DUMPABLE = 0` before any file is opened (`main.rs`); failure is fatal | Code review only: no automated test checks that the limits take effect (review item) |
| T4 | Secrets linger in memory | Fixed-capacity `SecretBuf` (no reallocation copies), zeroized on drop over the whole capacity; env values copied one at a time and the `OsString` wiped; extractors hand out slices, not copies | Unit tests in `domain/secret.rs` |
| T5 | lootr exfiltrates (bug or compromised dependency) | No network code: clippy `disallowed-types/methods` (`std::net`, Unix sockets), `cargo-deny` bans HTTP/TLS/async/subprocess crates (also transitively); no subprocesses (`std::process::Command` disallowed); `#![forbid(unsafe_code)]` in lootr itself | CI: clippy `-D warnings`, `cargo deny check` |
| T6 | Malicious files in the scanned tree | `lstat` first, only regular files are opened (`O_NOFOLLOW \| O_NONBLOCK \| O_CLOEXEC \| O_NOCTTY`), `fstat` on the descriptor, size checked before reading, at most `max-file-size`; walk never follows symlinks, `max-depth`, `one-file-system`; below a source's literal prefix every component is resolved with `openat` + `O_NOFOLLOW`; a symlinked literal prefix is followed once only if owned by the user or root and pointing to a real directory; projected-volume links (`*_within`) only while they stay inside their directory; config files and the report path are never FIFOs/devices (`stat` first, `O_NONBLOCK`); the report is `fchmod 0600` and must be the user's regular file | `hostile-files` scenario (symlink loops, FIFOs, huge files, deep trees, YAML bombs), `os/open.rs` tests |
| T7 | Parser bombs and crashes | YAML: depth 64, 100 000 nodes, 64 documents, 200 000 expanded alias nodes, aliases kept as references; JSON recursion limit 128; TOML nesting limit; 10 000 entries per file; own INI/netrc parsers never fail | Fuzz targets for every parser and extractor (30 s each per CI run, 20 min each nightly), `test-envs/kube/alias-bomb` |
| T8 | Policy causing hangs | CEL has no loops; load-time limits on expression size, nesting, comprehension depth (2) and literal sizes (256) bound the cost per fact; `matches()` and custom types use the linear-time `regex` crate; globs compile to `regex` | Unit tests |
| T9 | Malicious policy guessing secrets (oracle) | Documented: config is as trusted as code; custom types are listed in the report header (`custom_types`) | - |
| T10 | Wrong results pass silently | Every config problem is an error (exit 2) before scanning; unknown attributes are load-time errors; runtime rule errors are reported (`rule_errors`) and exit 2; nothing a source selects is dropped silently: limits (`depth_limit`, `other_fs`), partial scans (`binary`, `truncated`), unfollowed prefixes (`symlink_root`) and unrecognized literal files are `skipped` entries, and `[scan] fail-on-skipped` fails the run on chosen reasons | Unit tests, `lootr policy check`, `hostile-files` and `kubernetes-pod` scenarios |
| T11 | Weakened company policy | `locked` rules: later layers cannot disable, unlock, change `when`/`type` or lower severity; only the locking layer may waive them. Their inputs are locked too: sources, custom types and `[scan]` marked `locked`, and implicitly everything a locked rule depends on (`[scan]`, custom types, sources that can produce its type) cannot be disabled, repointed, excluded or limited by later layers. Documented: an in-repository config is controlled by every PR author; enforced policy must come from outside the repository | Unit tests over four layers (incl. the review's bypasses), `company-policy` scenario |
| T12 | Report as a map for attackers | `~` normalization of paths, `--redact-paths`, `--summary-only`; the action redacts by default; report file created `0600`, never through a symlink | Unit tests, container scenarios (no home directory in redacted output) |
| T13 | lootr modifies the system | Writes only the report (`os::open::create_report`); `std::fs::write`/`File::create` disallowed elsewhere | clippy |
| T14 | Tampered release or action | See [Release integrity](#release-integrity) | `tests/ci_files.rs`, release workflow |

## Release integrity

Built in M7 (`.github/workflows/release.yml`, `scripts/release.sh`, `flake.nix`):

- **Pinned toolchain.** Releases are built in `nix develop .#release`: the official Rust release
  binaries (version pinned in `flake.nix`, content hashes in `flake.lock`) with the standard
  libraries of all release targets, GNU tar/gzip and `cargo-cyclonedx` from the pinned nixpkgs.
- **Static Linux binaries.** `x86_64-unknown-linux-musl` (static-pie) and
  `aarch64-unknown-linux-musl` (static) are linked by `rust-lld` against the toolchain's bundled
  musl: no host C library or linker is involved.
- **macOS universal binary.** Both architectures are linked by the runner's Xcode (`/usr/bin/cc`),
  merged with `lipo`; the binary references only `/usr/lib/libSystem.B.dylib` and
  `/usr/lib/libiconv.2.dylib` (checked in the workflow). Deployment target macOS 11.
- **Reproducible.** `--locked`, one codegen unit, LTO, stripped, `--remap-path-prefix` for the
  source, target and cargo home directories, no build script, no timestamps; macOS links with
  `-Wl,-S` so the linker's UUID does not depend on object file paths. Archives have sorted
  entries, owner 0/0, fixed modes, mtime = commit time, `gzip -n`. Every release build is done
  twice from two copies of the source in different directories and must be bit for bit equal;
  CI does the same for both Linux targets on every push.
- **Provenance and signature.** One Sigstore bundle per asset (`<asset>.sigstore.json`) with a
  SLSA v1 provenance attestation from `actions/attest-build-provenance`, keyless via GitHub
  OIDC. It binds the archive digest to this repository, `release.yml` and the tag. The publish job
  verifies every bundle with the same `gh attestation verify` call the action uses before it
  creates the release, and the action is then tested end to end against the published release.
- **SBOM.** CycloneDX 1.5 (`lootr-<version>.cdx.json`, all platforms, with build dependencies)
  with its own provenance bundle.
- **Least privilege in CI.** Workflows default to `contents: read`; only the `publish` job (which
  runs no build code) can write, sign and attest. Checkouts do not persist credentials. Third-party
  actions are pinned by commit SHA (`tests/ci_files.rs` enforces it).
- **The action** verifies the bundle (`gh attestation verify`, fallback `cosign
  verify-blob-attestation`) before unpacking anything, never passes its token to lootr, and puts
  inputs into scripts only through the environment (no `${{ }}` in scripts, enforced by a test).

## Residual risks and known limits

Accepted by design:

- **Zeroizing is best effort.** The process environment block, the kernel page cache, and scratch
  buffers inside `serde_json`/`saphyr-parser` (unescaping) may keep copies. So may the `toml`
  crate's owned strings: the `toml` extractor's keys and values pass through them, and so does a
  secrets file passed as `--config` by mistake (lootr reads it into a `SecretBuf`, but the parser
  copies keys and values into ordinary `String`s before it fails). No `mlock` (would need
  `unsafe`; secrets live for milliseconds).
- **macOS:** no unprivileged equivalent of `PR_SET_DUMPABLE` without `unsafe`; only core dumps are
  disabled. A same-user debugger with the developer-tools permission can attach.
- **root and the kernel** can read lootr's memory.
- **Config is code.** A malicious config can probe secrets through custom regex types and report
  the answer through which rules fire. The CEL interpreter itself is not hardened; lootr's
  load-time limits bound expression size, nesting and comprehension depth. Whoever can edit a
  layer controls it: a config in the scanned repository (and its waivers) is controlled by the
  pull request author, so enforced policy must come from outside the repository and lock what it
  enforces (rules and, implicitly, their inputs).
- **The literal prefix is trusted.** Symlinks in a glob's literal prefix are resolved by the
  kernel (and its last component is followed once, with owner and target checks). For
  cwd-relative patterns (`./.github/workflows/*.yml`) part of that prefix lies in the checkout,
  so a symlinked directory in an untrusted repository can point a source at another directory of
  the user. Only non-secret facts and paths come out of it.
- **One discover/collect race remains:** a symlink swapped into a parent directory between the
  two stages is refused (collect re-resolves from the trusted prefix with `openat`), but an
  ordinary file replaced in that window is read.
- **Unsafe code in dependencies.** `#![forbid(unsafe_code)]` covers lootr only; `rustix`, `libc`,
  `linux-raw-sys`, `hashbrown`, `memchr`, `regex-automata`, `arraydeque`, `cel`, `antlr4rust` and
  others contain `unsafe` (see [dependencies.md](dependencies.md)). Fuzzing runs without
  AddressSanitizer (stable toolchain), so memory errors in dependencies would only show as
  crashes.
- **Exemptions, not audits.** `cargo vet` records every dependency as an exemption
  (`supply-chain/config.toml`); no third-party audit sets are imported yet.
- **Report content.** `--redact-paths` hides paths, not env var names, key paths, attribute text
  (JWT issuers, kube context names) or messages built from them. `~` normalization compares
  strings: when `HOME` or the working directory are reached through a symlink (e.g. macOS
  `/var` vs `/private/var`), paths may stay absolute and include the user name.
- **No verification against services.** Token scopes, revocation and real checksums (beyond the
  GitHub CRC32, itself only tested on generated dummies) are unknown.

Release-specific:

- **Trust in GitHub and Sigstore.** The provenance proves that the archive was built by
  `release.yml` at the tag on a GitHub-hosted runner, not that the source is benign. A
  compromised maintainer account that can push tags can publish a validly attested release.
- **Trust in the toolchain.** The Rust binaries come from rust-lang's release infrastructure via
  `rust-overlay`; nixpkgs supplies tar, gzip and `cargo-cyclonedx`. macOS builds also trust the
  runner's Xcode, and are reproducible only with the same Xcode version.
- **Unpinned actions until the first release.** Some actions are still marked `TODO(pin)` (all-zero
  SHA) in the workflows; the release and fuzz workflows fail until they are pinned
  (`tests/ci_files.rs::pin_placeholders_are_listed`).
- **Not yet exercised.** The release workflow, the attestations and the action's verification
  have only been validated statically (actionlint, YAML parsing, tests) and by local reproducible
  builds; the first tag is their first real run.

