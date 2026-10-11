# External review checklist (before 1.0)

lootr is pre-1.0. Before 1.0, an independent reviewer (not one of the authors) goes through this
list. Background: [threat-model.md](threat-model.md), PLAN.md ("Security model"),
[dependencies.md](dependencies.md). Record the result (findings, commit reviewed, date, reviewer)
in a new section at the end of this file, and file findings as security advisories or issues per
[SECURITY.md](../SECURITY.md).

Never use real secrets for the review: the test environments (`test-envs/`), container scenarios
(`containers/`) and fakes contain dummy secrets marked with `LOOTRCANARY`.

## 1. Secrets never leave the collector

- [ ] Every `Ident::from_non_secret` / `PublicText::from_non_secret` call site
      (`rg from_non_secret src/`): none receives secret material (token bodies, key bytes,
      passwords, env values).
- [ ] `SecretBuf` / `SecretSlice` (`src/domain/secret.rs`): no trait or method that can print,
      serialize, clone or leak the bytes; zeroized over the whole capacity on drop; no
      reallocation.
- [ ] Every document and value type (`src/domain/types/`) reads only what its attributes need;
      SSH/PEM decode stops at the public part; JWT signatures are never decoded.
- [ ] Parser and config errors never quote input (`ParseError` is `&'static str`; third-party
      parser messages are replaced).
- [ ] `proc_environ` and `kube_service_account` probes only pass values to the value types.
- [ ] The canary harness (`src/testing.rs`, `tests/canary.rs`, `containers/run.sh`) covers every
      output format and flag, stderr, `types`, `explain` and `policy check`.

## 2. Process and file system

- [ ] Hardening (`src/os/hardening.rs`, `src/main.rs`) runs before anything is opened; check on
      Linux that core dumps are off and `/proc/<pid>/status` shows the process non-dumpable (no
      automated test does this yet).
- [ ] `src/os/open.rs`: `lstat` → `open(O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|O_NOCTTY)` → `fstat` on
      the fd; regular files only; size limit enforced before and during reading; `*_beneath`
      resolves every component with `openat` + `O_NOFOLLOW`.
- [ ] Discovery never follows symlinks, honours `max-depth` and `one-file-system`; the remaining
      discover/collect race is as documented.
- [ ] The report file is created `0600`, not through a symlink; nothing else is written.
- [ ] No subprocess, no network, no environment changes anywhere (`clippy.toml` lists, `deny.toml`
      bans); check that lints cannot be silenced locally (`rg 'allow\(clippy::disallowed'`).

## 3. Parsers (untrusted input)

- [ ] YAML loader limits (`src/domain/format/yaml.rs`): depth, node count, documents, expanded
      alias size, recursive aliases.
- [ ] JSON/TOML recursion limits; INI/netrc/dotenv/content tokenizer bounds.
- [ ] Every parser and extractor has a fuzz target (`fuzz/`); nightly fuzz runs are green
      (`.github/workflows/fuzz.yml`); consider a run with AddressSanitizer on nightly.

## 4. Policy engine and config

- [ ] CEL load-time checks (`src/service/cel.rs`): identifiers, `attrs.<x>`, function allowlist;
      runtime errors become `rule_error` and exit 2 (never a silent pass).
- [ ] Layering and `locked` rules (`src/service/config.rs`): no way for a later layer (or an
      included file) to disable, weaken or waive a locked rule.
- [ ] Includes are local only; cycles and depth are limited.

## 5. Reports

- [ ] `--redact-paths` and `~` normalization (`src/report/paths.rs`) in JSON, SARIF, Markdown and
      stderr; behaviour with symlinked `HOME`/working directory.
- [ ] Markdown escaping (everything from scan or config in code spans): no mentions, links or
      HTML in PR comments.
- [ ] SARIF output against the 2.1.0 schema with a full JSON-schema validator.

## 6. Release and supply chain

- [ ] Every `TODO(pin)` in `.github/workflows/` replaced by a verified commit SHA
      (`tests/ci_files.rs::pin_placeholders_are_listed` lists none).
- [ ] `release.yml`: permissions per job (only `publish` writes), no build code in `publish`,
      tag/version check, attestation verification before the release is created.
- [ ] Rebuild a release locally with `nix develop .#release -c scripts/release.sh reproduce
      <target> dist` at the tag (`LOOTR_SOURCE_DATE_EPOCH` = commit time) and compare with
      `SHA256SUMS`.
- [ ] Verify a published release with both `gh attestation verify` and `cosign
      verify-blob-attestation` as documented in PLAN.md ("Release artifacts").
- [ ] `action.yml`: verifies before unpacking, no `${{ }}` in scripts, token never reaches lootr.
- [ ] `cargo deny check`, `cargo audit`, `cargo vet --locked` are green; the exemptions in
      `supply-chain/config.toml` are reviewed or covered by imported audits for the crates in
      the release binary.

## 7. Known open items to confirm or close

- [ ] `~` normalization is string based (symlinked home or cwd keeps absolute paths).

## Review log

(none yet)
