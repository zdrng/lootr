# Dependency review record

Every crate lootr depends on runs inside a process that holds secrets. This record lists the
direct dependencies, why each is needed, how much `unsafe` code it carries and its license; it is
the human-readable side of the `cargo vet` state in [`supply-chain/`](../supply-chain/).

Rules (PLAN.md, "Supply chain"): every new dependency needs a reason in the PR and an entry here;
no network, async or subprocess crates (`deny.toml`); GPL-3.0-compatible licenses only; crates.io
only; `Cargo.lock` is committed and every build uses `--locked`.

## Tooling

| Check | Command | Where |
|---|---|---|
| Licenses, banned crates, sources, advisories | `nix develop -c cargo deny check` | CI, release |
| Advisories (RustSec) | `nix develop -c cargo audit` | CI, daily (`audit.yml`) |
| Review state | `nix develop -c cargo vet --locked` | CI, release |
| SBOM | `nix develop .#release -c scripts/release.sh sbom dist` | release asset `lootr-<version>.cdx.json` |

`cargo vet` was initialized offline (`cargo vet init`, cargo-vet 0.10.2): all 93 crates in the
lockfile (including dev, fuzz-irrelevant and other-platform crates) are recorded as
**exemptions** in `supply-chain/config.toml` (`safe-to-deploy`, `tempfile` `safe-to-run`). An
exemption means "in use, not audited"; it is not a review. No third-party audit sets are imported
yet, because importing fetches them over the network. To reduce the exemption list:

```sh
nix develop -c cargo vet import mozilla      # https://raw.githubusercontent.com/mozilla/supply-chain/...
nix develop -c cargo vet import google       # and/or bytecode-alliance, zcash, ...
nix develop -c cargo vet prune               # drops exemptions now covered by imported audits
nix develop -c cargo vet suggest             # what is left to audit, smallest diffs first
nix develop -c cargo vet certify <crate> <version>   # after reviewing it yourself
```

New or updated crates make `cargo vet --locked` fail in CI until they are certified, covered by an
import, or (with a reason in the PR) added as an exemption.

## Direct dependencies

Versions as locked. `unsafe` = approximate number of `unsafe` blocks, functions and impls found by
text search in the crate's sources (including tests); `forbid` = the crate itself declares
`#![forbid(unsafe_code)]`.

| Crate | Version | Why lootr needs it | `unsafe` | License |
|---|---|---|---|---|
| `cel` | 0.15.0 | Policy expressions (CEL). Only the `regex` feature: no chrono, no base64 encoder. Choice and alternatives: PLAN.md "CEL engine decision" | ~127, all in the ANTLR-generated parser (`src/parser/gen/celparser.rs`) | MIT |
| `clap` (+ `derive`) | 4.6.7 | Command line parsing | 0, `forbid` (clap_builder: 5, clap_lex: 6) | MIT OR Apache-2.0 |
| `regex` | 1.13.1 | Custom value types, globs, `matches()` in CEL: linear time, no backtracking | 1 (regex-automata: ~56, memchr/aho-corasick: SIMD) | MIT OR Apache-2.0 |
| `rustix` (`fs`, `process`) | 1.1.5 | Safe wrappers for `openat`/`O_NOFOLLOW`/`fstat`, `setrlimit`, `prctl`, `lgetxattr`: lets lootr forbid `unsafe` itself | ~1600: this is the crate's purpose (raw syscalls on Linux via `linux-raw-sys`, `libc` on macOS) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| `saphyr-parser` | 0.1.0 | YAML event parser (kubeconfig, workflows, gh hosts, yaml extractor); the tree and its limits are lootr's own. Alternatives rejected: PLAN.md M3 notes | 0 (dependency `arraydeque`: ~72, ring buffer) | MIT OR Apache-2.0 |
| `serde` (+ `derive`) | 1.0.229 | (De)serialization of config, reports and credential files | 2 | MIT OR Apache-2.0 |
| `serde_json` (`preserve_order`) | 1.0.151 | JSON report, SARIF, JSON credential files and extractor (recursion limit 128) | ~18 (number formatting, UTF-8 fast paths) | MIT OR Apache-2.0 |
| `thiserror` | 2.0.21 | Error types (derive only) | 0 | MIT OR Apache-2.0 |
| `toml` | 1.1.7 | `lootr.toml`, TOML credential files and the toml extractor | 0, `forbid` (toml_parser: ~54 in its lexer/decoder, winnow: ~44) | MIT OR Apache-2.0 |
| `zeroize` | 1.9.1 | Wipes secret buffers on drop (volatile writes + compiler fence) | ~39: the volatile writes are the point | Apache-2.0 OR MIT |
| `tempfile` (dev only) | 3.27.0 | Temporary directories in tests; never in the binary | 3 | MIT OR Apache-2.0 |

## Notable transitive dependencies

| Crate | Pulled in by | Note |
|---|---|---|
| `antlr4rust` 0.6.0 | `cel` | Parser runtime (BSD-3-Clause); ~49 `unsafe`; pulls `parking_lot`, `uuid` (default features = `std`, no RNG used), `murmur3`, `typed-arena`, `bit-set`, `lazy_static`, `once_cell`, `byteorder` |
| `nom` 7.1.3 | `cel` | Parser combinators (string literal unescaping) |
| `libc`, `linux-raw-sys`, `errno` | `rustix` | Raw system call definitions |
| `hashbrown`, `indexmap` | `serde_json` (`preserve_order`), `toml` | Hash tables; `unsafe` internals |
| `memchr`, `aho-corasick`, `regex-automata`, `regex-syntax` | `regex` | SIMD search; `regex-syntax` forbids `unsafe` |
| `zmij`, `itoa` | `serde_json` | Number formatting |
| `proc-macro2`, `quote`, `syn`, `*_derive`, `pastey`, `rustversion` | derive macros | Build-time only (run in the compiler, not in the binary) |
| `windows-sys`, `wasm-bindgen`, `js-sys`, `r-efi`, `redox_syscall`, `futures-*`, `bumpalo` | various, other platforms only | In `Cargo.lock` and the SBOM (all platforms) but not compiled for the release targets |

Crates compiled into the Linux musl binaries (`cargo tree -e normal --target
x86_64-unknown-linux-musl`): 66 including proc macros; the macOS build adds `errno` and drops
`linux-raw-sys`.

## Build-time code

lootr has no build script. Dependencies with build scripts only probe the compiler (they run
`$RUSTC --version` or read cfg variables: `libc`, `rustix`, `serde`, `proc-macro2`, `zmij`, ...);
none downloads anything or compiles C.
Procedural macros (`serde_derive`, `clap_derive`, `thiserror-impl`, `pastey`) run inside the
compiler at build time with the builder's rights; the release build runs them on a fresh
GitHub-hosted runner with a read-only token.

## Review history

| Date | Reviewer | Scope | Result |
|---|---|---|---|
| 2026-10-09 | maintainers (M7) | Direct dependencies: purpose, license, `unsafe` count, features; `cargo vet init` | Recorded above; all crates exempted, no audit imported |
