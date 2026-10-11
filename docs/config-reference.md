# `lootr.toml` reference

One TOML format holds sources (where values come from), custom value types, rules (what is
acceptable) and waivers (accepted exceptions). lootr applies config **layers** in order: the
built-in default, then every `--config` file. This document describes what the code accepts;
the policy language used in `when` is described in [cel.md](cel.md), the report formats in
[report-schema.md](report-schema.md), and the generated list of types and attributes is in
[types.json](types.json) (`lootr types --json`).

Contents: [File layout](#file-layout) - [`version`](#version) - [`include`](#include) -
[`[scan]`](#scan) - [Paths and globs](#paths-and-globs) - [`[[source]]`](#source) -
[Extractors](#extractors) - [Document types](#document-types) - [Probes](#probes) -
[`[[type]]`](#type) - [`[[rule]]`](#rule) - [`[[waiver]]`](#waiver) - [Layering](#layering) -
[Built-in default layer](#built-in-default-layer) - [Command line](#command-line) -
[Exit codes](#exit-codes) - [Validation errors](#validation-errors)

## File layout

```text
version = 1                     # required
include = ["base.toml"]         # optional: local files applied before this one

[scan]                          # optional
max-file-size = "1MiB"

[[source]]                      # any number of each
[[type]]
[[rule]]
[[waiver]]
```

General rules:

- Keys are kebab-case (`max-file-size`); **unknown keys are errors**, in every table.
- Identifiers (source ids, rule ids, custom type names, tag keys and values) are 1 to 128 bytes
  of ASCII letters, digits and `_ - . / : @ + %`.
- Every problem in every layer is collected and reported together as
  `<file>: <message>` on stderr; any problem means exit code 2 and nothing is scanned (see
  [Validation errors](#validation-errors)).
- Config is as trusted as code: custom types and rules run with lootr's access to secret values.
  Review third-party policy like a dependency.

## `version`

| key | type | required | meaning |
|---|---|---|---|
| `version` | integer | yes | must be `1`; otherwise the error ``expected `version = 1` `` |

Every file, including included ones, needs `version = 1`.

## `include`

| key | type | default | meaning |
|---|---|---|---|
| `include` | list of strings | `[]` | local config files applied as layers **before** this file |

- Paths are relative to the including file (`..` allowed, normalized lexically); absolute paths
  work too. Includes are read depth first, in list order, each with its own includes first.
- URLs (anything containing `://`) are rejected: `only local files can be included`.
- Cycles (`include cycle: a.toml -> b.toml -> a.toml`) and nesting deeper than 16 levels are
  errors. A missing file is `cannot read config: not found`.
- An included file is a layer of its own (it has its own name in messages and counts as a
  different layer for [locked rules](#locked-rules)).

## `[scan]`

| key | type | default | meaning |
|---|---|---|---|
| `max-file-size` | integer (bytes) or string | `"1MiB"` (1048576) | files larger than this are not read; they are reported as skipped (`too_large`) |
| `max-depth` | integer >= 1 | `16` | how many path components below a pattern's literal prefix a `**` walk descends |
| `one-file-system` | bool | `true` | do not descend into directories on another device than the walk's start directory |
| `exclude` | list of globs | `[]` | paths excluded from every `file` and `probe` source; appended across layers |
| `fail-on-skipped` | list of skip reasons or `"*"` | `[]` | a [skipped entry](report-schema.md#skipped) with one of these reasons fails the run (exit code 1, like a failing finding); appended across layers |
| `locked` | bool | not locked | `true` locks `[scan]` against weakening by later layers (see [Locked inputs](#locked-inputs)) |

Sizes: an integer is a byte count; a string is digits plus an optional unit, whitespace allowed
in between: `B`, `KiB`, `MiB`, `GiB` (powers of 1024), `KB`, `MB`, `GB` (powers of 1000). No
decimals, no `TiB`. `0` is an error.

Layering: each later layer overrides the single settings it sets; `exclude` and `fail-on-skipped`
lists of all layers are concatenated (a later layer cannot remove an entry).

`fail-on-skipped` reasons: `not_found`, `permission_denied`, `symlink`, `not_regular`,
`too_large`, `io_error`, `parse_error`, `invalid_path`, `not_recognized`, `binary`, `truncated`,
`depth_limit`, `other_fs`, `symlink_root`, or `"*"` for all of them (unknown reasons are config
errors). Skipped entries are false-negative risks: a CI policy that must not pass when lootr
could not look somewhere sets e.g.

```toml
[scan]
fail-on-skipped = ["truncated", "binary", "depth_limit", "other_fs", "symlink_root", "too_large"]
```

## Paths and globs

The same glob syntax is used for env var names, source `paths`/`exclude`, `[scan] exclude` and
waiver `path`. Globs are compiled to a linear-time `regex`.

| syntax | matches |
|---|---|
| `*` | any characters except `/`, including a leading `.` (dotfiles are not special) |
| `?` | one character except `/` |
| `**` as a whole component | zero or more components: `a/**/b` matches `a/b` and `a/x/y/b`; a trailing `/**` matches everything below |
| `**` inside a component | same as `*` |
| `[abc]`, `[a-z]` | one character from the set |
| `[!abc]` | one character not in the set (`]` right after `[` or `[!` is literal) |
| `\x` | `x` literally |

Path expansion (paths, excludes, waiver paths):

- `~` and `~/...` are the home directory (`$HOME`). `~user` is not supported. Without a home
  directory a `~` pattern cannot be expanded: a source path is reported as skipped
  (`invalid_path`), a waiver path is a config error.
- A relative pattern is relative to the **current directory** (not to the config file):
  `./**/.env`, `.github/workflows/*.yml`.
- `.` components are dropped; `..` removes the previous literal component (`..` after a
  wildcard is an error). Glob characters in the home or current directory are matched literally.
- Matching is always against absolute paths; CEL and waivers also see absolute paths (reports
  show `~/...`).

How a file or probe source walks the file system:

- The walk starts at the pattern's longest literal prefix (`~/.ssh/**` starts at `~/.ssh`). If
  that prefix does not exist nothing is reported; if it cannot be read it is reported as skipped.
- The literal prefix comes from the (trusted) config: symlinks in its parent components are
  resolved by the kernel. If its last component is a symlink (`~/.ssh -> dotfiles/ssh`), it is
  followed **once**, when the link is owned by the scanning user or root and points to a real
  directory (not to another symlink) that is not excluded; the walk then runs below the target
  and reported paths keep the configured prefix (`~/.ssh/id_ed25519`). Otherwise the prefix is
  reported as skipped (`symlink_root`). Nothing below the literal prefix is ever followed.
- A fully literal pattern (`~/.aws/credentials`) is a candidate if it exists and is not a
  directory. Directories are never candidates of a `file` source; a `probe` source gets matching
  directories too (literal or matched by a glob), because probes such as `writable` judge
  directories.
- Without `**` the walk descends exactly as deep as the pattern has components; with `**` at most
  `max-depth` components below the literal prefix. A directory the `**` walk does not enter
  because of `max-depth` is reported as skipped (`depth_limit`), one on another device with
  `one-file-system = true` as `other_fs`.
- Symlinks below the literal prefix are never followed (a matching symlink is reported as
  skipped, not read). Entries below the literal prefix are opened with `openat` + `O_NOFOLLOW`,
  so a symlink planted in a parent directory is refused.
- One file reached through two paths of the same source (a symlinked parent such as
  `/var/run` -> `/run`, a hard link) is collected once, at the first path (by device and inode).
- Excluded paths (global `[scan] exclude` plus the source's `exclude`) are pruned: a pattern
  matches a path either as is or with a trailing `/`, so `~/Library/**` prunes `~/Library`
  itself.
- Only regular files are read; FIFOs, sockets and devices are reported as skipped by metadata.

## `[[source]]`

A source selects candidates; `kind` decides what is selected and which fields are allowed.

| field | type | kinds | meaning |
|---|---|---|---|
| `id` | identifier | all, required | unique name; later layers override the source by this id |
| `kind` | `"env"`, `"file"`, `"probe"` | all, required for a new source | what the source selects |
| `names` | list of globs | `env` (required, non-empty) | environment variable names to read |
| `paths` | list of globs | `file` (required, non-empty), `probe` (optional) | paths to read / to hand to the probes |
| `exclude` | list of globs | `file`, `probe` | paths to skip, in addition to `[scan] exclude` |
| `type` | document type name | `file` | parse every matching file with this [document type](#document-types) |
| `extract` | extractor name | `file` | split every matching file with this [extractor](#extractors) |
| `probes` | list of probe names | `probe` (required, non-empty) | built-in [probes](#probes) to run |
| `path-vars` | list of env var names | `probe` | variables holding `:`-separated directory lists (`PATH`); every absolute entry is handed to the probes as a literal path (not a glob), like `paths` |
| `enabled` | bool | all | `false` disables the source (default: enabled) |
| `locked` | bool | all | `true` locks the source against weakening by later layers (see [Locked inputs](#locked-inputs)) |

Valid combinations (anything else is an error such as `` `paths` is not allowed for kind `env` ``):

| kind | required | optional | not allowed |
|---|---|---|---|
| `env` | `names` | `enabled` | `paths`, `exclude`, `type`, `extract`, `probes`, `path-vars` |
| `file` | `paths` and exactly one of `type` / `extract` | `exclude`, `enabled` | `names`, `probes`, `path-vars` |
| `probe` | `probes` | `paths`, `exclude`, `path-vars`, `enabled` | `names`, `type`, `extract` |

What each kind produces:

- **`env`**: one candidate per variable whose name matches one of the globs (names must be UTF-8
  and valid identifiers, others are not scanned). Each value is classified by every value type
  (built-in and custom) and always produces a generic `env_var` fact at location `$NAME`.
- **`file` with `type`**: the file is read (up to `max-file-size`), the document type sniffs the
  first 512 bytes and parses it. A file a glob matched that does not look like the type is no
  match (silent: `~/.ssh/**` skips `known_hosts`); a file named literally (no glob, e.g.
  `~/.aws/credentials`) that does not look like the type is reported as skipped
  (`not_recognized`).
  The type emits facts of its own name and may emit nested values (tokens, passwords) that are
  classified by the value types, located at `path#key.path`. All of them carry the
  [file attributes](cel.md#file-attributes).
- **`file` with `extract`**: every entry the extractor finds produces a generic entry fact
  (`dotenv_entry` or `config_entry`) located at `path#key` and is classified by the value types,
  exactly like an env var. The `content` extractor emits no generic facts (see below).
- **`probe`**: one run per listed probe. `paths` are walked like file paths (nothing is read) and
  the matching paths, directories included, are handed to the probe together with the absolute
  entries of the `path-vars` variables (read from the environment; empty, relative and non-UTF-8
  entries are left out; `exclude` applies to them too); probes that do not inspect paths ignore
  them.

Example:

```toml
[[source]]
id = "ssh-documents"
kind = "file"
paths = ["~/Documents/**/id_*"]
exclude = ["~/Documents/archive/**"]
type = "ssh_private_key"

[[source]]
id = "ci-env"
kind = "env"
names = ["CI_*", "*_TOKEN"]

[[source]]
id = "app-config"
kind = "file"
paths = ["./config/*.yaml"]
extract = "yaml"

[[source]]
id = "my-sockets"
kind = "probe"
probes = ["unix_socket"]
paths = ["/srv/run/*.sock"]
```

## Extractors

`extract = "<name>"` in a `file` source. Keys are identifiers: bytes an identifier cannot hold
(spaces, brackets, non-ASCII) become `_`; a key path longer than 128 bytes is cut to 125 bytes
plus `...` (the entry is still classified); more than 10 000 entries in one file is a parse error
(the file is reported as skipped).

| extractor | entry type | entries | key |
|---|---|---|---|
| `dotenv` | `dotenv_entry` | `KEY=value` lines; `export ` prefix, spaces around `=`, `#` comments, inline ` #` comments, `'single'` / `"double"` / `` `backtick` `` quotes (may span lines; escapes are not resolved) | the variable name |
| `ini` | `config_entry` | `key = value` or `key: value` lines, split at the earliest `=` or `:` (like Python's `configparser`: `api_key: QUJDRA==` is key `api_key`); `[section]` headers, `#`/`;` comments, quotes removed, indented continuation lines | `section.key` (`key` before any section; `[profile dev]` gives `profile_dev.key`) |
| `json` | `config_entry` | every string value (numbers, booleans, null skipped) | dotted path, arrays by index: `a.b.0.c` |
| `yaml` | `config_entry` | every non-null scalar value | dotted path `a.b.0.c`; with several documents the path starts with the document index (`0.a`, `1.b`) |
| `toml` | `config_entry` | every string value | dotted path `a.b.0.c` |
| `content` | (none) | runs of `[A-Za-z0-9_.+/~-]` per line, 8 to 4096 bytes (`=` and `:` split runs); binary files (NUL in the first 8 KiB) are not scanned and reported as skipped (`binary`); after 10 000 runs the rest of the file is not scanned and the file is reported as skipped (`truncated`) | `L<line>` |

`content` scans arbitrary text files for embedded secrets: only runs that a value type recognizes
become facts (of that value type, at `file#L42`); unrecognized runs produce nothing. The other
extractors produce one generic entry fact per entry plus one fact per value type that matched.

Parser limits: YAML depth 64, 100 000 nodes, 64 documents, alias expansion capped at 200 000
nodes (an alias bomb is a parse error); JSON nesting 128; TOML nesting about 80; JSON/TOML values
deeper than 64 levels are not visited and the file is reported as skipped (`truncated`, next to
the entries that were found).

## Document types

`type = "<name>"` in a `file` source. Each type sniffs and parses the file and emits facts of its
own name (some also emit nested values that are classified by the value types). Attributes:
`lootr types`, [types.json](types.json), examples in [cel.md](cel.md#examples).

| type | file |
|---|---|
| `ssh_private_key` | OpenSSH, PEM or PKCS#8 private key (only the non-secret parts are read) |
| `pem` | PEM file: keys, certificates, requests |
| `aws_credentials` | AWS shared credentials / config file |
| `gcp_credentials` | Google Cloud credential JSON (service account key, user, federated) |
| `azure_profile` | Azure CLI files in `~/.azure` |
| `kubeconfig` | Kubernetes client config (one fact per file) |
| `docker_config` | Docker / Podman client config |
| `npmrc`, `pypirc`, `netrc`, `git_credentials`, `gh_hosts` | developer tool credential files |
| `github_workflow` | GitHub Actions workflow (one fact per job, at `path#jobs.<id>`) |

Value types (`github_token`, `gitlab_token`, `aws_access_key_id`, `api_key`, `jwt`) and custom
types are not used in sources: every value from an env source, an extractor, a document type or
a probe that reads secrets is run through all of them automatically.

## Probes

`probes = ["<name>"]` in a `probe` source. A probe produces facts directly; the probe name is not
always its fact type name.

| probe | fact types | uses `paths` | notes |
|---|---|---|---|
| `process` | `process` | no | one fact per run: uid, root, groups, container markers |
| `unix_socket` | `unix_socket` | yes | one fact per matched path that is a socket; access judged from mode and groups, never by connecting |
| `proc_environ` | `proc_environ` (+ value types) | no | Linux `/proc/<pid>/environ` of other processes; one summary fact; each readable value is classified by the value types at `probe:proc_environ:<process name>`; an environment larger than 256 KiB is classified up to that size and reported as skipped (`truncated`) |
| `writable` | `writable_path_dir`, `writable_file` | yes (and `path-vars`) | writability from mode, owner and groups, never by writing; directories become `writable_path_dir`, other objects `writable_file`; only objects someone other than the owner may write produce a fact (group/world write bit on a directory, on a file or on its directory); a symlink is judged by its target (`stat`, nothing opened; `symlink = true`), a file symlink also by the link's own directory, a dangling link only by its directory |
| `suid` | `suid_binary` | yes | only regular files with setuid/setgid or Linux file capabilities produce a fact |
| `kube_service_account` | `kube_service_account` (+ value types) | yes | `paths` point at the token file; the token is classified (normally `jwt`), `namespace` and `ca.crt` are read from the same directory. Symlinks are followed only while they stay in that directory (the projected-volume layout `token -> ..data/token`); anything else, or an unreadable token, is reported as skipped. The same token reached through two paths (`/var/run` -> `/run`) is reported once |

## `[[type]]`

Custom value types: regex only.

| field | type | required | meaning |
|---|---|---|---|
| `name` | identifier | yes | type name used in `[[rule]] type`; must not clash with a built-in type |
| `pattern` | string | yes for a new type | Rust `regex` syntax, matched against the raw bytes of every value (unanchored: use `^...$`); compiled size limit 1 MiB; linear time |
| `locked` | bool | no | `true` locks the pattern against changes by later layers (see [Locked inputs](#locked-inputs)) |

```toml
[[type]]
name = "acme_api_key"
pattern = '^acme_(live|test)_[A-Za-z0-9]{24}$'
```

A custom type gets the attributes `length`, `entropy` (estimated bits) and `charset` (`digits`,
`hex`, `alnum`, `base64`, `base64url`, `printable`, `binary`), plus the file attributes when the
value came from a file. Custom types are listed in the report header (a pattern can act as an
oracle for secret values). A later layer with the same `name` replaces the pattern (unless the
type is locked); an override without `pattern` only sets `locked`.

## `[[rule]]`

| field | type | required | meaning |
|---|---|---|---|
| `id` | identifier | yes | unique name; later layers override the rule by this id |
| `type` | type name | yes for a new rule | facts of this type are evaluated (any type from `lootr types`, incl. custom types and `waiver`) |
| `when` | string (CEL) | yes | condition over the fact; true = finding. See [cel.md](cel.md) |
| `severity` | `info`, `low`, `medium`, `high`, `critical` | yes | ordered `info < low < medium < high < critical` |
| `message` | template | no | default `{type} at {location} matches rule {rule}` |
| `remediation` | template | no | default empty |
| `tags` | table of identifier = identifier | no | free key/value pairs shown in every report format, e.g. `{ category = "privilege", control = "SEC-12" }` |
| `locked` | bool | no | `true` locks the rule for later layers (see [Locked rules](#locked-rules)) |
| `enabled` | bool | no | `false` disables the rule; disabled rules are not evaluated or validated |

Rules are selected by the fact's type and evaluated in config order (the position where the id
was first defined). `type`, `when` and `severity` must be present after all layers are merged;
a rule that only exists as an override is an error.

Placeholders in `message` and `remediation` (unknown placeholders are config errors):

| placeholder | value |
|---|---|
| `{path}` | the file path (`-` for env and probe locations) |
| `{name}` | env var name, key path inside the file, probe location name, or the file name |
| `{type}` | fact type |
| `{rule}` | rule id |
| `{source}` | source id (`config` for waiver facts) |
| `{location}` | `/path`, `/path#key.path`, `$NAME` or `probe:name` |
| `{<attribute>}` | any attribute of the rule's type, incl. file attributes where the type has them |

A missing optional attribute renders as `-`; `{mode}` renders in octal (`0644`); lists render
comma separated, maps as `key=value` pairs; `{{` and `}}` are literal braces (`${{NPM_TOKEN}}`
renders `${NPM_TOKEN}`). Paths are rendered absolute and mapped to `~/...` (or redacted) in the
report.

## `[[waiver]]`

| field | type | required | meaning |
|---|---|---|---|
| `rule` | rule id | yes | the waived rule; must exist in some layer (it may be disabled) |
| `reason` | string | yes, non-empty | shown in the report next to the waived finding |
| `path` | glob | no | the finding's file path must match (`~` and relative paths expanded like source paths) |
| `name` | string | no | must equal the finding's `{name}`: env var name, key path inside a file, probe location name, or the file name for whole-file facts |
| `expires` | TOML date, unquoted: `2027-01-31` | no | last day (UTC) the waiver applies |

- A waiver matches a finding if the rule id is equal and every given `path`/`name` matches;
  without both it waives the rule everywhere. Facts without a file location never match a
  waiver with `path`. The first matching waiver is applied.
- Waived findings stay in the report (with the reason) and do not count for `--fail-on`.
- `expires` must be a plain date (a datetime or a quoted string is an error). The waiver applies
  through that day; from the next day (UTC) it is **expired**: ignored (the findings count
  again), listed in the report's `expired_waivers`, warned about on stderr and by
  `lootr policy check` (a warning, exit 0 there), and its `waiver` fact has `expired = true`,
  which the default rule `waiver-expired` reports.
- Every waiver is also a `waiver` fact at `<config file>#[[waiver]] #<n>` (n-th waiver of that
  file), so rules can demand expiry dates or flag unused waivers (see
  [cel.md](cel.md#waiver)).
- `lootr policy check` reads no home directory: it expands `~` in waiver paths against
  `/nonexistent-home`.

## Layering

Layers are applied in order: built-in default (unless `--no-default`) -> each `--config` file
(its includes first) -> for `policy check`, the positional files.

| entry | merge key | later layer may |
|---|---|---|
| `[scan]` | per setting | override single settings; `exclude` and `fail-on-skipped` are appended |
| `[[source]]` | `id` | override the fields it sets (field by field), disable with `enabled = false` |
| `[[type]]` | `name` | replace the pattern |
| `[[rule]]` | `id` | override the fields it sets; `tags` are merged key by key; disable with `enabled = false` |
| `[[waiver]]` | (none) | add waivers (all waivers of all layers apply) |

- A source without `kind` or a rule without `type` whose id no earlier layer defines is an error:
  ``rule `x` overrides nothing: no earlier layer defines this rule (check the id; ...)``. Typos
  in overrides never pass silently.
- An override can be as small as one field:

  ```toml
  [[rule]]
  id = "process-sudo-group"
  enabled = false

  [[rule]]
  id = "workflow-default-permissions"
  severity = "medium"
  tags = { team = "platform" }    # added to the existing category tag
  ```

### Locked rules

`locked = true` (set when the rule is defined or by a later override) locks a rule from the next
layer on. Later layers may only:

- raise the severity;
- change `message`, `remediation` and `tags` (merged).

Each of these is a config error naming the file, the rule, the locking layer and every attempted
change; the whole override is rejected:

- `enabled = false` (disable it);
- `locked = false` (unlock it);
- a different `type`;
- a different `when` (whitespace differences are ignored);
- a lower `severity`.

```text
team.toml: rule `ssh-key-unencrypted` is locked by baseline.toml; this layer tries to disable it
(`enabled = false`), lower its severity from high to medium. A locked rule only accepts a higher
severity and a new message, remediation or tags
```

Only the locking layer itself may waive a locked rule. Waivers for it in later layers, in
earlier layers and in files included by the locking file are errors
(`rule is locked by <layer>; only that layer may waive it`). `lootr explain <rule>` shows
`locked yes (by <layer>)`; `lootr policy check` lists locked rules with their locking layer.
See [`examples/company/`](../examples/company/) for a baseline, a team layer and project waivers.

### Locked inputs

A locked rule is only as strong as what it is evaluated on. Later layers may therefore not
**weaken** (they may always extend):

- a `[[source]]`, `[[type]]` or `[scan]` with `locked = true` (set where it is defined or by an
  override such as `[[source]] id = "ssh"` / `locked = true` in a baseline);
- implicitly, the inputs of every locked rule, as they were in the locking layer: `[scan]`, every
  custom type, and every source that can produce facts of the rule's type: sources with that
  document type, sources with an extractor whose entry type it is, env sources for `env_var`,
  probe sources for probe fact types, and **every** source for a value type (`github_token`,
  `jwt`, a custom type, ...), because values come from env vars, extracted entries, documents and
  probes alike. Sources and types added after the lock are not protected by it.

Weakening means:

| input | weakening (error) | allowed |
|---|---|---|
| `[[source]]` | `enabled = false`, `locked = false`, another `kind`, `type` or `extract`, a `paths`/`names`/`probes`/`path-vars` list that drops an entry, an `exclude` list with a new entry | more paths, names, probes, path-vars; `locked = true` |
| `[[type]]` | another `pattern`, `locked = false` | `locked = true` |
| `[scan]` | new `exclude` entries, a lower `max-file-size` or `max-depth`, `one-file-system = true` after `false`, `locked = false` | a higher limit, `one-file-system = false`, more `fail-on-skipped` reasons |

```text
project.toml: source `dotenv` is locked: rule `github-classic-token`, locked by baseline.toml,
depends on it; this layer tries to exclude `./**`. A locked input may only be extended (more
paths, sources, rules), not weakened
```

So a baseline that locks rules also fixes, for every later layer, where and how deeply lootr
looks. Excludes a project needs (vendored test fixtures, generated code) belong into the layer
that locks, or a layer before it.

**Where the policy comes from matters.** Every layer is as trusted as code, and so is whoever can
edit it. A `lootr.toml` checked into the scanned repository is controlled by every pull request
author: they can add waivers, disable unlocked rules and sources, or drop the file. Company policy
that a pull request must not be able to weaken has to come from outside the repository (a config
file baked into the CI image or runner, a pinned policy repository checked out by the workflow,
the action's `config` input pointing outside the checkout) and has to lock what it enforces; the
in-repository file can then only add rules, sources and waivers for unlocked rules. The workflow
that runs lootr must itself be one a pull request cannot change (e.g. a required workflow).

## Built-in default layer

The default config is compiled into the binary (`src/service/default.toml`) and is an ordinary
first layer: later layers override or disable any of its sources and rules by id, nothing in it
is locked, and `--no-default` drops it completely (then your config must define all sources and
rules). Inspect it with:

```sh
lootr policy check                      # counts: 1 layer, 31 sources, 71 enabled rules
lootr explain ssh-key-unencrypted       # one rule after all layers, with its type's attributes
lootr explain nope                      # error listing every enabled rule id
lootr types                             # every type and attribute
```

`[scan]` defaults: `max-file-size = "1MiB"`, `max-depth = 16`, `one-file-system = true`,
`exclude = []`, `fail-on-skipped = []`.

Sources (31):

| id | kind | selects | type / extract / probe |
|---|---|---|---|
| `process-env` | env | `*` | `env_var` + value types |
| `ssh` | file | `~/.ssh/**` | `ssh_private_key` |
| `dotenv` | file | `./**/.env`, `./**/.env.*` (not in `.git`, `node_modules`) | `dotenv` |
| `pem` | file | `./**/*.pem`, `./**/*.key`, `~/.docker/**/*.pem`, `~/.kube/**/*.key`, `~/.minikube/**/*.key` (not `~/.ssh`, `.git`, `node_modules`) | `pem` |
| `aws` | file | `~/.aws/credentials`, `~/.aws/config` | `aws_credentials` |
| `gcp` | file | `~/.config/gcloud/application_default_credentials.json`, `~/.config/gcloud/legacy_credentials/*/adc.json` | `gcp_credentials` |
| `azure` | file | `~/.azure/{azureProfile,msal_token_cache,accessTokens,service_principal_entries}.json` | `azure_profile` |
| `kubeconfig` | file | `~/.kube/config`, `~/.kube/*.yaml`, `~/.kube/*.yml` | `kubeconfig` |
| `docker-config` | file | `~/.docker/config.json`, `~/.config/containers/auth.json` | `docker_config` |
| `npmrc` | file | `~/.npmrc`, `./**/.npmrc` | `npmrc` |
| `pypirc` | file | `~/.pypirc` | `pypirc` |
| `netrc` | file | `~/.netrc` | `netrc` |
| `git-credentials` | file | `~/.git-credentials`, `~/.config/git/credentials` | `git_credentials` |
| `gh-hosts` | file | `~/.config/gh/hosts.yml` | `gh_hosts` |
| `cargo-credentials` | file | `~/.cargo/credentials.toml`, `~/.cargo/credentials` | `toml` |
| `terraform-credentials` | file | `~/.terraform.d/credentials.tfrc.json` | `json` |
| `composer-auth` | file | `~/.config/composer/auth.json`, `~/.composer/auth.json` | `json` |
| `gem-credentials` | file | `~/.gem/credentials` | `yaml` |
| `yarnrc` | file | `~/.yarnrc.yml`, `./**/.yarnrc.yml` | `yaml` |
| `gradle-properties` | file | `~/.gradle/gradle.properties` | `ini` |
| `workflows` | file | `./.github/workflows/*.yml`, `*.yaml` | `github_workflow` |
| `process` | probe | - | `process` |
| `container-sockets` | probe | `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/podman/podman.sock`, `/run/buildkit/buildkitd.sock`, `~/.docker/run/docker.sock`, `~/.colima/default/docker.sock`, `~/.rd/docker.sock` | `unix_socket` |
| `proc-environ` | probe | - | `proc_environ` |
| `path-dirs` | probe | every absolute `$PATH` entry (`path-vars = ["PATH"]`), `/usr/local/bin`, `/usr/local/sbin`, `/opt/bin`, `~/bin`, `~/.local/bin` | `writable` |
| `shared-caches` | probe | `~/.cargo/registry`, `~/.cargo/git`, `~/.npm`, `~/.cache/{pip,go-build,yarn}`, `~/.gradle/caches`, `~/.m2/repository`, `/opt/hostedtoolcache` | `writable` |
| `shell-rc` | probe | `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.zshrc`, `~/.zshenv`, `~/.zprofile`, `~/.config/fish/config.fish` | `writable` |
| `git-hooks` | probe | `./.git/hooks/*`, `~/.config/git/hooks/*` | `writable` |
| `suid` | probe | `/usr/local/bin/*`, `/usr/local/sbin/*`, `/opt/bin/*`, `~/bin/*`, `~/.local/bin/*` | `suid` |
| `kube-service-account` | probe | `/var/run/secrets/kubernetes.io/serviceaccount/token`, `/run/secrets/kubernetes.io/serviceaccount/token` | `kube_service_account` |
| `content` | file | `./**/*.{rs,py,js,ts,go,java,rb,php,yml,yaml,json,tf,sh}` (one glob per extension; not in `.git`, `node_modules`, `target`, `vendor`) | `content` |

(Brace lists above are shorthand for this table; the glob syntax has no braces.)

Rules (71), by type. Every default rule has a `category` tag (`key-protection`, `key-strength`,
`file-permissions`, `version-control`, `credential-exposure`, `long-lived-credential`,
`plaintext-storage`, `transport-security`, `ci-permissions`, `privilege`, `policy-hygiene`).

| type | rule ids |
|---|---|
| `ssh_private_key` | `ssh-key-unencrypted`, `ssh-key-world-readable`, `ssh-key-group-readable`, `ssh-key-weak`, `ssh-key-legacy-encryption`, `ssh-key-in-git-repo` |
| `github_token` | `github-classic-token`, `github-token` |
| `jwt` | `jwt-long-lived`, `jwt-no-expiry` |
| `gitlab_token` | `gitlab-token`, `gitlab-ci-job-token` |
| `api_key` | `api-key`, `api-key-test-mode` |
| `aws_access_key_id` | `aws-long-lived-key`, `aws-session-key` |
| `aws_credentials` | `aws-credentials-readable` |
| `gcp_credentials` | `gcp-service-account-key`, `gcp-user-credentials`, `gcp-credentials-readable` |
| `azure_profile` | `azure-service-principal-secret`, `azure-cached-tokens`, `azure-credentials-readable` |
| `kubeconfig` | `kubeconfig-static-credentials`, `kubeconfig-embedded-client-key`, `kubeconfig-insecure-tls`, `kubeconfig-readable` |
| `docker_config` | `docker-inline-credentials`, `docker-config-readable` |
| `npmrc` | `npmrc-inline-token`, `npmrc-token-not-gitignored`, `credential-file-readable-npmrc` |
| `pypirc` | `pypirc-inline-token`, `credential-file-readable-pypirc` |
| `netrc` | `netrc-password`, `netrc-default-entry`, `credential-file-readable-netrc` |
| `git_credentials` | `git-credentials-store`, `credential-file-readable-git` |
| `gh_hosts` | `gh-token-in-file`, `credential-file-readable-gh` |
| `config_entry` | `config-secret-like`, `config-secret-world-readable`, `config-token-not-gitignored` |
| `pem` | `pem-private-key-world-readable`, `pem-private-key-in-git-repo`, `pem-private-key-unencrypted` |
| `github_workflow` | `workflow-write-all`, `workflow-untrusted-trigger-write`, `workflow-untrusted-trigger-default-permissions`, `workflow-pull-request-target`, `workflow-packages-write`, `workflow-contents-write`, `workflow-default-permissions` |
| `dotenv_entry` | `dotenv-token-not-gitignored`, `dotenv-secret-not-gitignored`, `dotenv-secret-world-readable` |
| `env_var` | `env-secret-like` |
| `process` | `process-root`, `process-root-equivalent-group`, `process-sudo-group` |
| `unix_socket` | `container-socket-root` |
| `proc_environ` | `proc-environ-readable` |
| `writable_path_dir` | `writable-path-dir-world`, `writable-cache-dir-group` |
| `writable_file` | `writable-startup-file` |
| `suid_binary` | `suid-sgid-writable`, `suid-not-root-owned`, `file-capabilities` |
| `kube_service_account` | `kube-service-account-token` |
| `waiver` | `waiver-expired` |

Typical adjustments on top of the default:

```toml
version = 1

[scan]
exclude = ["~/Library/**"]          # e.g. avoid macOS permission prompts

[[source]]
id = "proc-environ"                 # disable a default source
enabled = false

[[source]]
id = "ssh"                          # replace a default source's paths
paths = ["~/.ssh/**", "~/keys/**"]

[[rule]]
id = "jwt-long-lived"               # tune a default rule
severity = "high"
```

## Command line

```text
lootr [OPTIONS]                   scan, write the report to stdout (or --output)
lootr [OPTIONS] types [--json]    every type with its attributes (custom types from --config included)
lootr [OPTIONS] explain <RULE>    one enabled rule after all layers, with its type's attributes
lootr [OPTIONS] policy check [FILES]...
                                  validate default + --config + FILES, scan nothing
```

| flag | default | scope | meaning |
|---|---|---|---|
| `--config <PATH>` | - | global, repeatable | config layer after the built-in default; later files override earlier ones; relative to the current directory |
| `--no-default` | off | global | do not load the built-in default layer |
| `--fail-on <SEVERITY>` | `high` | scan | exit 1 if an unwaived finding has at least this severity (`info`, `low`, `medium`, `high`, `critical`) |
| `--format <FORMAT>` | `json` | scan | `json`, `sarif` (SARIF 2.1.0) or `markdown` |
| `--output <FILE>` | stdout | scan | write the report to FILE (created with mode 0600, never through a symlink) |
| `--emit-facts` | off | scan | add every collected fact (and every `waiver` fact) to the JSON report; requires `--format json` (else `--emit-facts needs --format json`, exit 2), conflicts with `--summary-only` |
| `--redact-paths` | off | scan | hide paths outside the working directory (`~/<redacted:1>`), also on stderr |
| `--summary-only` | off | scan | only counts by severity and rule: no findings, locations or facts |
| `-q`, `--quiet` | off | global | only warnings and errors on stderr |
| `-h`, `--help` / `-V`, `--version` | | | |

"Global" flags may be given before or after a subcommand; scan flags only before it
(`lootr types --fail-on low` is a usage error). The `--emit-facts` format check also applies to
`types` and `explain`.

Subcommands:

- `lootr types [--json]` prints every type (entry, document, value, custom, probe and config
  types) with each attribute's kind, documentation and whether it is optional. `--json` prints
  `{"types": [...], "file_attrs": [...], "builtin_variables": [...]}` (the source of
  [types.json](types.json)).
- `lootr explain <RULE>` prints `rule`, `type`, `severity`, `when`, `message`, `remediation`,
  `tags`, `locked` (with the locking layer), `defined in` (the last layer that touched it) and the
  type's attributes. An unknown or disabled rule id is an error (exit 2) listing the enabled ids.
- `lootr policy check [FILES]` loads the default (unless `--no-default`), every `--config`, then
  `FILES`, validates everything and prints `policy ok: N layers, N sources, N enabled rules
  (N locked), N custom types, N waivers`, the layers in order, locked rules and waivers with the
  days until they expire. It reads only the config files: no environment, no home directory
  (`~` in waiver paths expands to `/nonexistent-home`), no scan. Expired waivers are warnings.
  Without any file it warns that only the built-in default was checked. Use it in the CI of a
  policy repository.

The `types`, `explain` and `policy check` subcommands load and validate the config exactly like
a scan but read nothing else (`types` and `explain` expand `~` against the real home directory).

## Exit codes

| code | meaning |
|---|---|
| `0` | no unwaived finding at or above `--fail-on`; or the subcommand succeeded |
| `1` | at least one unwaived finding at or above `--fail-on`, or a skipped entry whose reason is in `[scan] fail-on-skipped` |
| `2` | error: invalid config, a rule that failed to evaluate (`rule_error`, even if findings exist), I/O error writing the report, unknown rule for `explain`, `--emit-facts` without JSON, command line usage error |

## Validation errors

All problems of all layers are printed at once, one per line, then a summary; the run exits 2
before anything is scanned. TOML errors show the position and a fixed description only, never
text from the file: a secrets file passed as `--config` or `include` by mistake (`.env`,
`~/.git-credentials`) must not end up in a CI log. A config file is read only if it is a regular
file (a symlink to one is followed; FIFOs and devices are refused without opening them) of at
most 1 MiB. Examples (paths shortened):

```text
error: src.toml: expected `version = 1`
error: src.toml: line 3, column 1: unknown key, expected one of `max-file-size`, `max-depth`, `one-file-system`, `exclude`, `fail-on-skipped`, `locked` (file content not shown)
error: .env: line 1, column 10: invalid TOML syntax (file content not shown)
error: src.toml: scan.max-file-size: `1TiB` is not a size (e.g. 1MiB, 512KiB)
error: src.toml: scan.max-depth must be at least 1
error: src.toml: scan.exclude: invalid glob `[abc`: unclosed `[`
error: src.toml: include `https://example.com/a.toml`: only local files can be included
error: missing.toml: cannot read config: not found
error: src.toml: source `a`: set exactly one of `type` (a document type) or `extract` (an extractor)
error: src.toml: source `b`: `names` is required for kind `env`
error: src.toml: source `c`: unknown probe `nope` (known: process, unix_socket, proc_environ, writable, suid, kube_service_account)
error: src.toml: source `d`: unknown kind `socket` (env, file, probe)
error: src.toml: source `e`: `names` is not allowed for kind `file`
error: src.toml: source `f`: unknown extractor `xml` (known: dotenv, ini, json, yaml, toml, content)
error: src.toml: source `typo-src` overrides nothing: no earlier layer defines this source (check the id; a new source needs `kind`)
error: src.toml: type: `bad re` is not a valid identifier (1 to 128 characters: letters, digits, `_ - . / : @ + %`)
error: src.toml: type `env_var`: type `env_var` is defined twice
error: src.toml: rule `x`: unknown type `ssh_key` (known: ...)
error: src.toml: rule `x`: `when` is required
error: src.toml: rule `x`: unknown placeholder `{user}` (known: path, name, type, rule, source, location, uid, is_root, groups, in_container)
error: src.toml: waiver for `nope`: unknown rule
error: src.toml: waiver for `nope`: `reason` must not be empty
error: src.toml: waiver for `process-root`: path `~/a/*/../b`: `..` after a wildcard
error: src.toml: waiver for `process-root`: `expires = 2027-01-01T00:00:00Z` must be a date (YYYY-MM-DD)
error: invalid config (N problems); nothing was done
```

CEL errors in `when` (unknown attributes, functions, syntax) are listed in
[cel.md](cel.md#load-time-checks).
