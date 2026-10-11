# Report formats

Reference for what `lootr` writes: the JSON report (`schema_version` 1), SARIF 2.1.0, Markdown,
the type reference of `lootr types --json`, and the exit codes. It describes the code in
`src/report/` and the serde attributes in `src/domain/model.rs`. For the config file see
[config-reference.md](config-reference.md), for rule conditions [cel.md](cel.md).

All formats are rendered from one format-independent model (`report::Report`). Paths are mapped
once when the model is built, so JSON, SARIF, Markdown and the stderr lines show the same paths.
Only facts reach a report: no format can contain secret values.

| Flag | Effect |
|---|---|
| `--format json` (default) | JSON report, see [JSON report](#json-report) |
| `--format sarif` | SARIF 2.1.0, see [SARIF](#sarif-210) |
| `--format markdown` | Markdown, see [Markdown](#markdown) |
| `--output FILE` | write the report to `FILE` instead of stdout (new files get mode 0600, never written through a symlink; relative to the working directory) |
| `--emit-facts` | add `facts` to the JSON report; JSON only, not with `--summary-only` |
| `--summary-only` | counts only: no findings, facts or locations |
| `--redact-paths` | hide paths outside the working directory, see [Paths](#paths) |
| `--fail-on SEVERITY` | threshold for exit code 1 (default `high`) |

Progress, warnings (expired waivers) and errors (rule errors) go to stderr, with the same mapped
paths as the report; `-q` keeps only warnings and errors.

## JSON report

Pretty-printed JSON (two-space indent) followed by a newline. Object keys appear in the order
listed below; maps (`tags`, `attrs`, `by_rule`, map attributes) are sorted by key.

### Top level

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | `1` |
| `tool` | object | [`tool`](#tool) |
| `run` | object | [`run`](#run) |
| `custom_types` | array | [`custom_types`](#custom_types) |
| `summary` | object | [`summary`](#summary) |
| `findings` | array | [Finding](#finding) objects |
| `rule_errors` | array | [`rule_errors`](#rule_errors) |
| `expired_waivers` | array | [`expired_waivers`](#expired_waivers) |
| `skipped` | array | [`skipped`](#skipped) |
| `facts` | array | only with `--emit-facts` (key absent otherwise), see [`facts`](#facts---emit-facts) |

With `--summary-only` only `schema_version`, `tool`, `run`, `custom_types` and `summary` are
written.

### `tool`

| Field | Type | Notes |
|---|---|---|
| `name` | string | always `"lootr"` |
| `version` | string | crate version, e.g. `"0.1.0"` |

### `run`

| Field | Type | Notes |
|---|---|---|
| `started_at` | string | scan start, UTC, RFC 3339 with seconds: `"2026-10-08T14:03:00Z"` |
| `duration_ms` | integer | wall time of the run in milliseconds |
| `uid` | integer | real user id lootr ran as |
| `home` | string or `null` | absolute home directory (not `~`-normalized); `null` if unknown; `"<redacted>"` with `--redact-paths` |
| `cwd` | string | absolute working directory; `"<redacted>"` with `--redact-paths` |
| `config_layers` | array of strings | layers in the order applied: `"<built-in>"` for the default layer, then config files (mapped like any path) |
| `fail_on` | string | the `--fail-on` severity |

### `custom_types`

Every `[[type]]` from the config, so a reader can spot a config that probes for specific secret
values. Empty with the built-in default only.

| Field | Type | Notes |
|---|---|---|
| `name` | string | type name |
| `pattern` | string | the regex as configured |

### `summary`

| Field | Type | Notes |
|---|---|---|
| `candidates` | integer | what discovery selected: env vars, files, probe targets |
| `facts` | integer | all facts, including one `waiver` fact per configured waiver |
| `findings` | integer | all findings, waived ones included |
| `waived` | integer | findings with a matching, unexpired waiver |
| `failing` | integer | unwaived findings at or above `fail_on` (exit code 1 if > 0) |
| `by_severity` | object | unwaived findings per severity: `critical`, `high`, `medium`, `low`, `info` (always all five keys) |
| `rule_errors` | integer | length of `rule_errors` (exit code 2 if > 0) |
| `expired_waivers` | integer | length of `expired_waivers` |
| `skipped` | integer | length of `skipped` |
| `failing_skipped` | integer | skipped entries whose reason is in `[scan] fail-on-skipped` (exit code 1 if > 0) |
| `by_rule` | object | rule id → number of unwaived findings; rules without unwaived findings are absent |

### Finding

Sorted by severity (highest first), then rule id, then location (file before env before probe,
then by path and key path).

| Field | Type | Notes |
|---|---|---|
| `rule` | string | rule id |
| `severity` | string | `"info"`, `"low"`, `"medium"`, `"high"` or `"critical"` |
| `message` | string | the rule's `message` template rendered with the fact (default `{type} at {location} matches rule {rule}`); the location path inside it is mapped |
| `remediation` | string | rendered `remediation`, `""` if the rule has none |
| `tags` | object | rule tags, string → string (`{}` if none) |
| `waived` | object or `null` | `null`, or `{"reason": string, "expires": "YYYY-MM-DD" or null}` of the matching waiver |
| `fact` | object | the [Fact](#fact) the rule matched |

Severity order: `info < low < medium < high < critical`.

### Fact

| Field | Type | Notes |
|---|---|---|
| `type` | string | type name (`"ssh_private_key"`, a custom type, `"waiver"`, ...) |
| `location` | object | [Location](#location) |
| `source` | string | id of the config source that produced it; `"config"` for `waiver` facts |
| `attrs` | object | attribute name → [value](#attribute-values); keys sorted |

`attrs` holds the attributes listed for the type in `lootr types --json`
([`docs/types.json`](types.json) for the built-in types), plus the file attributes (`file_attrs`
in the same output) when the type allows them and the fact comes from a file. Optional
attributes are left out when absent; no attribute is ever `null`.

### Location

Tagged by `kind`:

| `kind` | Fields | Text form (messages, Markdown, SARIF) |
|---|---|---|
| `"file"` | `path` (string, mapped), `key_path` (string, only when set) | `path` or `path#key_path` |
| `"env"` | `name` (string) | `$NAME` |
| `"probe"` | `name` (string) | `probe:name` |

```json
{"kind": "file", "path": "~/proj/.env", "key_path": "GH_TOKEN"}
{"kind": "file", "path": "~/.ssh/id_ed25519"}
{"kind": "env", "name": "GH_TOKEN"}
{"kind": "probe", "name": "process"}
```

`key_path` is the entry inside a file: a dotenv key, a dotted extractor key (`section.key`,
`a.b.0.c`), a workflow job (`jobs.<id>`), a line (`L2`, content scanning), or `[[waiver]] #n`
for waiver facts (whose `path` is the config file). Per-value facts of the `proc_environ` probe
use a probe location named `proc_environ:<process name>` (the pid if the process has no
name).

### Attribute values

Every attribute has one of the kinds of `lootr types` (`attrs[].kind`). Values are plain JSON:

| Kind | JSON | Notes |
|---|---|---|
| `bool` | `true` / `false` | |
| `int` | number | 64-bit signed. `mode` is the permission bits as a decimal number (`0600` → `384`, `0644` → `420`); messages render `{mode}` in octal |
| `sym` | string | closed vocabulary compiled into the binary (`"rsa"`, `"classic"`, `"write"`) |
| `name` | string | identifier: 1-128 bytes of ASCII letters, digits and `_ - . / : @ + %` |
| `text` | string | non-secret text (JWT issuer, context name, waiver reason); control characters replaced by U+FFFD, cut to 256 characters (the last one `…`) |
| `path` | string | a path, mapped like locations (`~`, `--redact-paths`) |
| `list` | array | of any of these values |
| `map` | object | keys are identifiers (sorted), values any of these values |

Dates in `waiver` facts (`expires`) are `text` in `YYYY-MM-DD` form. `text` attributes are not
redacted by `--redact-paths`.

### `rule_errors`

A rule whose condition failed to evaluate for a fact (type mismatch, ordering across types, ...).
Never counted as "no finding": any entry makes the run exit with 2.

| Field | Type | Notes |
|---|---|---|
| `rule` | string | rule id |
| `type` | string | type of the fact |
| `location` | object | [Location](#location) of the fact |
| `message` | string | the CEL error (built from fact values only; location path mapped) |

### `expired_waivers`

Waivers past their `expires` date. They are ignored (their findings count again) and also produce
a `waiver` fact with `expired = true`, which the default rule `waiver-expired` reports as a
finding.

| Field | Type | Notes |
|---|---|---|
| `rule` | string | waived rule id |
| `path` | string or `null` | path glob as written in the config (not mapped) |
| `name` | string or `null` | env var name / key path as written |
| `reason` | string | |
| `expires` | string | `YYYY-MM-DD` |
| `layer` | string | config file that defined it (mapped like a path) |

### `skipped`

Something a source selected but lootr did not interpret, completely or at all. Reported,
never fatal by itself; `[scan] fail-on-skipped` makes chosen reasons fail the run (exit code 1).
A skipped entry is a possible false negative: whatever is there was not (fully) checked.

| Field | Type | Notes |
|---|---|---|
| `source` | string | source id |
| `location` | object | [Location](#location) (a file location) |
| `reason` | string | stable code, see below |
| `detail` | string | human-readable detail: static text or an OS error description, never file content |

`reason` codes: `not_found`, `permission_denied`, `symlink` (not followed), `not_regular`
(FIFO, socket, device; `detail` names the kind), `too_large` (above `max-file-size`), `io_error`
(other OS error), `parse_error` (a document type or extractor rejected the file; `detail` starts
with the type or extractor name), `invalid_path` (a source path pattern that could not be
expanded or compiled; `location.path` is the pattern), `not_recognized` (a file named literally
in a source that its document type does not recognize), `binary` (the `content` extractor did
not scan a file with a NUL byte in its first 8 KiB), `truncated` (only the first part was
scanned: `content` after 10 000 token runs, a foreign process environment larger than 256 KiB at
`probe:proc_environ:<name>`; the facts from that part are reported), `depth_limit` (a directory a
`**` walk did not enter because of `max-depth`), `other_fs` (a directory on another device, with
`one-file-system`), `symlink_root` (a glob's literal prefix is a symlink that was not followed:
another user's, or not to a real directory; `detail` says which). A skipped entry and facts for
the same file can both be present (partial scans).

### `facts` (`--emit-facts`)

Every fact of the run as [Fact](#fact) objects, in collection order (sources in config order,
before any rule ran), followed by one `waiver` fact per configured waiver (location
`{"kind": "file", "path": "<config file>", "key_path": "[[waiver]] #1"}`, source `"config"`).
Facts carry derived, non-secret data only, so the array can be handed to jq, OPA or a data
warehouse. `--no-default` plus a config with only sources collects facts without any rule:

```sh
lootr --emit-facts | jq '.facts[] | select(.type == "ssh_private_key" and .attrs.encrypted == false)'
lootr --no-default --config sources-only.toml --emit-facts > facts.json
```

`--emit-facts` with `--format sarif` or `--format markdown` is an error (exit 2), and so is the
combination with `--summary-only`.

### Example

A run with `--no-default --config ./lootr.toml` (an env source, an ssh source, a dotenv source, a
custom type `acme_api_key`, three rules and two waivers, one of them expired) on a fake home with
dummy keys. Shortened: one of the four findings and most attributes are left out, and the
absolute temp paths in `run` are replaced by `/home/dev`. Exit code 1.

```json
{
  "schema_version": 1,
  "tool": {
    "name": "lootr",
    "version": "0.1.0"
  },
  "run": {
    "started_at": "2026-10-08T22:03:56Z",
    "duration_ms": 11,
    "uid": 501,
    "home": "/home/dev",
    "cwd": "/home/dev/proj",
    "config_layers": [
      "~/proj/lootr.toml"
    ],
    "fail_on": "high"
  },
  "custom_types": [
    {
      "name": "acme_api_key",
      "pattern": "^acme_[A-Za-z0-9]{32}$"
    }
  ],
  "summary": {
    "candidates": 5,
    "facts": 8,
    "findings": 4,
    "waived": 1,
    "failing": 2,
    "by_severity": {
      "critical": 0,
      "high": 2,
      "medium": 0,
      "low": 1,
      "info": 0
    },
    "rule_errors": 0,
    "expired_waivers": 1,
    "skipped": 1,
    "failing_skipped": 0,
    "by_rule": {
      "acme-key-anywhere": 1,
      "deploy-token-in-env": 1,
      "ssh-key-unencrypted": 1
    }
  },
  "findings": [
    {
      "rule": "acme-key-anywhere",
      "severity": "high",
      "message": "ACME API key in ~/proj/.env#ACME_KEY",
      "remediation": "Rotate the key and remove it from ACME_KEY",
      "tags": {},
      "waived": null,
      "fact": {
        "type": "acme_api_key",
        "location": {
          "kind": "file",
          "path": "~/proj/.env",
          "key_path": "ACME_KEY"
        },
        "source": "dotenv",
        "attrs": {
          "charset": "base64url",
          "entropy": 88,
          "gitignored": false,
          "length": 37,
          "mode": 420
        }
      }
    },
    {
      "rule": "ssh-key-unencrypted",
      "severity": "high",
      "message": "SSH private key ~/.ssh/dummy_id_ecdsa is not encrypted",
      "remediation": "Set a passphrase: ssh-keygen -p -f ~/.ssh/dummy_id_ecdsa",
      "tags": {
        "category": "key-protection"
      },
      "waived": {
        "reason": "Hardware-bound deploy key, rotated weekly",
        "expires": "2030-01-31"
      },
      "fact": {
        "type": "ssh_private_key",
        "location": {
          "kind": "file",
          "path": "~/.ssh/dummy_id_ecdsa"
        },
        "source": "ssh",
        "attrs": {
          "age_days": 0,
          "encrypted": false,
          "key_type": "ecdsa",
          "mode": 384,
          "world_readable": false
        }
      }
    },
    {
      "rule": "deploy-token-in-env",
      "severity": "low",
      "message": "env_var at $DEPLOY_TOKEN matches rule deploy-token-in-env",
      "remediation": "",
      "tags": {},
      "waived": null,
      "fact": {
        "type": "env_var",
        "location": {
          "kind": "env",
          "name": "DEPLOY_TOKEN"
        },
        "source": "env",
        "attrs": {
          "classified_as": [],
          "entropy": 167,
          "length": 35,
          "name": "DEPLOY_TOKEN"
        }
      }
    }
  ],
  "rule_errors": [],
  "expired_waivers": [
    {
      "rule": "acme-key-anywhere",
      "path": null,
      "name": "ACME_KEY",
      "reason": "Sandbox key",
      "expires": "2026-01-31",
      "layer": "~/proj/lootr.toml"
    }
  ],
  "skipped": [
    {
      "source": "ssh",
      "location": {
        "kind": "file",
        "path": "~/.ssh/agent.fifo"
      },
      "reason": "not_regular",
      "detail": "not a regular file (fifo)"
    }
  ]
}
```

A rule error entry has the shape:

```json
{"rule": "broken", "type": "env_var", "location": {"kind": "env", "name": "MULTI"}, "message": "..."}
```

## Paths

Applied to every location path, `path` attribute, config layer name and expired waiver layer,
and to the location path inside rendered messages, in every format and on stderr. Rules, waivers
and CEL always see absolute paths; only the presentation changes.

- **`~` normalization** (always on): a path below the home directory is shown as `~/rest`, the
  home itself as `~`. `run.home` keeps the absolute home so consumers can expand it again. The
  comparison is textual (no symlink resolution): if `HOME` points through a symlink and the
  working directory does not (e.g. `/var` vs. `/private/var` on macOS), project paths stay
  absolute.
- **`--redact-paths`**: paths below the working directory stay visible, relative (`./src/.env`,
  `.` for the directory itself); every other path becomes a numbered placeholder that keeps only
  its anchor: `~/<redacted:N>` below the home, `<redacted:N>` elsewhere. The same path keeps its
  number within one report. If the working directory is `/`, the home directory or above it,
  every path is redacted. `run.home` and `run.cwd` become `"<redacted>"`.
- Not paths found on the machine, so never redacted: waiver globs (`expired_waivers[].path`,
  `waived_path`), text from message templates, and `text` attributes (issuers, context names).
- Names that are not absolute paths (`<built-in>`) are left as they are.

## SARIF 2.1.0

`--format sarif` writes one SARIF log with one run:

```
{"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
 "version": "2.1.0",
 "runs": [{"tool", "invocations", "originalUriBaseIds", "results", "properties"}]}
```

### Rules (`runs[0].tool.driver`)

`driver` has `name` (`"lootr"`), `version` and `semanticVersion` (both the crate version) and
`rules`: one `reportingDescriptor` per **enabled** rule, in config order (a result's `ruleIndex`
points into this array).

| reportingDescriptor field | Value |
|---|---|
| `id`, `name` | rule id |
| `shortDescription.text` | the message template (or the default one) with placeholders shown as `<name>`: `SSH private key <path> is not encrypted` |
| `fullDescription.text` | `Matches <type> facts where: <when>` (whitespace in the condition collapsed) |
| `help.text` | the remediation template with `<name>` placeholders; absent if the rule has none |
| `defaultConfiguration.level` | level of the rule's severity (below) |
| `properties.tags` | `"security"`, then each rule tag as `"key/value"` |
| `properties.security-severity` | GitHub score as a string; absent for `info` |
| `properties.lootr-type` | fact type |
| `properties.lootr-severity` | severity name |
| `properties.lootr-locked` | boolean |

| Severity | `level` | `security-severity` |
|---|---|---|
| `critical` | `error` | `"9.5"` |
| `high` | `error` | `"8.0"` |
| `medium` | `warning` | `"5.5"` |
| `low` | `note` | `"3.0"` |
| `info` | `note` | (none) |

### Results (`runs[0].results`)

One result per finding (waived ones included), in report order:

| result field | Value |
|---|---|
| `ruleId`, `ruleIndex` | rule id and its index in `driver.rules` |
| `level` | level of the finding's severity |
| `message.text` | rendered message (paths mapped) |
| `locations` | one location, see below |
| `partialFingerprints["lootr/v1"]` | `<rule>\|<location text>` with the location as shown in the report (`ssh-key-unencrypted\|~/.ssh/id_ed25519`), stable across runs |
| `suppressions` | waived findings only: `[{"kind": "external", "status": "accepted", "justification": "<reason> (waived until YYYY-MM-DD)"}]` (the suffix only with an expiry date) |
| `properties` | `severity`, `type` (fact type), `source`, `remediation` (if not empty), `tags` (object, if any) |

Locations:

| Report location | SARIF location |
|---|---|
| file below the working directory | `physicalLocation.artifactLocation`: `{"uri": "<relative, percent-encoded>", "uriBaseId": "%SRCROOT%"}` |
| other file (not redacted) | `{"uri": "file:///absolute/path"}` (`~` expanded with `run.home`) |
| other file with `--redact-paths` | no physical location; `logicalLocations: [{"name": "~/<redacted:1>", "kind": "resource"}]` |
| file with `key_path` | the physical location above (if any) plus `logicalLocations: [{"name": "<key_path>", "fullyQualifiedName": "<path>#<key_path>", "kind": "variable"}]` |
| env var | `logicalLocations: [{"name": "NAME", "fullyQualifiedName": "$NAME", "kind": "variable"}]` |
| probe | `logicalLocations: [{"name": "<probe>", "fullyQualifiedName": "probe:<probe>", "kind": "resource"}]` |

URIs percent-encode every byte except ASCII letters, digits and `- . _ ~ /`.
`originalUriBaseIds["%SRCROOT%"]` is `{"uri": "file:///<cwd>/"}`, or
`{"description": {"text": "the working directory lootr ran in"}}` with `--redact-paths`. GitHub
code scanning only shows results with a file in the repository (run lootr from the checkout
root); the other results stay in the file.

### Invocation and properties

`runs[0].invocations[0]`:

- `executionSuccessful`: `false` if there is a rule error.
- `startTimeUtc`: `run.started_at`.
- `toolExecutionNotifications`: one `error` per rule error
  (``rule `x` failed on <type> at <location>: <message>``, with `locations` and
  `associatedRule: {"id", "index"}`), and one `note` per skipped file
  (`skipped <location> (source <id>): <detail>`, with `locations`).
- `toolConfigurationNotifications`: one `warning` per expired waiver
  (``waiver for `x` in <layer> expired on YYYY-MM-DD; its findings are reported again``, with
  `associatedRule`).

`runs[0].properties` is `{"fail_on": "<severity>", "summary": {...}}` with the JSON
[`summary`](#summary) object.

lootr itself writes no `automationDetails`. The GitHub Action (`action.yml`) sets
`runs[0].automationDetails.id` to `<category>/` before uploading, so several lootr jobs keep
their own alerts.

### `--summary-only`

No `results` key (do not upload such a file to code scanning: it would neither open nor close
alerts). Rules, `properties.summary` and the expired waiver notifications stay; rule error
notifications have no location (``rule `x` failed on a <type> fact``); skipped files are left
out.

## Markdown

For pull request comments, job summaries (`$GITHUB_STEP_SUMMARY`) and merge request notes.
Structure:

1. `## lootr report`
2. The result: ``**Result: error**: N rules failed to evaluate (exit code 2).``, or
   ``**Result: failed**: N unwaived findings at or above `high`, N skipped entries with a
   `fail-on-skipped` reason.`` (either part as present), or
   ``**Result: passed**: no unwaived finding at or above `high`.``
3. Table `| Severity | Findings | Waived |` with one row per severity (critical first) and a
   `**total**` row; `Findings` counts unwaived findings.
4. A line `lootr <version> · N facts · N candidates[ · N expired waivers][ · N skipped] · config:
   <layers>`.
5. With `--summary-only`: a `| Rule | Findings |` table from `by_rule` (if not empty), then the
   output ends.
6. `### Findings`, then `#### <severity> (N)` per severity with unwaived findings, one item per
   finding: ``- **`rule`** at `location`: `message` ``, with sub-items `Remediation:` and `Tags:`
   (one `key=value` code span per tag) when present.
7. `### Waived (N)`: table `| Severity | Rule | Location | Reason | Expires |` (`never` without
   an expiry date).
8. `### Expired waivers (N)`: ``- `rule` (path `glob`, name `X`) in `layer` expired on DATE: `reason` ``.
9. `### Rule errors (N)`: ``- `rule` failed on `type` at `location`: `message` ``.
10. `<details><summary>Skipped (N)</summary>` with ``- `location` (source `id`): `detail` ``,
    collapsed.

Sections 6-10 appear only when they have entries.

**Escaping.** Every value that comes from the scan or the config (rule ids, locations, messages,
remediations, tags, reasons, layers, details) is written as an inline code span, so a key named
`@org/team`, a JWT issuer `https://...` or text like `<img>` cannot become a mention, a link or
HTML. The code span helper replaces control characters by spaces, uses a backtick fence one
longer than the longest backtick run in the value (padded with a space when the value starts or
ends with a backtick), writes `-` for an empty or blank value, and inside tables escapes `|` as
`\|` (GFM splits cells on it even inside code spans). Text from the binary (severity names,
counts, dates, the version) is written as is.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no unwaived finding at or above `--fail-on` (default `high`); for subcommands: success (`policy check`: config valid; expired waivers are only warnings) |
| `1` | at least one unwaived finding at or above `--fail-on` (`summary.failing > 0`), or a skipped entry with a `fail-on-skipped` reason (`summary.failing_skipped > 0`); the report is written |
| `2` | error: a rule error (the report is still written; 2 wins over 1), invalid config (nothing is scanned, no report), invalid arguments (e.g. `--emit-facts` with `--summary-only` or a non-JSON format), failure writing the report, a failed scan, `explain` with an unknown rule |

Waived findings never affect the exit code.

## Type reference: `lootr types --json`

[`docs/types.json`](types.json) is the output of `lootr types --json` with only the built-in
default config. `tests/docs.rs` checks that it is up to date;
`LOOTR_UPDATE_DOCS=1 cargo test --test docs` regenerates it. With a config that defines
`[[type]]` entries the output also lists those types (kind `custom`).

| Field | Type | Notes |
|---|---|---|
| `types` | array | one object per type, in registry order |
| `types[].name` | string | type name, as in `fact.type` and a rule's `type` |
| `types[].kind` | string | `document` (whole file), `value` (single value), `custom` (config regex), `entry` (generic per-value fact: `env_var`, `dotenv_entry`, `config_entry`), `probe`, `config` (`waiver`) |
| `types[].doc` | string | one-line description |
| `types[].attrs` | array | `{"name", "kind", "doc", "optional"}`; `kind` as in [Attribute values](#attribute-values) |
| `types[].file_attrs` | boolean | facts of this type get the file attributes when found in a file |
| `file_attrs` | array | the file attributes, same shape as `attrs` |
| `builtin_variables` | array of strings | names every rule can use besides attributes: `type`, `source`, `location`, `attrs` |

## Schema stability

`schema_version` (currently `1`) versions the JSON report layout, including the fact, location
and attribute value shapes and the `lootr types --json` output. It is bumped on incompatible
changes. lootr is pre-1.0 and unreleased: until the first release, additions are made without a
bump (e.g. `summary.by_rule`).

Breaking (bump `schema_version`):

- removing or renaming a field, or changing its type or meaning;
- changing the shape of `Location`, `Fact`, `waived` or an attribute value kind;
- changing an existing string code (severity names, location kinds, `skipped.reason` codes,
  `sym` values of an attribute);
- changing how a count is defined (e.g. `by_severity` including waived findings);
- removing an attribute from a built-in type or changing its kind.

Not breaking (consumers must tolerate them):

- new fields in any object, new top-level keys;
- new types, new attributes (optional or not), new `skipped.reason` codes, new `sym` values;
- new or changed rules in the built-in default config, and different message texts;
- a different order of arrays other than the documented sort of `findings`.

Values that change between runs and should be ignored when comparing reports: `run.started_at`,
`run.duration_ms`, `tool.version`, and time-dependent attributes such as `age_days`,
`expires_in_hours`, `expires_in_days`.

SARIF follows the SARIF 2.1.0 schema. Its lootr-specific parts (`lootr-*` rule properties,
result `properties`) follow the same rules as the JSON report; the fingerprint key is versioned
on its own (`lootr/v1`), because changing it reopens code scanning alerts. The Markdown output is
meant for people and has no stability guarantee.
