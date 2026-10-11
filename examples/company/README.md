# Company policy example

Three config layers on top of lootr's built-in default, as a company would split them:

| file | owner | applied | purpose |
|------|-------|---------|---------|
| (built-in default) | lootr | 1st | sources and rules for every type (`lootr explain <rule>`) |
| [`baseline.toml`](baseline.toml) | security team | 2nd | locks the rules that matter, a company key format, rules over waivers |
| [`team-platform.toml`](team-platform.toml) | platform team | 3rd | tunes what the baseline leaves open |
| [`project.toml`](project.toml) | the project (as its `lootr.toml`) | 4th | accepted exceptions (waivers) with reasons and expiry dates |

```sh
lootr --config baseline.toml --config team-platform.toml --config project.toml
```

The order is the trust order: later layers can only do what earlier ones allow. Distribute the
baseline the way you distribute other policy (a pinned package, a config management run, a
reviewed policy repository); lootr never downloads config.

## 1. The baseline locks rules

A rule with `locked = true` keeps its type, condition and (minimum) severity for every later layer.
Later layers may raise its severity and change its message, remediation and tags; nothing else.
Only the layer that locks a rule may waive it.

`baseline.toml` locks the default rules for unencrypted and world-readable SSH keys, classic GitHub
tokens, long-lived AWS keys, tokens in `.env` files that git does not ignore, and every
`credential-file-readable-*` rule (npmrc, pypirc, netrc, git, gh) plus `aws-credentials-readable`.
It only names the fields it changes (`locked`, `severity`, `tags`); type and condition come from the
default layer. It also adds:

- a custom type `acme_api_key` (regex only) with a locked rule `acme-api-key`;
- `tags = { control = "ACME-SEC-.." }` on its rules; tags are merged key by key across layers, so
  reports show both lootr's `category` and the company's control id;
- rules over **waivers**: every configured waiver is also a fact of type `waiver` (`lootr types`
  lists its attributes: `waived_rule`, `reason`, `expires`, `expired`, `expires_in_days`,
  `matched`, `waived_path`, `waived_name`). The baseline raises the default `waiver-expired` to
  high and locks it, adds `waiver-without-expiry` (every waiver must expire) and `waiver-unused`
  (a waiver that matched nothing in this run, info).

## 2. The team layer tunes the rest

`team-platform.toml` disables `process-sudo-group` (the team's build users have sudo on purpose),
raises `workflow-default-permissions` to medium, and gives the locked `ssh-key-unencrypted` a
team-specific remediation and a `team` tag: both are allowed on a locked rule.

## 3. The project waives what it accepts

`project.toml` has three waivers. A waiver names a rule and narrows it with a `path` glob (`~`
and relative paths are expanded; `*`, `**`, `?`, `[...]`) and/or a `name` (env var name or the
key path inside a file); without either it waives the rule everywhere. It needs a `reason` and
should have an `expires` date (here the baseline insists). Waived findings stay in the report,
marked as waived with the reason, and do not count for `--fail-on`.

The third waiver expired on 2026-06-30: lootr ignores it, reports the finding again and reports
the waiver itself as `waiver-expired`, located at `project.toml#[[waiver]] #3`.

## Check the policy without scanning

`lootr policy check` loads and validates the layers and prints what they add up to. It reads only
the config files: no environment, no home directory, nothing is scanned. Use it in the CI of the
repository that holds the policy:

```console
$ lootr policy check baseline.toml team-platform.toml project.toml
warning: waiver for `gh-token-in-file` (project.toml [[waiver]] #3) expired on 2026-06-30: scans ignore it and report `waiver-expired`
policy ok: 4 layers, 23 sources, 65 enabled rules (14 locked), 1 custom type, 3 waivers

layers (in order):
  1. <built-in>
  2. baseline.toml
  3. team-platform.toml
  4. project.toml

locked rules:
  ssh-key-unencrypted (high, locked by baseline.toml)
  ...
waivers:
  netrc-password path ~/.netrc, until 2030-06-30 (1361 days) (project.toml [[waiver]] #1): Read-only mirror credentials ...
  env-secret-like name TEST_DB_PASSWORD, until 2030-06-30 (1361 days) (project.toml [[waiver]] #2): Password of the throwaway ...
  gh-token-in-file path ~/.config/gh/hosts.yml, expired on 2026-06-30 (project.toml [[waiver]] #3): Until the keyring ...
```

A project layer that tries to get around the baseline does not load. Every problem is reported at
once, with the file, the rule, the locking layer and what was attempted; the exit code is 2 and
nothing is scanned:

```toml
# bad-project.toml
version = 1

[[rule]]
id = "credential-file-readable-netrc"
enabled = false

[[rule]]
id = "github-classic-token"
severity = "medium"

[[waiver]]
rule = "ssh-key-unencrypted"
path = "~/.ssh/id_ed25519"
reason = "I will fix it later"
expires = 2026-12-31
```

```console
$ lootr policy check baseline.toml team-platform.toml bad-project.toml
error: bad-project.toml: rule `credential-file-readable-netrc` is locked by baseline.toml; this layer tries to disable it (`enabled = false`). A locked rule only accepts a higher severity and a new message, remediation or tags
error: bad-project.toml: rule `github-classic-token` is locked by baseline.toml; this layer tries to lower its severity from critical to medium. A locked rule only accepts a higher severity and a new message, remediation or tags
error: bad-project.toml: waiver for `ssh-key-unencrypted`: rule is locked by baseline.toml; only that layer may waive it
error: invalid config (3 problems); nothing was done
```

(Paths in error messages are absolute; they are shortened here.) A typo in an override is an
error too: `rule \`ssh-key-unencrpyted\` overrides nothing: no earlier layer defines this rule`.

`lootr explain <rule>` shows a single rule after all layers, including who locked it:

```console
$ lootr --config baseline.toml --config team-platform.toml explain ssh-key-unencrypted
rule         ssh-key-unencrypted
type         ssh_private_key
severity     high
when         !encrypted
...
tags         category=key-protection, control=ACME-SEC-01, team=platform
locked       yes (by /etc/lootr/baseline.toml)
defined in   /etc/lootr/team-platform.toml
```

## What a scan reports

The container scenario [`company-policy`](../../containers/scenarios/company-policy/Containerfile)
runs exactly these files on a developer account with an unencrypted SSH key, a `~/.netrc` readable
by others, a gh token file, a classic token in a committed `.env`, an ACME key and a test database
password in the environment ([expected report](../../containers/scenarios/company-policy/expected.json)):

| severity | rule | why |
|----------|------|-----|
| critical | `github-classic-token` | raised and locked by the baseline |
| high | `acme-api-key` | the company's own key type |
| high | `credential-file-readable-netrc` | locked: the project's netrc waiver does not cover it |
| high | `dotenv-token-not-gitignored`, `ssh-key-unencrypted` | locked |
| high | `waiver-expired` | the expired gh waiver, raised by the baseline |
| medium | `github-token`, `workflow-default-permissions` | default / raised by the team |
| low | `gh-token-in-file` | its waiver expired |
| waived | `netrc-password`, `env-secret-like` (`TEST_DB_PASSWORD`) | project waivers |

`process-sudo-group` does not fire although the user is in `sudo`: the team disabled it.
