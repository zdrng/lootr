# Policy language (CEL)

A rule's `when` is a [CEL](https://github.com/google/cel-spec) expression. lootr evaluates it once
per fact of the rule's `type`; `true` produces a finding. CEL has no loops, no side effects and
always terminates. lootr uses the `cel` crate (cel-rust 0.15) with its standard library only and
the `regex` feature; there are no `timestamp`/`duration` types (dates are attributes such as
`age_days` or `expires_in_days`).

CEL only ever sees facts: derived, non-secret attributes. Raw secret values never reach a rule.

See [config-reference.md](config-reference.md#rule) for the other `[[rule]]` fields, placeholders
and layering, [report-schema.md](report-schema.md) for how findings and rule errors appear in
reports, and [types.json](types.json) (`lootr types --json`) for the generated list of every type
and attribute.

Contents: [Variables](#variables) - [Values](#values) -
[Optional attributes](#optional-attributes-and-has) -
[Operators and functions](#operators-and-functions) - [Regular expressions](#regular-expressions) -
[Comparisons](#comparisons-and-type-caveats) - [Load-time checks](#load-time-checks) -
[Runtime errors](#runtime-errors) - [Validating rules](#validating-rules) - [Examples](#examples)

## Variables

| name | CEL type | content |
|---|---|---|
| `<attribute>` | see [Values](#values) | every attribute present on the fact, as a top-level identifier: `encrypted`, `bits`, `kind` |
| `attrs` | map(string, dyn) | the same attributes as a map; for `has(attrs.x)` and attributes whose name is a CEL keyword |
| `type` | string | the fact type, e.g. `"github_token"` |
| `source` | string | id of the config source that produced the fact (`"config"` for `waiver` facts) |
| `location` | map(string, string) | where the fact was found, see below |

`location` keys:

| key | present | value |
|---|---|---|
| `kind` | always | `"file"`, `"env"` or `"probe"` |
| `path` | `kind == "file"` | absolute path (also for paths shown as `~/...` in reports) |
| `key_path` | file locations inside a file | key path: `PASSWORD` (dotenv), `registries.x.token` (json/yaml/toml/ini), `L42` (content scan), `jobs.build` (workflow job), `users.0.user.token` (nested value), `[[waiver]] #2` (waiver) |
| `name` | `kind` `"env"` or `"probe"` | env var name (`GH_TOKEN`) or probe location (`process`, `proc_environ`, `proc_environ:node`) |

Where facts are located:

| facts | `location.kind` | notes |
|---|---|---|
| `env_var` and values classified from env vars | `env` | `name` = variable name |
| document facts (`ssh_private_key`, `kubeconfig`, ...) | `file` | `key_path` only for `github_workflow` (`jobs.<id>`) |
| `dotenv_entry`, `config_entry` and their classified values | `file` | `key_path` = entry key |
| values nested in documents (token in `.netrc`, kubeconfig, ...) | `file` | `key_path` = position in the document |
| values found by the `content` extractor | `file` | `key_path` = `L<line>` |
| `process`, `proc_environ` | `probe` | `name` = `process` / `proc_environ` |
| values from foreign process environments | `probe` | `name` = `proc_environ:<process name>` |
| `unix_socket`, `writable_path_dir`, `writable_file`, `suid_binary`, `kube_service_account` and the service account token's `jwt` | `file` | the probed path, no `key_path` |
| `waiver` | `file` | the config file (`<built-in>` for the default layer), `key_path` = `[[waiver]] #<n>` |

### File attributes

Facts that come from a file read by a `file` source also carry these attributes:

| attribute | kind | meaning |
|---|---|---|
| `mode` | int | permission bits, e.g. `0600` is `384` |
| `world_readable` | bool | others may read the file |
| `group_readable` | bool | the group may read the file |
| `owner_is_self` | bool | owned by the scanning user |
| `age_days` | int | days since the last modification |
| `size` | int | file size in bytes |
| `in_git_repo` | bool | a parent directory has `.git` |
| `gitignored` | bool | the repository's `.gitignore` files or `.git/info/exclude` ignore the file (false outside a repository; global excludes and the index are not considered) |

They are always present on document facts, `dotenv_entry` and `config_entry`. On **value types**
(`github_token`, `jwt`, custom types, ...) they are present only when the value came from a file
read by a file source; a token from an env var, a foreign process environment or the
`kube_service_account` probe has none of them. Rules on value types must therefore guard file
attributes with `has()`, e.g. `has(attrs.world_readable) && world_readable`. `env_var`, probe
facts and `waiver` do not have file attributes at all (probe facts have their own `mode`,
`owner_is_self`, ...).

## Values

How each attribute kind (as listed by `lootr types`) appears in CEL:

| kind | CEL type | examples |
|---|---|---|
| `bool` | `bool` | `encrypted`, `!world_readable` |
| `int` | `int` (64-bit signed) | `bits < 3072`, `age_days > 365`, `mode == 384` |
| `sym` | `string` (a closed vocabulary from the binary) | `key_type == "rsa"`, `kind in ["runner", "deploy"]` |
| `name` | `string` (identifier: letters, digits, `_ - . / : @ + %`) | `name.endsWith("_TOKEN")`, `waived_rule == "x"` |
| `text` | `string` (non-secret text, at most 256 characters, control characters replaced) | `issuer.startsWith("https://")` |
| `path` | `string` (absolute path) | `dir.startsWith("/usr/local")` |
| `list` | `list` of the converted items (strings for all current list attributes) | `"docker" in groups`, `size(write_scopes) > 0` |
| `map` | `map(string, ...)` | `permissions["packages"] == "write"` |

There are no `uint`, `double`, `bytes`, timestamp or null attributes. Notes:

- `mode` is a plain int. CEL has **no octal literals**: `0644` is the decimal number 644. Write
  `mode == 420` or `mode == 0x1A4`; test bits with arithmetic, e.g. `(mode / 8) % 8 >= 4` (group
  read). Usually `world_readable`, `group_readable`, `world_writable`, ... are clearer.
- `sym` values are documented per attribute in `lootr types`; comparing with a value outside the
  vocabulary is simply false.
- Map attributes (`github_workflow.permissions`) have string keys; keys that are not CEL
  identifiers (`id-token`) need `permissions["id-token"]` or `"id-token" in permissions`.

## Optional attributes and `has()`

Attributes marked "(optional)" in `lootr types` (`bits`, `issuer`, `lifetime_hours`, `expires`,
...) are absent on some facts. Referencing an absent attribute as a variable is a runtime error,
not `false`. CEL's `has()` only accepts a field selection (`has(a.b)`), not a bare variable,
which is why the attributes are also available as the map `attrs`:

```cel
has(attrs.lifetime_hours) && lifetime_hours > 24
!has(attrs.checksum_valid) || checksum_valid
has(attrs.bits) ? bits < 3072 : key_type == "dsa"
```

`&&` and `||` short-circuit in both directions (CEL's commutative error handling): `false && x`
and `x && false` are `false`, `true || x` and `x || true` are `true` even if `x` is an error. A
condition is a rule error only if the error decides the result.

`has()` also works on `location` (`has(location.key_path)`) and on map attributes
(`has(permissions.contents)`).

CEL keywords cannot be used as identifiers. Of the built-in attributes this affects only
`kube_service_account.namespace` (`namespace` is a reserved word): write `attrs.namespace`, e.g.
`has(attrs.namespace) && attrs.namespace == "kube-system"`. Placeholders (`{namespace}`) are not
affected.

## Operators and functions

lootr allows CEL operators and the standard functions below; anything else is a load-time error
(``unknown function `x` ``).

| kind | allowed |
|---|---|
| operators | `!`, `-`, `&&`, `\|\|`, `? :`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `+`, `-`, `*`, `/`, `%`, `in`, `[ ]` (index), `.` (field) |
| macros | `has(x.f)`, `list.all(x, p)`, `list.exists(x, p)`, `list.exists_one(x, p)`, `list.filter(x, p)`, `list.map(x, e)` (on maps they iterate the keys) |
| global functions | `size`, `matches`, `string`, `int`, `uint`, `double`, `bytes`, `bool`, `type`, `dyn` |
| member functions | `.size()`, `.contains()`, `.startsWith()`, `.endsWith()`, `.matches()`, `.hasValue()`, `.value()`, `.orValue()` |
| literals | `true`, `false`, `null`, ints (`42`, `0x2A`), uints (`42u`), doubles (`1.5`), strings (`"x"`, `'x'`, `r"raw"`, `'''multi'''`), bytes (`b"x"`), lists `[...]`, maps `{...}` |

Not available: string extensions such as `lowerAscii`, `split`, `replace`, `format`; `timestamp`
and `duration`; `optional.of`/`optional.none` (allowed by name but rejected as member calls).
`type()` is callable, but type names such as `int` are not known identifiers, so it is of little
use. The optional index syntax `attrs[?"x"].orValue(0)` parses and runs, but string keys
(`attrs["x"]`, `attrs[?"x"]`) are **not** checked against the schema; prefer `attrs.x`.

`size()` of a string counts Unicode code points; `in` tests list membership or map keys.

## Regular expressions

`s.matches(re)` and `matches(s, re)` use the Rust `regex` crate (RE2-like syntax, linear time, no
backreferences or lookaround):

- the match is **unanchored** (a search): `name.matches("TOKEN")` is true for `GH_TOKEN_OLD`; use
  `^...$` for whole-string matches;
- inline flags work: `(?i)` case-insensitive, `(?x)` verbose;
- the pattern is compiled at evaluation time: an invalid regex is **not** a load-time error but a
  rule error (`Error executing function 'matches': ... not a valid regex`) on the first fact of
  the rule's type. Check regexes in a test environment.

In TOML, put `when` in single quotes (`'...'`, literal string) so backslashes reach CEL unchanged,
or in `'''...'''` for multi-line conditions. Inside CEL, `"\\d"` or a raw string `r"\d"` gives
the regex `\d`.

## Comparisons and type caveats

- `==` and `!=` between values of different types are `false` / `true`, not errors (CEL spec),
  except numbers: `int`, `uint` and `double` compare by value (`bits == 2048.0` is true). So a
  wrong literal type fails silently: `bits == "2048"` and `encrypted == "false"` are always
  false. Check the attribute kind in `lootr types`.
- Ordering (`<`, `<=`, `>`, `>=`) across different types is an error: `bits < "3072"` is a rule
  error (`found no matching overload for '_<_' applied to '(int, string)'`). Numbers of
  different kinds order fine; strings order lexicographically.
- `x in list` with elements of another type is false.
- Integer overflow, division or modulo by zero and an out-of-range list index are rule errors.
- A condition that returns something other than a bool (`when = "bits"`) passes the load-time
  check but is a rule error: `condition returned Int instead of a bool`.

## Load-time checks

When the config is loaded (every scan, `types`, `explain`, `policy check`), every enabled rule's
`when` is compiled and its abstract syntax tree is walked:

- every free identifier must be an attribute of the rule's type (including file attributes where
  the type has them) or one of `type`, `source`, `location`, `attrs`;
- every `attrs.<x>` field must name an attribute of the type;
- comprehension variables (`g` in `groups.exists(g, ...)`) are in scope only inside their macro;
- every function must be in the allowlist above;
- complexity limits (CEL has no loops, but nested comprehensions multiply and the parser
  recurses on nesting): at most 4096 bytes per expression, brackets and chains of unary
  operators nested at most 32 deep, an AST at most 64 levels deep, comprehension macros (`all`,
  `exists`, `exists_one`, `map`, `filter`) nested at most 2 deep (`a.all(x, b.exists(y, ...))`
  is fine, a third level is not; chaining `a.map(...).all(...)` does not nest), list and map
  literals with at most 256 elements. Fact lists are bounded by the types (a few hundred items),
  so one condition costs at most about 256² steps per fact. Violations are errors
  (`expression too complex: ...`).

The check does not know attribute kinds (`bits == "x"` passes), does not check string keys
(`attrs["x"]`, `location["x"]`), regexes or the result type. Disabled rules are not checked.

Error messages (one per problem, all reported together, exit 2; syntax errors are followed by
the expression with a caret under the error position):

```text
error: rules.toml: rule `bad-attr`: unknown attribute `bitz` for type `ssh_private_key` (known: format, encrypted, cipher, kdf, kdf_rounds, key_type, bits, mode, world_readable, group_readable, owner_is_self, age_days, size, in_git_repo, gitignored)
error: rules.toml: rule `bad-has`: unknown attribute `lifetime` for type `jwt` (known: alg, issuer, ...)
error: rules.toml: rule `bad-env-file-attr`: unknown attribute `world_readable` for type `env_var` (known: name, length, entropy, classified_as)
error: rules.toml: rule `bad-scope`: unknown attribute `g` for type `process` (known: uid, is_root, groups, in_container)
error: rules.toml: rule `bad-func`: unknown function `lowerAscii`
error: rules.toml: rule `bad-syntax`: invalid CEL expression: ERROR: <input>:1:9: Syntax error: mismatched input '<EOF>' expecting {...}
error: rules.toml: rule `bad-ns`: invalid CEL expression: ERROR: <input>:1:25: reserved identifier: namespace
error: invalid config (7 problems); nothing was done
```

The first comes from `when = 'bitz < 2048'`, `bad-scope` from
`groups.exists(g, g == "docker") && g == "x"`, `bad-ns` from a bare `namespace`.

## Runtime errors

An evaluation error never counts as "no finding". It becomes a **rule error**:

- printed on stderr: ``rule `x` failed on <type> at <location>: <message>``;
- listed in the report (`rule_errors` in JSON, notifications in SARIF, a section in Markdown;
  see [report-schema.md](report-schema.md));
- the run exits with **2**, whatever `--fail-on` says and whether or not there are findings.

Typical messages:

| condition | message |
|---|---|
| `lifetime_hours > 24` on a JWT without `exp`/`iat` | `Undeclared reference to 'lifetime_hours'` |
| `permissions["contents"] == "write"` on an empty map | `No such key: contents` |
| `bits < "3072"` | `found no matching overload for '_<_' applied to '(int, string)'` |
| `name.matches("(")` | `Error executing function 'matches': '(' not a valid regex ...` |
| `bits` | `condition returned Int instead of a bool` |

Messages contain only names and values from facts and the config, never secret material.
Runtime errors appear only on real facts of the rule's type; `policy check` cannot find them.

## Validating rules

```sh
lootr policy check rules.toml               # default + rules.toml: load-time checks, no scan
lootr --no-default policy check rules.toml  # only your file (it must define what it uses)
lootr --config rules.toml explain my-rule   # the rule after all layers, with its attributes
lootr types                                 # every type and attribute (--json for tools)
lootr --emit-facts                          # a scan: real facts to try conditions on
```

`lootr policy check` reads only the given config files (no environment, no home directory) and
exits 0 if every layer is valid, 2 otherwise. Run it in the CI of a policy repository. Every
example rule below was checked this way (`lootr policy check` with the built-in default plus a
file holding all examples: exit 0).

## Examples

One or more realistic rules per built-in type. Rule ids are examples; attribute names are those
of `lootr types`.

### Generic entries

`env_var` (every environment variable; no file attributes):

```toml
[[rule]]
id = "example-env-deploy-token"
type = "env_var"
when = 'name.matches("^(CI|DEPLOY)_.*TOKEN$") && length > 20 && size(classified_as) == 0'
severity = "low"
message = "${name} looks like a deploy token ({length} bytes, {entropy} bits)"

[[rule]]
id = "example-env-classified"
type = "env_var"
when = '"github_token" in classified_as && !name.startsWith("GITHUB_")'
severity = "medium"
message = "${name} holds a GitHub token under an unexpected name"
```

`dotenv_entry` (each `KEY=value` of a `.env` file; file attributes always present):

```toml
[[rule]]
id = "example-dotenv-token-readable"
type = "dotenv_entry"
when = 'size(classified_as) > 0 && (world_readable || group_readable)'
severity = "high"
message = "{name} in {path} ({classified_as}) is readable by others (mode {mode})"
```

`config_entry` (each value from the `ini`, `json`, `yaml`, `toml` extractors):

```toml
[[rule]]
id = "example-config-entry-registry-token"
type = "config_entry"
when = '''
  has(location.key_path) && location.key_path.startsWith("registries.")
  && entropy >= 100 && !gitignored
'''
severity = "medium"
message = "{name} in {path} looks like a registry token ({entropy} bits)"
```

### Document types

`ssh_private_key`:

```toml
[[rule]]
id = "example-ssh-rsa-below-4096"
type = "ssh_private_key"
when = 'key_type == "rsa" && has(attrs.bits) && bits < 4096'
severity = "low"
message = "{path}: RSA key with {bits} bits"

[[rule]]
id = "example-ssh-few-kdf-rounds"
type = "ssh_private_key"
when = 'encrypted && kdf == "bcrypt" && has(attrs.kdf_rounds) && kdf_rounds < 16'
severity = "low"
message = "{path}: passphrase protected with only {kdf_rounds} bcrypt rounds"
remediation = "ssh-keygen -p -a 64 -f {path}"

[[rule]]
id = "example-ssh-old-key"
type = "ssh_private_key"
when = 'age_days > 730 && location.path.contains("/.ssh/")'
severity = "info"
message = "{path} was last changed {age_days} days ago"
```

`pem`:

```toml
[[rule]]
id = "example-pem-old-unencrypted-key"
type = "pem"
when = 'kind == "private_key" && !encrypted && age_days > 365'
severity = "medium"
message = "{path}: unencrypted private key ({key_type}, {private_keys} keys) older than a year"
```

`aws_credentials`:

```toml
[[rule]]
id = "example-aws-static-keys-without-sso"
type = "aws_credentials"
when = 'long_lived_keys > 0 && sso_profiles == 0'
severity = "medium"
message = "{path}: {long_lived_keys} profile(s) with long-lived keys ({profiles}), none uses SSO"

[[rule]]
id = "example-aws-credential-process"
type = "aws_credentials"
when = 'credential_process > 0'
severity = "info"
message = "{path}: {credential_process} profile(s) run an external credential_process"
```

`gcp_credentials`:

```toml
[[rule]]
id = "example-gcp-prod-service-account"
type = "gcp_credentials"
when = 'kind == "service_account" && has(attrs.project) && project.startsWith("prod-")'
severity = "critical"
message = "Key of service account {account} for production project {project} in {path}"
```

`azure_profile`:

```toml
[[rule]]
id = "example-azure-stale-token-cache"
type = "azure_profile"
when = 'kind == "msal_token_cache" && refresh_tokens > 0 && age_days > 30'
severity = "low"
message = "{path} holds {refresh_tokens} refresh token(s) and was not used for {age_days} days"
```

`kubeconfig`:

```toml
[[rule]]
id = "example-kubeconfig-prod-static-token"
type = "kubeconfig"
when = '''
  has(attrs.current_context) && current_context.contains("prod")
  && (static_tokens > 0 || basic_auth > 0)
'''
severity = "high"
message = "{path}: current context {current_context} uses static credentials"

[[rule]]
id = "example-kubeconfig-exec-plugins"
type = "kubeconfig"
when = 'exec_commands.exists(c, !(c in ["aws", "gke-gcloud-auth-plugin", "kubelogin"]))'
severity = "low"
message = "{path} runs exec plugins outside the allowlist ({exec_commands})"
```

`docker_config`:

```toml
[[rule]]
id = "example-docker-no-helper"
type = "docker_config"
when = 'inline_auths > 0 && !has(attrs.creds_store) && cred_helpers == 0'
severity = "medium"
message = "{path} stores credentials for {hosts} and configures no credential helper"

[[rule]]
id = "example-docker-ghcr-inline"
type = "docker_config"
when = 'hosts.exists(h, h == "ghcr.io")'
severity = "medium"
message = "{path} stores a ghcr.io login (a GitHub token)"
```

`npmrc`, `pypirc`, `netrc`, `git_credentials`, `gh_hosts`:

```toml
[[rule]]
id = "example-npmrc-no-env-refs"
type = "npmrc"
when = 'inline_tokens > 0 && env_refs == 0 && location.path.endsWith("/.npmrc")'
severity = "low"
message = "{path} stores {inline_tokens} token(s) for {hosts} instead of ${{NPM_TOKEN}}"

[[rule]]
id = "example-pypirc-pypi-upload"
type = "pypirc"
when = 'inline_tokens > 0 && hosts.exists(h, h.endsWith("pypi.org"))'
severity = "medium"
message = "{path} stores a PyPI upload credential ({hosts})"

[[rule]]
id = "example-netrc-default-with-password"
type = "netrc"
when = 'default_entry && inline_tokens > 0'
severity = "high"
message = "{path}: the default entry sends a password to every host"

[[rule]]
id = "example-git-credentials-github"
type = "git_credentials"
when = '"github.com" in hosts'
severity = "medium"
message = "{path} stores a github.com password or token in plain text"

[[rule]]
id = "example-gh-hosts-enterprise"
type = "gh_hosts"
when = 'inline_tokens > 0 && hosts.exists(h, h != "github.com")'
severity = "medium"
message = "{path} stores tokens for GitHub Enterprise hosts ({hosts})"
```

`github_workflow` (one fact per job; `permissions` is empty when `permissions_source` is
`repository`, so guard map lookups or use `in`):

```toml
[[rule]]
id = "example-workflow-oidc-on-pr"
type = "github_workflow"
when = '"id-token" in write_scopes && "pull_request_target" in triggers'
severity = "high"
message = "Job {job} in {path} can mint OIDC tokens on pull_request_target"

[[rule]]
id = "example-workflow-actions-write"
type = "github_workflow"
when = 'permissions_source != "repository" && permissions["actions"] == "write"'
severity = "medium"
message = "Job {job} in {path} can modify workflow runs (actions: write, {permissions_source})"
```

### Value types

Value types are found in env vars, extracted entries, documents, file contents and foreign
process environments; use `location.kind` to tell them apart and `has()` for file attributes.

`github_token`:

```toml
[[rule]]
id = "example-github-token-in-file"
type = "github_token"
when = 'location.kind == "file" && kind in ["fine_grained", "oauth"]'
severity = "medium"
message = "GitHub {kind} token stored in {location}"

[[rule]]
id = "example-github-app-token-in-env"
type = "github_token"
when = 'prefix == "ghs_" && location.kind == "env" && !location.name.startsWith("GITHUB_")'
severity = "low"
message = "GitHub App installation token in ${name}"
```

`gitlab_token`:

```toml
[[rule]]
id = "example-gitlab-runner-token"
type = "gitlab_token"
when = 'kind in ["runner", "runner_registration"]'
severity = "high"
message = "GitLab runner token ({prefix}) visible in {location}"
```

`aws_access_key_id`:

```toml
[[rule]]
id = "example-aws-key-in-readable-file"
type = "aws_access_key_id"
when = '''
  kind == "long_lived" && location.kind == "file"
  && has(attrs.world_readable) && world_readable
'''
severity = "critical"
message = "Long-lived AWS key in {path}, readable by every user (mode {mode})"
```

`api_key`:

```toml
[[rule]]
id = "example-stripe-live-key"
type = "api_key"
when = 'service == "stripe" && has(attrs.live) && live && kind == "secret"'
severity = "critical"
message = "Stripe live secret key in {location}"

[[rule]]
id = "example-llm-admin-key"
type = "api_key"
when = '(service == "openai" && kind == "admin") || (service == "anthropic" && kind == "admin_key")'
severity = "critical"
message = "{service} admin key in {location}"
```

`jwt`:

```toml
[[rule]]
id = "example-jwt-alg-none"
type = "jwt"
when = 'alg == "none"'
severity = "high"
message = "Unsigned JWT (alg none) in {location}"

[[rule]]
id = "example-jwt-github-oidc-long"
type = "jwt"
when = '''
  has(attrs.issuer) && issuer == "https://token.actions.githubusercontent.com"
  && has(attrs.expires_in_hours) && expires_in_hours > 1
'''
severity = "low"
message = "GitHub OIDC token in {location} is valid for {expires_in_hours} more hours"

[[rule]]
id = "example-jwt-admin-scope"
type = "jwt"
when = '!expired && has(attrs.scopes) && scopes.exists(s, s.matches("(?i)admin"))'
severity = "high"
message = "JWT in {location} carries admin scopes ({scopes}), audience {audience}"
```

### Custom type

A `[[type]]` from the config gets `length`, `entropy`, `charset` (and file attributes when found
in a file):

```toml
[[type]]
name = "acme_api_key"
pattern = '^acme_(live|test)_[A-Za-z0-9]{24}$'

[[rule]]
id = "example-acme-key-in-env"
type = "acme_api_key"
when = 'location.kind == "env" || (has(attrs.in_git_repo) && in_git_repo)'
severity = "high"
message = "ACME key ({length} bytes, {charset}) in {location}"
```

### Probe fact types

`process`:

```toml
[[rule]]
id = "example-root-in-container"
type = "process"
when = 'is_root && in_container'
severity = "medium"
message = "lootr runs as root (uid {uid}) inside a container"
```

`unix_socket`:

```toml
[[rule]]
id = "example-unix-socket-rootless"
type = "unix_socket"
when = 'accessible && owner_is_self && kind in ["docker", "podman"]'
severity = "info"
message = "Rootless {kind} socket {path} (mode {mode}, group {group})"
```

`proc_environ` (the values found in the environments are separate facts of their value types,
at `probe:proc_environ:<process name>`):

```toml
[[rule]]
id = "example-proc-environ-runner"
type = "proc_environ"
when = 'readable_environ > 0 && names.exists(n, n.startsWith("Runner"))'
severity = "high"
message = "A CI runner's environment is readable ({names}; {foreign_processes} foreign processes)"
```

`writable_path_dir` and `writable_file` (both from the `writable` probe):

```toml
[[rule]]
id = "example-path-dir-foreign-writable"
type = "writable_path_dir"
when = 'writable && !owner_is_self && dir.startsWith("/usr/")'
severity = "high"
message = "{dir} belongs to another user but this user can write in it (mode {mode})"

[[rule]]
id = "example-hook-parent-writable"
type = "writable_file"
when = 'parent_writable && !owner_is_self'
severity = "medium"
message = "{path} belongs to another user, but its directory is writable by this user"
```

`suid_binary` (from the `suid` probe):

```toml
[[rule]]
id = "example-dangerous-capabilities"
type = "suid_binary"
when = 'capabilities.exists(c, c in ["cap_setuid", "cap_sys_admin", "cap_dac_override"])'
severity = "critical"
message = "{path} carries root-equivalent capabilities ({capabilities})"
```

`kube_service_account` (`namespace` is a CEL keyword: use `attrs.namespace`; the token itself is
a `jwt` fact at the same path):

```toml
[[rule]]
id = "example-kube-system-token"
type = "kube_service_account"
when = 'has(attrs.namespace) && attrs.namespace in ["kube-system", "default"]'
severity = "high"
message = "Service account token of namespace {namespace} mounted at {path} (CA present: {has_ca})"
```

### `waiver`

Every configured waiver is a `waiver` fact, evaluated after all other facts (so `matched` is
known), located at `<config file>#[[waiver]] #<n>` with `source == "config"`:

```toml
[[rule]]
id = "example-waiver-too-long"
type = "waiver"
when = 'has(attrs.expires_in_days) && expires_in_days > 365'
severity = "medium"
message = "Waiver for {waived_rule} ({location}) runs for {expires_in_days} more days"

[[rule]]
id = "example-waiver-everywhere"
type = "waiver"
when = '!has(attrs.waived_path) && !has(attrs.waived_name)'
severity = "low"
message = "Waiver for {waived_rule} ({location}) is not narrowed by path or name: {reason}"
```

The default layer has `waiver-expired` (`when = "expired"`); the
[company example](../examples/company/baseline.toml) adds `waiver-without-expiry`
(`!has(attrs.expires)`) and `waiver-unused` (`!expired && matched == 0`).
