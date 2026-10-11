//! `kubeconfig`: Kubernetes client configuration (YAML, also JSON).
//!
//! One fact per file: contexts, clusters and users with their kinds of
//! authentication. Credentials are emitted as nested values at
//! `users.<name>.<field>`, so a bearer token that is a JWT (service account
//! tokens) becomes a `jwt` fact with issuer and expiry:
//!
//! - `token`, `password`;
//! - legacy `auth-provider.config` tokens (`id-token`, `refresh-token`,
//!   `access-token`, `client-secret`);
//! - `exec.env` values (exec plugins often get credentials through their
//!   environment).
//!
//! Embedded client keys (`client-key-data`) are only counted: they are
//! base64 PEM, no value type would recognize them, and decoding them is
//! not needed. Exec plugins are reported by command name (basename), never
//! run. Parsed with the bounded loader in [`crate::domain::format::yaml`].

use std::collections::BTreeSet;

use crate::domain::format::yaml::{Value, Yaml};
use crate::domain::model::{AttrValue, Attrs, PublicText};
use crate::domain::secret::SecretSlice;
use crate::domain::types::creds::{key_path, texts};
use crate::domain::types::{AttrKind, AttrSpec, DocumentType, Emitter, ParseError};

pub const NAME: &str = "kubeconfig";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new("contexts", AttrKind::List, "context names (text)"),
    AttrSpec::optional(
        "current_context",
        AttrKind::Text,
        "the current-context, if set",
    ),
    AttrSpec::new("clusters", AttrKind::List, "cluster names (text)"),
    AttrSpec::new("users", AttrKind::Int, "user entries"),
    AttrSpec::new(
        "static_tokens",
        AttrKind::Int,
        "users with a bearer token in the file",
    ),
    AttrSpec::new(
        "token_files",
        AttrKind::Int,
        "users that read a token from a file (tokenFile)",
    ),
    AttrSpec::new(
        "basic_auth",
        AttrKind::Int,
        "users with a password in the file",
    ),
    AttrSpec::new(
        "client_certs",
        AttrKind::Int,
        "users with a client certificate",
    ),
    AttrSpec::new(
        "embedded_client_keys",
        AttrKind::Int,
        "users with a client private key in the file (client-key-data)",
    ),
    AttrSpec::new(
        "exec_auth",
        AttrKind::Int,
        "users authenticated by an exec plugin",
    ),
    AttrSpec::new(
        "exec_commands",
        AttrKind::List,
        "exec plugin commands (basename, text)",
    ),
    AttrSpec::new(
        "auth_providers",
        AttrKind::Int,
        "users with a legacy auth-provider (tokens stored in the file)",
    ),
    AttrSpec::new(
        "insecure_skip_tls",
        AttrKind::Bool,
        "a cluster disables TLS verification (insecure-skip-tls-verify)",
    ),
];

const PROVIDER_SECRETS: &[&str] = &["id-token", "refresh-token", "access-token", "client-secret"];

/// Most names listed per attribute.
const MAX_NAMES: usize = 64;

pub struct Kubeconfig;

impl DocumentType for Kubeconfig {
    fn name(&self) -> &'static str {
        NAME
    }

    fn doc(&self) -> &'static str {
        "a Kubernetes client configuration (kubeconfig): contexts, clusters, kinds of user credentials"
    }

    fn schema(&self) -> &'static [AttrSpec] {
        ATTRS
    }

    fn sniff(&self, head: &[u8]) -> bool {
        [
            &b"apiVersion"[..],
            b"clusters",
            b"contexts",
            b"users",
            b"current-context",
        ]
        .iter()
        .any(|k| head.windows(k.len()).any(|w| w == *k))
    }

    fn parse<'a>(&self, doc: SecretSlice<'a>, out: &mut Emitter<'a>) -> Result<(), ParseError> {
        let yaml = Yaml::parse(doc)?;
        let Some(root) = yaml.root().filter(|r| r.is_map()) else {
            return Ok(());
        };
        if ["clusters", "contexts", "users"]
            .iter()
            .all(|k| root.get(k).is_none())
        {
            return Ok(());
        }
        let names = |list: &str| -> BTreeSet<String> {
            root.get(list)
                .into_iter()
                .flat_map(|l| l.items())
                .filter_map(|item| item.get("name")?.text())
                .take(MAX_NAMES)
                .map(str::to_string)
                .collect()
        };
        let mut a = Attrs::new();
        a.insert("contexts", texts(names("contexts").iter()));
        if let Some(c) = root.get("current-context").and_then(|c| c.text())
            && !c.is_empty()
        {
            a.insert(
                "current_context",
                AttrValue::Text(PublicText::from_non_secret(c)),
            );
        }
        a.insert("clusters", texts(names("clusters").iter()));
        let insecure = root
            .get("clusters")
            .into_iter()
            .flat_map(|l| l.items())
            .any(|c| {
                c.get("cluster")
                    .and_then(|c| c.get("insecure-skip-tls-verify"))
                    .is_some_and(|v| v.is_true())
            });

        let mut users = 0;
        let mut c = UserCounts::default();
        let mut commands = BTreeSet::new();
        for (i, entry) in root
            .get("users")
            .into_iter()
            .flat_map(|l| l.items())
            .enumerate()
        {
            users += 1;
            let index = i.to_string();
            let name = entry
                .get("name")
                .and_then(|n| n.text())
                .filter(|n| !n.is_empty())
                .unwrap_or(&index);
            let Some(user) = entry.get("user").filter(|u| u.is_map()) else {
                continue;
            };
            user_facts(user, name, &mut c, &mut commands, out);
        }
        a.insert("users", AttrValue::Int(users));
        a.insert("static_tokens", AttrValue::Int(c.tokens));
        a.insert("token_files", AttrValue::Int(c.token_files));
        a.insert("basic_auth", AttrValue::Int(c.basic));
        a.insert("client_certs", AttrValue::Int(c.certs));
        a.insert("embedded_client_keys", AttrValue::Int(c.embedded_keys));
        a.insert("exec_auth", AttrValue::Int(c.exec));
        a.insert("exec_commands", texts(commands.iter()));
        a.insert("auth_providers", AttrValue::Int(c.providers));
        a.insert("insecure_skip_tls", AttrValue::Bool(insecure));
        out.fact(a);
        Ok(())
    }
}

#[derive(Default)]
struct UserCounts {
    tokens: i64,
    token_files: i64,
    basic: i64,
    certs: i64,
    embedded_keys: i64,
    exec: i64,
    providers: i64,
}

fn user_facts<'a>(
    user: Value<'_, 'a>,
    name: &str,
    c: &mut UserCounts,
    commands: &mut BTreeSet<String>,
    out: &mut Emitter<'a>,
) {
    let has = |k: &str| user.get(k).is_some_and(|v| v.has_value());
    let mut emit = |field: &[&str], v: Option<Value<'_, 'a>>| {
        if let Some(secret) = v.and_then(|v| v.secret()) {
            let mut parts = vec!["users", name];
            parts.extend_from_slice(field);
            out.nested(key_path(&parts), secret);
        }
    };
    if has("token") {
        c.tokens += 1;
        emit(&["token"], user.get("token"));
    }
    if has("tokenFile") {
        c.token_files += 1;
    }
    if has("password") {
        c.basic += 1;
        emit(&["password"], user.get("password"));
    }
    if has("client-certificate-data") || has("client-certificate") {
        c.certs += 1;
    }
    if has("client-key-data") {
        c.embedded_keys += 1;
    }
    if let Some(exec) = user.get("exec").filter(|e| e.is_map()) {
        c.exec += 1;
        if let Some(cmd) = exec.get("command").and_then(|c| c.text()) {
            let base = cmd.rsplit('/').next().unwrap_or(cmd);
            if !base.is_empty() && commands.len() < MAX_NAMES {
                commands.insert(base.to_string());
            }
        }
        for env in exec.get("env").into_iter().flat_map(|e| e.items()) {
            if let Some(var) = env.get("name").and_then(|n| n.text()) {
                emit(&["exec", "env", var], env.get("value"));
            }
        }
    }
    if let Some(provider) = user.get("auth-provider").filter(|p| p.is_map()) {
        c.providers += 1;
        if let Some(config) = provider.get("config") {
            for key in PROVIDER_SECRETS {
                emit(&["auth-provider", key], config.get(key));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::CANARY;

    fn parse(text: &str) -> Result<(Attrs, Vec<String>), ParseError> {
        let mut out = Emitter::default();
        Kubeconfig.parse(SecretSlice::new(text.as_bytes()), &mut out)?;
        let attrs = out.facts.pop().map(|f| f.1).unwrap_or_default();
        assert!(!format!("{attrs:?}").contains(CANARY));
        Ok((
            attrs,
            out.values.iter().map(|(k, _)| k.to_string()).collect(),
        ))
    }

    #[test]
    fn users_clusters_contexts() {
        let text = format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: prod\nclusters:\n\
             - name: prod\n  cluster:\n    server: https://k8s.example:6443\n    certificate-authority-data: {CANARY}\n\
             - name: lab\n  cluster:\n    server: https://lab.example\n    insecure-skip-tls-verify: true\n\
             contexts:\n- name: prod\n  context: {{cluster: prod, user: sa}}\n- name: lab\n  context: {{cluster: lab, user: admin}}\n\
             users:\n- name: sa\n  user:\n    token: {CANARY}-token\n\
             - name: admin\n  user:\n    client-certificate-data: {CANARY}\n    client-key-data: {CANARY}\n\
             - name: basic\n  user: {{username: u, password: \"{CANARY}pw\"}}\n\
             - name: eks\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: /usr/local/bin/aws\n      args: [eks, get-token]\n      env:\n      - name: AWS_SECRET_ACCESS_KEY\n        value: {CANARY}env\n\
             - name: oidc\n  user:\n    auth-provider:\n      name: oidc\n      config:\n        id-token: {CANARY}id\n        refresh-token: {CANARY}r\n\
             - name: file\n  user: {{tokenFile: /var/run/secrets/token}}\n"
        );
        let (a, v) = parse(&text).unwrap();
        assert_eq!(a["contexts"].to_string(), "lab, prod");
        assert_eq!(a["current_context"].to_string(), "prod");
        assert_eq!(a["clusters"].to_string(), "lab, prod");
        assert_eq!(a["users"], AttrValue::Int(6));
        assert_eq!(a["static_tokens"], AttrValue::Int(1));
        assert_eq!(a["token_files"], AttrValue::Int(1));
        assert_eq!(a["basic_auth"], AttrValue::Int(1));
        assert_eq!(a["client_certs"], AttrValue::Int(1));
        assert_eq!(a["embedded_client_keys"], AttrValue::Int(1));
        assert_eq!(a["exec_auth"], AttrValue::Int(1));
        assert_eq!(a["exec_commands"].to_string(), "aws");
        assert_eq!(a["auth_providers"], AttrValue::Int(1));
        assert_eq!(a["insecure_skip_tls"], AttrValue::Bool(true));
        assert_eq!(
            v,
            [
                "users.sa.token",
                "users.basic.password",
                "users.eks.exec.env.AWS_SECRET_ACCESS_KEY",
                "users.oidc.auth-provider.id-token",
                "users.oidc.auth-provider.refresh-token",
            ]
        );
    }

    #[test]
    fn json_kubeconfig_and_other_yaml() {
        let (a, _) = parse(
            r#"{"apiVersion":"v1","clusters":[],"users":[{"name":"x","user":{"token":"t"}}]}"#,
        )
        .unwrap();
        assert_eq!(a["static_tokens"], AttrValue::Int(1));
        assert!(!a.contains_key("current_context"));
        let (a, _) = parse("apiVersion: apps/v1\nkind: Deployment\n").unwrap();
        assert!(a.is_empty());
        let (a, _) = parse("- a\n- b\n").unwrap();
        assert!(a.is_empty());
    }

    #[test]
    fn alias_bomb_is_a_parse_error() {
        let mut text = String::from(
            "users: &a [{name: x}, {name: x}, {name: x}, {name: x}, {name: x}, {name: x}, {name: x}, {name: x}, {name: x}, {name: x}]\n",
        );
        for (n, p) in [
            ("b", "a"),
            ("c", "b"),
            ("d", "c"),
            ("e", "d"),
            ("f", "e"),
            ("g", "f"),
        ] {
            text.push_str(&format!(
                "{n}: &{n} [{}]\n",
                vec![format!("*{p}"); 10].join(", ")
            ));
        }
        assert_eq!(
            parse(&text).err(),
            Some(ParseError("YAML alias expansion too large"))
        );
    }
}
