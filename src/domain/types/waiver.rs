//! `waiver`: one fact per configured waiver, made by the evaluate step after
//! the other rules ran (not by a source). Rules over it keep waivers honest:
//! the default policy reports expired waivers (`waiver-expired`); a company
//! baseline can require an expiry date or flag waivers that match nothing.
//!
//! The location is the config file that defines the waiver, with the key
//! path `[[waiver]] #<n>` (n-th waiver of that file). Everything here comes
//! from the config, never from scanned data.

use crate::domain::config::Waiver;
use crate::domain::model::{AttrValue, Attrs, DisplayPath, Fact, Ident, Location, PublicText};
use crate::domain::time::Date;
use crate::domain::types::{AttrKind, AttrSpec, FactType};

pub const NAME: &str = "waiver";

/// Source id of waiver facts.
pub const SOURCE: &str = "config";

pub const ATTRS: &[AttrSpec] = &[
    AttrSpec::new("waived_rule", AttrKind::Name, "id of the waived rule"),
    AttrSpec::new("reason", AttrKind::Text, "the waiver's reason"),
    AttrSpec::optional("expires", AttrKind::Text, "expiry date (YYYY-MM-DD)"),
    AttrSpec::new(
        "expired",
        AttrKind::Bool,
        "the expiry date has passed: the waiver is ignored",
    ),
    AttrSpec::optional(
        "expires_in_days",
        AttrKind::Int,
        "days from the scan date to the expiry date (negative once expired)",
    ),
    AttrSpec::new(
        "matched",
        AttrKind::Int,
        "findings this waiver waived in this run (0 for expired waivers)",
    ),
    AttrSpec::optional(
        "waived_path",
        AttrKind::Text,
        "the waiver's path glob as written",
    ),
    AttrSpec::optional(
        "waived_name",
        AttrKind::Text,
        "the waiver's env var name or key path",
    ),
];

pub const FACT_TYPE: FactType = FactType {
    name: NAME,
    doc: "a waiver from the config (one fact per waiver, made after the other rules ran)",
    schema: ATTRS,
};

/// The facts of `waivers`; `matched[i]` is the number of findings waiver `i`
/// waived.
pub fn facts(waivers: &[Waiver], matched: &[usize], today: Date) -> Vec<Fact> {
    let (Ok(type_), Ok(source)) = (Ident::from_non_secret(NAME), Ident::from_non_secret(SOURCE))
    else {
        return Vec::new();
    };
    waivers
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let mut attrs = Attrs::new();
            attrs.insert("waived_rule", AttrValue::Name(w.rule.clone()));
            attrs.insert(
                "reason",
                AttrValue::Text(PublicText::from_non_secret(&w.reason)),
            );
            if let Some(expires) = w.expires {
                attrs.insert(
                    "expires",
                    AttrValue::Text(PublicText::from_non_secret(&expires.to_string())),
                );
                attrs.insert("expires_in_days", AttrValue::Int(today.days_until(expires)));
            }
            attrs.insert(
                "expired",
                AttrValue::Bool(w.expires.is_some_and(|e| e < today)),
            );
            let n = matched.get(i).copied().unwrap_or(0);
            attrs.insert(
                "matched",
                AttrValue::Int(i64::try_from(n).unwrap_or(i64::MAX)),
            );
            if let Some(p) = &w.path_pattern {
                attrs.insert(
                    "waived_path",
                    AttrValue::Text(PublicText::from_non_secret(p)),
                );
            }
            if let Some(n) = &w.name {
                attrs.insert(
                    "waived_name",
                    AttrValue::Text(PublicText::from_non_secret(n)),
                );
            }
            Fact {
                type_: type_.clone(),
                location: Location::File {
                    path: DisplayPath::new(std::path::Path::new(&w.layer)),
                    key_path: Some(PublicText::from_non_secret(&format!(
                        "[[waiver]] #{}",
                        w.position
                    ))),
                },
                source: source.clone(),
                attrs,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_fact_per_waiver() {
        let w = |expires: Option<&str>, position| Waiver {
            rule: Ident::from_non_secret("ssh-key-unencrypted").unwrap(),
            path: Some("/home/u/.ssh/ci".into()),
            path_pattern: Some("~/.ssh/ci".into()),
            name: None,
            reason: "deploy key".into(),
            expires: expires.map(|d| d.parse().unwrap()),
            layer: "/etc/lootr/project.toml".into(),
            position,
        };
        let today: Date = "2026-10-08".parse().unwrap();
        let facts = facts(
            &[
                w(Some("2026-10-01"), 1),
                w(None, 2),
                w(Some("2026-10-18"), 3),
            ],
            &[0, 4, 1],
            today,
        );
        let json = serde_json::to_value(&facts).unwrap();
        assert_eq!(json[0]["attrs"]["expired"], true);
        assert_eq!(json[0]["attrs"]["expires_in_days"], -7);
        assert_eq!(json[0]["attrs"]["waived_path"], "~/.ssh/ci");
        assert_eq!(json[1]["attrs"]["matched"], 4);
        assert!(json[1]["attrs"].get("expires").is_none());
        assert_eq!(json[1]["attrs"]["expired"], false);
        assert_eq!(json[2]["attrs"]["expires_in_days"], 10);
        assert_eq!(
            json[2]["location"],
            serde_json::json!({"kind": "file", "path": "/etc/lootr/project.toml", "key_path": "[[waiver]] #3"})
        );
        assert_eq!(json[2]["source"], "config");
    }
}
