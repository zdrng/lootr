//! Message templates: `"SSH private key {path} is not encrypted"`.
//!
//! `{name}` is replaced by a placeholder value; `{{` and `}}` are literal
//! braces. Which names exist is decided by the caller (the evaluate service
//! offers `path`, `name`, `type`, `rule`, `source`, `location` and the
//! type's attributes); names are validated when the config is loaded.

/// Placeholder names used in `template`, or an error for unbalanced braces.
pub fn placeholders(template: &str) -> Result<Vec<&str>, String> {
    let mut names = Vec::new();
    render_with(template, |name| {
        names.push(name);
        Some(String::new())
    })?;
    Ok(names)
}

/// Renders `template`; `value` returns the text for a placeholder (`None`
/// renders `-`).
pub fn render(template: &str, value: impl FnMut(&str) -> Option<String>) -> String {
    render_with(template, value).unwrap_or_else(|_| template.to_string())
}

fn render_with<'t>(
    template: &'t str,
    mut value: impl FnMut(&'t str) -> Option<String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(pos) = rest.find(['{', '}']) {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        if tail.starts_with("{{") || tail.starts_with("}}") {
            out.push_str(&tail[..1]);
            rest = &tail[2..];
        } else if tail.starts_with('}') {
            return Err(format!("unmatched `}}` in `{template}` (write `}}}}`)"));
        } else {
            let end = tail
                .find('}')
                .ok_or_else(|| format!("unclosed `{{` in `{template}` (write `{{{{`)"))?;
            let name = &tail[1..end];
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(format!("invalid placeholder `{{{name}}}` in `{template}`"));
            }
            out.push_str(&value(name).unwrap_or_else(|| "-".to_string()));
            rest = &tail[end + 1..];
        }
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_placeholders() {
        assert_eq!(
            placeholders("key {path} has {bits} bits"),
            Ok(vec!["path", "bits"])
        );
        assert_eq!(placeholders("{{literal}} {x}"), Ok(vec!["x"]));
        assert!(placeholders("{unclosed").is_err());
        assert!(placeholders("bad }").is_err());
        assert!(placeholders("{a b}").is_err());
        assert!(placeholders("{}").is_err());
    }

    #[test]
    fn renders() {
        let out = render("{path}: {bits} {{ok}} {missing}", |n| match n {
            "path" => Some("/k".into()),
            "bits" => Some("2048".into()),
            _ => None,
        });
        assert_eq!(out, "/k: 2048 {ok} -");
    }
}
