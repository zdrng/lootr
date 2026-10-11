//! `.gitignore` patterns, compiled to [`Glob`]s (linear time). Pure: the
//! service layer finds the repository and reads the files (`service::git`).
//!
//! Supported (gitignore(5)): comments, `!` negation, `\#` / `\!` escapes,
//! trailing-space trimming, a trailing `/` for directories only, patterns
//! with a `/` anchored to the file's directory, patterns without one
//! matching at any depth, `*`, `?`, `[...]` (also `[^...]`) and `**`. The
//! last matching pattern wins; files below an ignored directory are ignored.

use crate::domain::glob::{Glob, escape};

/// One pattern line of an ignore file.
#[derive(Clone, Debug)]
pub struct IgnoreRule {
    glob: Glob,
    negated: bool,
    dir_only: bool,
}

impl IgnoreRule {
    /// Whether this rule matches `path` (absolute, `/`-separated).
    pub fn matches(&self, path: &str, is_dir: bool) -> bool {
        (is_dir || !self.dir_only) && self.glob.matches(path)
    }
}

/// Parses the ignore file of directory `dir` (absolute). Lines that do not
/// compile are skipped.
pub fn parse(dir: &str, text: &str) -> Vec<IgnoreRule> {
    let base = escape(dir.trim_end_matches('/'));
    text.lines().filter_map(|line| rule(&base, line)).collect()
}

fn rule(base: &str, line: &str) -> Option<IgnoreRule> {
    let mut line = line.strip_suffix('\r').unwrap_or(line).to_string();
    if line.starts_with('#') {
        return None;
    }
    // Trailing spaces are dropped unless escaped.
    while line.ends_with(' ') && !line.ends_with("\\ ") {
        line.pop();
    }
    let mut pattern = line.as_str();
    let negated = pattern.starts_with('!');
    if negated {
        pattern = &pattern[1..];
    }
    let dir_only = pattern.ends_with('/');
    let pattern = pattern.trim_end_matches('/');
    if pattern.is_empty() {
        return None;
    }
    let anchored = pattern.contains('/');
    let pattern = pattern.trim_start_matches('/').replace("[^", "[!");
    let full = if anchored {
        format!("{base}/{pattern}")
    } else {
        format!("{base}/**/{pattern}")
    };
    let glob = Glob::new(&full).ok()?;
    Some(IgnoreRule {
        glob,
        negated,
        dir_only,
    })
}

/// Applies `rules` (lowest precedence first) to `path`: `Some(true)` if the
/// last matching rule ignores it, `Some(false)` if it re-includes it, `None`
/// if no rule matches.
pub fn decide<'r>(
    rules: impl IntoIterator<Item = &'r IgnoreRule>,
    path: &str,
    is_dir: bool,
) -> Option<bool> {
    let mut result = None;
    for r in rules {
        if r.matches(path, is_dir) {
            result = Some(!r.negated);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ignored(text: &str, path: &str, is_dir: bool) -> Option<bool> {
        let rules = parse("/repo", text);
        decide(&rules, path, is_dir)
    }

    #[test]
    fn basic_patterns() {
        assert_eq!(ignored(".env", "/repo/.env", false), Some(true));
        assert_eq!(ignored(".env", "/repo/app/.env", false), Some(true));
        assert_eq!(ignored(".env", "/repo/.env.local", false), None);
        assert_eq!(ignored(".env*", "/repo/a/.env.local", false), Some(true));
        assert_eq!(ignored("*.secret", "/repo/x/y.secret", false), Some(true));
        assert_eq!(ignored("# .env\n", "/repo/.env", false), None);
        assert_eq!(ignored("\\#x", "/repo/#x", false), Some(true));
        assert_eq!(ignored("\n\n", "/repo/.env", false), None);
    }

    #[test]
    fn anchoring_and_directories() {
        assert_eq!(ignored("/.env", "/repo/.env", false), Some(true));
        assert_eq!(ignored("/.env", "/repo/app/.env", false), None);
        assert_eq!(ignored("app/.env", "/repo/app/.env", false), Some(true));
        assert_eq!(ignored("app/.env", "/repo/x/app/.env", false), None);
        assert_eq!(ignored("build/", "/repo/build", true), Some(true));
        assert_eq!(ignored("build/", "/repo/build", false), None);
        assert_eq!(
            ignored("**/conf/.env", "/repo/a/b/conf/.env", false),
            Some(true)
        );
        assert_eq!(ignored("conf/**", "/repo/conf/x/.env", false), Some(true));
        assert_eq!(ignored("conf/**", "/repo/conf", true), None);
    }

    #[test]
    fn negation_last_match_wins() {
        let text = ".env*\n!.env.example\n";
        assert_eq!(ignored(text, "/repo/.env.local", false), Some(true));
        assert_eq!(ignored(text, "/repo/.env.example", false), Some(false));
        assert_eq!(ignored("!.env\n.env", "/repo/.env", false), Some(true));
        assert_eq!(ignored("\\!x", "/repo/!x", false), Some(true));
    }

    #[test]
    fn whitespace_and_brackets() {
        assert_eq!(ignored(".env   \r", "/repo/.env", false), Some(true));
        assert_eq!(ignored("[^a]x", "/repo/bx", false), Some(true));
        assert_eq!(ignored("[^a]x", "/repo/ax", false), None);
        assert_eq!(ignored("[", "/repo/[", false), None);
    }

    #[test]
    fn metacharacters_in_the_directory_are_literal() {
        let rules = parse("/re[po]", ".env");
        assert_eq!(decide(&rules, "/re[po]/.env", false), Some(true));
        assert_eq!(decide(&rules, "/rep/.env", false), None);
        let rules = parse("/", ".env");
        assert_eq!(decide(&rules, "/x/.env", false), Some(true));
    }
}
