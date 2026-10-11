//! Globs for env var names, paths, excludes and waivers, compiled to a
//! linear-time `regex`.
//!
//! Syntax:
//!
//! - `*` matches any characters except `/` (including a leading `.`: lootr
//!   does not treat dotfiles specially);
//! - `?` matches one character except `/`;
//! - `**` as a whole path component matches zero or more components
//!   (`a/**/b` matches `a/b` and `a/x/y/b`; a trailing `/**` matches
//!   everything below);
//! - `[abc]`, `[a-z]`, `[!abc]` match one character from (not from) the set;
//! - `\x` matches `x` literally.
//!
//! `~` and relative paths are expanded by the service layer before compiling
//! (see [`escape`] for embedding literal paths).

use regex::Regex;

#[derive(Clone, Debug)]
pub struct Glob {
    pattern: String,
    regex: Regex,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid glob `{pattern}`: {reason}")]
pub struct GlobError {
    pub pattern: String,
    pub reason: String,
}

impl Glob {
    pub fn new(pattern: &str) -> Result<Glob, GlobError> {
        let err = |reason: &str| GlobError {
            pattern: pattern.to_string(),
            reason: reason.to_string(),
        };
        let mut re = String::from("^");
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            match c {
                '*' if chars.get(i + 1) == Some(&'*') => {
                    let at_start = i == 0 || chars[i - 1] == '/';
                    let next = chars.get(i + 2);
                    if at_start && next == Some(&'/') {
                        // `**/`: zero or more whole components.
                        re.push_str("(?:[^/]*/)*");
                        i += 3;
                    } else if at_start && next.is_none() {
                        // trailing `**`: everything below.
                        re.push_str(".*");
                        i += 2;
                    } else {
                        // `**` inside a component behaves like `*`.
                        re.push_str("[^/]*");
                        i += 2;
                    }
                }
                '*' => {
                    re.push_str("[^/]*");
                    i += 1;
                }
                '?' => {
                    re.push_str("[^/]");
                    i += 1;
                }
                '[' => {
                    let close = chars[i + 1..]
                        .iter()
                        .skip(1) // `]` right after `[` or `[!` is a literal
                        .position(|&c| c == ']')
                        .map(|p| i + 2 + p)
                        .ok_or_else(|| err("unclosed `[`"))?;
                    let mut body: &[char] = &chars[i + 1..close];
                    re.push('[');
                    if body.first() == Some(&'!') {
                        re.push('^');
                        body = &body[1..];
                        if body.is_empty() {
                            return Err(err("empty `[!]`"));
                        }
                    }
                    for &b in body {
                        match b {
                            '\\' | '[' | ']' | '^' | '&' | '~' => {
                                re.push('\\');
                                re.push(b);
                            }
                            _ => re.push(b),
                        }
                    }
                    re.push(']');
                    i = close + 1;
                }
                '\\' => {
                    let next = chars.get(i + 1).ok_or_else(|| err("trailing `\\`"))?;
                    re.push_str(&regex::escape(&next.to_string()));
                    i += 2;
                }
                _ => {
                    re.push_str(&regex::escape(&c.to_string()));
                    i += 1;
                }
            }
        }
        re.push('$');
        let regex = Regex::new(&re).map_err(|e| err(&e.to_string()))?;
        Ok(Glob {
            pattern: pattern.to_string(),
            regex,
        })
    }

    pub fn matches(&self, s: &str) -> bool {
        self.regex.is_match(s)
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// Escapes glob metacharacters so `s` matches literally (e.g. a home
/// directory that contains `[`).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Whether `component` (one path component of a pattern) contains glob
/// metacharacters.
pub fn is_literal(component: &str) -> bool {
    !component.contains(['*', '?', '[', '\\'])
}

/// Undoes [`escape`] for a literal component.
pub fn unescape(component: &str) -> String {
    let mut out = String::with_capacity(component.len());
    let mut chars = component.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Turns a configured path pattern into an absolute one: `~` and `~/...`
/// become the home directory, relative patterns are relative to `cwd`
/// (`./**/.env`). `.` components are dropped and `..` removes the previous
/// literal component. The home and current directories are escaped, so
/// metacharacters in them match literally.
pub fn expand_path(
    pattern: &str,
    home: Option<&std::path::Path>,
    cwd: &std::path::Path,
) -> Result<String, String> {
    let base = |dir: &std::path::Path| escape(&dir.to_string_lossy());
    let joined = if pattern == "~" || pattern.starts_with("~/") {
        let home = home.ok_or_else(|| format!("`{pattern}`: no home directory"))?;
        format!("{}/{}", base(home), &pattern[1..])
    } else if pattern.starts_with('~') {
        return Err(format!("`{pattern}`: `~user` is not supported"));
    } else if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("{}/{}", base(cwd), pattern)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => match parts.last() {
                Some(prev) if is_literal(prev) => {
                    parts.pop();
                }
                Some(_) => return Err(format!("`{pattern}`: `..` after a wildcard")),
                None => {}
            },
            p => parts.push(p),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, s: &str) -> bool {
        Glob::new(p).unwrap().matches(s)
    }

    #[test]
    fn star_and_question() {
        assert!(m("*", "GH_TOKEN"));
        assert!(m("*_TOKEN", "GH_TOKEN"));
        assert!(!m("*_TOKEN", "GH_TOKEN_X"));
        assert!(m("/h/.ssh/*", "/h/.ssh/id_rsa"));
        assert!(m("/h/.ssh/*", "/h/.ssh/.hidden"));
        assert!(!m("/h/.ssh/*", "/h/.ssh/sub/id_rsa"));
        assert!(m("id_?sa", "id_rsa"));
        assert!(!m("a?b", "a/b"));
    }

    #[test]
    fn double_star() {
        assert!(m("/p/**/.env", "/p/.env"));
        assert!(m("/p/**/.env", "/p/a/b/.env"));
        assert!(!m("/p/**/.env", "/p/a/b/x.env"));
        assert!(m("/p/**", "/p/a"));
        assert!(m("/p/**", "/p/a/b"));
        assert!(m("/p/**", "/p/"));
        assert!(!m("/p/**", "/p"));
        assert!(m("**/x", "x"));
        assert!(m("**/x", "a/b/x"));
        assert!(m("/p/a**b", "/p/axxb"));
        assert!(!m("/p/a**b", "/p/a/b"));
    }

    #[test]
    fn classes_and_escapes() {
        assert!(m("[abc]x", "bx"));
        assert!(!m("[!abc]x", "bx"));
        assert!(m("[!abc]x", "dx"));
        assert!(m("[a-c]", "b"));
        assert!(m("[]]", "]"));
        assert!(m(r"a\*b", "a*b"));
        assert!(!m(r"a\*b", "axb"));
        assert!(m("a.b", "a.b"));
        assert!(!m("a.b", "axb"));
        assert!(m("(x)+", "(x)+"));
    }

    #[test]
    fn errors() {
        assert!(Glob::new("[abc").is_err());
        assert!(Glob::new("abc\\").is_err());
        assert!(Glob::new("[!]").is_err());
    }

    #[test]
    fn expands_paths() {
        use std::path::Path;
        let home = Some(Path::new("/home/u"));
        let cwd = Path::new("/work/p");
        let e = |p: &str| expand_path(p, home, cwd);
        assert_eq!(e("~/.ssh/*").unwrap(), "/home/u/.ssh/*");
        assert_eq!(e("~").unwrap(), "/home/u");
        assert_eq!(e("./**/.env").unwrap(), "/work/p/**/.env");
        assert_eq!(e(".env").unwrap(), "/work/p/.env");
        assert_eq!(e("../shared/.env").unwrap(), "/work/shared/.env");
        assert_eq!(e("/etc//x/./y").unwrap(), "/etc/x/y");
        assert!(e("~root/x").is_err());
        assert!(e("/a/*/../b").is_err());
        assert!(expand_path("~/x", None, cwd).is_err());
        let odd = expand_path("~/x", Some(Path::new("/h/[a]")), cwd).unwrap();
        assert!(Glob::new(&odd).unwrap().matches("/h/[a]/x"));
    }

    #[test]
    fn escape_roundtrip() {
        let home = "/home/we[ir]d*";
        let g = Glob::new(&format!("{}/x", escape(home))).unwrap();
        assert!(g.matches("/home/we[ir]d*/x"));
        assert!(!g.matches("/home/wei/x"));
        assert!(!is_literal(&escape("a*")));
        assert!(is_literal("plain"));
        assert_eq!(unescape(&escape("we[ir]d*")), "we[ir]d*");
    }
}
