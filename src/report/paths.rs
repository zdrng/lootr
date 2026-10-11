//! How paths appear in reports (every format, and the CLI's stderr lines).
//!
//! - **`~` normalization** (always): a path below the home directory is shown
//!   as `~/...` (`~` for the home itself). `run.home` keeps the absolute home
//!   directory, so consumers can expand it again. Rules, waivers and CEL
//!   always see absolute paths; only the presentation changes.
//! - **`--redact-paths`**: paths below the working directory (the project)
//!   stay visible, relative (`./src/.env`); every other path is replaced by a
//!   numbered placeholder that keeps only its anchor: `~/<redacted:1>` below
//!   the home directory, `<redacted:2>` elsewhere. The same path gets the same
//!   number within one report. If the working directory is `/`, the home
//!   directory or above it, every path is redacted. `run.home` and `run.cwd`
//!   become `<redacted>`. Values that come from the config (waiver globs,
//!   message templates) are not paths found on the machine and stay as
//!   written.

use std::collections::BTreeMap;
use std::path::Path;

/// Placeholder for `run.home` / `run.cwd` with `--redact-paths`.
pub const REDACTED: &str = "<redacted>";

pub struct PathMapper {
    home: Option<String>,
    cwd: String,
    redact: bool,
    /// Whether paths below `cwd` stay visible when redacting.
    keep_cwd: bool,
    numbers: BTreeMap<String, usize>,
}

impl PathMapper {
    pub fn new(home: Option<&Path>, cwd: &Path, redact: bool) -> PathMapper {
        let home = home
            .map(|h| h.to_string_lossy().trim_end_matches('/').to_string())
            .filter(|h| !h.is_empty());
        let cwd = cwd.to_string_lossy().trim_end_matches('/').to_string();
        let keep_cwd = !cwd.is_empty()
            && home
                .as_deref()
                .is_none_or(|h| below(h, &cwd).is_none() && h != cwd);
        PathMapper {
            home,
            cwd,
            redact,
            keep_cwd,
            numbers: BTreeMap::new(),
        }
    }

    /// The working directory as it appears in mapped paths: `None` when
    /// paths below it are shown relative (`./x`, with `--redact-paths`) or
    /// redacted.
    pub fn cwd_prefix(&self) -> Option<String> {
        if self.redact {
            None
        } else {
            Some(self.normalize(&self.cwd))
        }
    }

    /// A path as shown in the report.
    pub fn map(&mut self, path: &str) -> String {
        if !path.starts_with('/') {
            // `<built-in>` and other names that are not paths.
            return path.to_string();
        }
        if !self.redact {
            return self.normalize(path);
        }
        if self.keep_cwd
            && let Some(rel) = below(path, &self.cwd)
        {
            return if rel.is_empty() {
                ".".to_string()
            } else {
                format!("./{rel}")
            };
        }
        let next = self.numbers.len() + 1;
        let n = *self.numbers.entry(path.to_string()).or_insert(next);
        let in_home = self
            .home
            .as_deref()
            .is_some_and(|h| below(path, h).is_some());
        if in_home {
            format!("~/<redacted:{n}>")
        } else {
            format!("<redacted:{n}>")
        }
    }

    /// `run.home` / `run.cwd`: absolute, or [`REDACTED`].
    pub fn run_dir(&self, dir: &str) -> String {
        if self.redact {
            REDACTED.to_string()
        } else {
            dir.to_string()
        }
    }

    /// Replaces `path` in free text (rendered messages) by its mapped form.
    pub fn text(&mut self, text: &str, path: &str) -> String {
        if path.is_empty() || !text.contains(path) {
            return text.to_string();
        }
        let mapped = self.map(path);
        text.replace(path, &mapped)
    }

    fn normalize(&self, path: &str) -> String {
        match self.home.as_deref().and_then(|h| below(path, h)) {
            Some("") => "~".to_string(),
            Some(rel) => format!("~/{rel}"),
            None => path.to_string(),
        }
    }
}

/// `path` relative to `base` if it is `base` itself (`""`) or below it.
pub fn below<'a>(path: &'a str, base: &str) -> Option<&'a str> {
    if base.is_empty() || base == "/" {
        return path.strip_prefix('/');
    }
    let rest = path.strip_prefix(base)?;
    if rest.is_empty() {
        Some("")
    } else {
        rest.strip_prefix('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapper(redact: bool, cwd: &str) -> PathMapper {
        PathMapper::new(Some(Path::new("/home/u")), Path::new(cwd), redact)
    }

    #[test]
    fn home_is_normalized_to_tilde() {
        let mut m = mapper(false, "/home/u/proj");
        assert_eq!(m.map("/home/u/.ssh/id_rsa"), "~/.ssh/id_rsa");
        assert_eq!(m.map("/home/u"), "~");
        assert_eq!(m.map("/home/u2/x"), "/home/u2/x");
        assert_eq!(m.map("/var/run/docker.sock"), "/var/run/docker.sock");
        assert_eq!(m.map("<built-in>"), "<built-in>");
        assert_eq!(m.cwd_prefix().as_deref(), Some("~/proj"));
        assert_eq!(
            m.text("key /home/u/.ssh/a is open", "/home/u/.ssh/a"),
            "key ~/.ssh/a is open"
        );
        assert_eq!(m.run_dir("/home/u"), "/home/u");
    }

    #[test]
    fn redaction_keeps_the_project_and_numbers_the_rest() {
        let mut m = mapper(true, "/home/u/proj");
        assert_eq!(m.map("/home/u/proj/.env"), "./.env");
        assert_eq!(m.map("/home/u/proj"), ".");
        assert_eq!(m.map("/home/u/.ssh/id_rsa"), "~/<redacted:1>");
        assert_eq!(m.map("/var/run/docker.sock"), "<redacted:2>");
        assert_eq!(m.map("/home/u/.ssh/id_rsa"), "~/<redacted:1>");
        assert_eq!(m.map("/home/u/project2/x"), "~/<redacted:3>");
        assert_eq!(m.cwd_prefix(), None);
        assert_eq!(m.run_dir("/home/u"), REDACTED);
    }

    #[test]
    fn redaction_from_home_or_root_hides_everything() {
        for cwd in ["/home/u", "/", "/home"] {
            let mut m = mapper(true, cwd);
            assert_eq!(m.map("/home/u/.env"), "~/<redacted:1>", "{cwd}");
            assert_eq!(m.map("/etc/x"), "<redacted:2>", "{cwd}");
        }
    }

    #[test]
    fn below_handles_prefixes_and_root() {
        assert_eq!(below("/a/b", "/a"), Some("b"));
        assert_eq!(below("/a", "/a"), Some(""));
        assert_eq!(below("/ab", "/a"), None);
        assert_eq!(below("/x/y", "/"), Some("x/y"));
    }
}
