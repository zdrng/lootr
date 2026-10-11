//! Progress on stderr in the style of cargo: one line per finished step with
//! a right-aligned verb and the time it took. stdout carries only the report.
//! `--quiet` keeps warnings and errors; colors only on a terminal and
//! without `NO_COLOR`.

use std::fmt::Display;
use std::io::Write;
use std::time::Instant;

use crate::service::scan;

const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const RED: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

pub struct Progress {
    out: Box<dyn Write>,
    quiet: bool,
    color: bool,
    last: Instant,
}

impl Progress {
    pub fn new(out: Box<dyn Write>, quiet: bool, color: bool) -> Progress {
        Progress {
            out,
            quiet,
            color,
            last: Instant::now(),
        }
    }

    /// `    Finished message`.
    pub fn line(&mut self, verb: &str, message: impl Display) {
        if self.quiet {
            return;
        }
        let verb = self.paint(GREEN, &format!("{verb:>12}"));
        let _ = writeln!(self.out, "{verb} {message}");
        self.last = Instant::now();
    }

    /// `warning: message`, also with `--quiet`.
    pub fn warn(&mut self, message: impl Display) {
        let tag = self.paint(YELLOW, "warning");
        let _ = writeln!(self.out, "{tag}: {message}");
    }

    /// `error: message`, also with `--quiet`.
    pub fn error(&mut self, message: impl Display) {
        let tag = self.paint(RED, "error");
        let _ = writeln!(self.out, "{tag}: {message}");
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }
}

impl scan::Progress for Progress {
    fn step(&mut self, verb: &str, message: &str) {
        let took = self.last.elapsed().as_secs_f64();
        self.line(verb, format!("{message} ({took:.1}s)"));
    }
}
