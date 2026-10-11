//! lootr binary: harden the process, then hand over to the CLI.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Before any file is opened or any secret is read.
    if let Err(e) = lootr::os::hardening::harden() {
        let _ = writeln!(std::io::stderr(), "error: process hardening: {e}");
        return ExitCode::from(2);
    }
    lootr::cli::run()
}
