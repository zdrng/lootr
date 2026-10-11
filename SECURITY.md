# Security policy

lootr runs on machines and in pipelines that hold secrets, and it reads them. A vulnerability in
lootr can expose exactly what it is meant to protect, so we treat security reports with priority.

## What counts as a vulnerability

- Any way for secret material (file contents, environment values, or anything derived from them
  that allows recovering them) to appear in a report, on stdout/stderr, in a file, or anywhere
  outside the process.
- Ways to make lootr follow symlinks, read non-regular files, read beyond the size limit, write
  anything besides the report, start a subprocess or open a network connection.
- Crashes, hangs or unbounded resource use caused by scanned files (malicious files in the
  scanned tree are in scope; a malicious config is not, because config is as trusted as code).
- Process hardening that does not take effect (core dumps, ptrace on Linux).
- Supply-chain issues in released binaries or the GitHub Action.

What lootr defends against, how, and the known residual risks: [docs/threat-model.md](docs/threat-model.md).

Out of scope: findings lootr misses or reports wrongly (open a normal issue), and attackers that
already run as root or as the scanning user while lootr runs.

## Reporting

Please do **not** open a public issue. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on the lootr repository. Include the lootr version,
the platform, and a minimal reproduction (use dummy secrets, never real ones).

We aim to acknowledge reports within 3 working days and to agree on a disclosure date with you;
the default is 90 days or the release of a fix, whichever comes first. We credit reporters in the
release notes unless you prefer otherwise.

## Supported versions

lootr is pre-1.0. Only the latest release receives security fixes.
