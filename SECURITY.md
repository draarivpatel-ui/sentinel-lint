# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x | yes |

The project is pre 1.0. Fixes land on `main` and are released as a patch
version. There are no long lived release branches.

## Reporting a vulnerability

Report privately through GitHub security advisories:
<https://github.com/sentinel-lint/sentinel-lint/security/advisories/new>

If advisory access is unavailable, contact the maintainers through the email
listed on the repository profile. Please do not open a public issue, a public
pull request or a discussion thread with reproduction steps.

Include:

- the version or commit you tested
- the smallest input that demonstrates the problem
- what the scanner reported and what it should have reported
- the impact you believe it has for a user

Do not include real credentials. If a report needs a live token to demonstrate
a pattern match, rotate it first and send only the shape.

## What counts as a vulnerability

This is a security tool, so its failure modes are unusual. All of the following
are in scope:

- **False negative with a realistic shape.** A known dangerous construct, for
  example an interpolated `github.event` value in a workflow `run:` block, that
  the scanner misses. This is the most important class: somebody relied on the
  scanner to block it.
- **Path escape.** Any way to make the walker read outside the scan root, or to
  make a rule read a file it was not given.
- **Denial of service on the scanner.** ReDoS in a rule pattern, unbounded
  memory from a crafted manifest, or a crash that prevents the rest of the scan
  from completing.
- **Suppression bypass.** An inline comment, config file or plugin load path
  that suppresses a finding the user did not intend to suppress.
- **Output injection.** A crafted path, message or rule id that breaks the SARIF
  or JSON report structure, or injects terminal escape sequences into the
  terminal reporter.
- **Code execution through scanning.** Anything that makes scanning a
  repository execute code from that repository without the user asking for it.
  Plugins named in a config file are documented as trusted code; everything
  else must be data.

## What is out of scope

- A missing rule for a pattern that is not in the documented rule set. Open a
  feature request instead.
- A false positive with no security consequence. Message quality issues are
  bugs, not vulnerabilities.
- Findings in a repository you do not own, unless they demonstrate a scanner
  defect. Send those to that repository's maintainers.
- Scanner output on intentionally vulnerable test fixtures.
- Social engineering, physical access or dependency confusion against the
  package name itself. Report those to the registry.

## Response

- Acknowledgement within three business days.
- An initial assessment, including whether the report is in scope, within seven
  business days.
- A fix or a mitigation plan for confirmed issues as soon as practical. A
  bypass that allows a critical finding to disappear is treated as urgent.

Credit is offered in the advisory unless you ask to stay anonymous. We do not
operate a paid bounty.

## Safe harbor

Good faith research on your own repositories and on this project's own code is
welcome. We will not pursue legal action for research that follows this policy,
avoids privacy violations and does not degrade service for other users.

## Design notes for reporters

Three properties are intentional and should not be weakened:

1. Rules never receive file system access. The engine reads files, rules
   receive text.
2. Symlinks are never followed by the walker and every resolved path must stay
   inside the scan root.
3. A rule failure is contained. It becomes a diagnostic and the scan
   continues.

Reports that weaken any of these are treated as security reports, not style
comments.
