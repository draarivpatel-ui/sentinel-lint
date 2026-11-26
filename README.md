# sentinel-lint

A plugin-first, zero-dependency security policy linter for repositories, GitHub
Actions workflows and MCP configurations. It ships **15 security rules**, a
stable rule API, three reporters (terminal, JSON and SARIF 2.1.0) and **359
tests** that run on the Node.js built in test runner without installing a
single package.

```
$ node bin/sentinel-lint.mjs scan .
sentinel-lint 0.1.1
scan root /home/dev/project

.github/workflows/release.yml
  18:14    CRITICAL actions/script-injection  Untrusted expression "${{ github.event.pull_request.title }}" is interpolated directly into a shell script. Assign it to env: and use the shell variable instead.
           fix: Put the value in an env: variable and reference the shell variable ("$TITLE"), which the shell treats as data.

mcp.json
  12:28    CRITICAL mcp/plaintext-secret     MCP server "github" sets env.GITHUB_PERSONAL_ACCESS_TOKEN to a literal value that matches a GitHub token pattern. Use a secret reference instead.
           fix: Replace the literal with an environment variable reference or a secret manager lookup, and rotate any credential that was committed.

7 files scanned, 2 findings (2 critical)
```

## Why this exists

Two classes of configuration are now security critical and are rarely reviewed
as code:

- **GitHub Actions workflows** run with repository secrets and a token. A
  `${{ github.event.pull_request.title }}` inside a `run:` block is remote code
  execution from a fork. A third-party action on `@v4` is unread code that can
  move under you.
- **MCP manifests** are copied between machines and pasted into issues. They
  carry API keys, launch packages from the network and grant filesystem access.

sentinel-lint checks both, plus the ordinary repository hygiene that precedes
most incidents: committed credentials, dynamic code sinks, HTML sinks, shell
injection and a missing disclosure policy.

## Install and run

Requires Node.js 18.18 or newer. There is nothing to install at runtime.

```bash
# from a checkout
node bin/sentinel-lint.mjs scan .

# package form, once published
npx sentinel-lint scan .
```

Common invocations:

```bash
sentinel-lint scan . --sarif --output sentinel.sarif   # GitHub code scanning
sentinel-lint scan . --json                            # machine readable
sentinel-lint scan . --fail-on error                   # tolerate warnings in CI
sentinel-lint scan . --quiet                           # one summary line
sentinel-lint rules                                    # list active rules
sentinel-lint init .                                   # write .sentinelrc.json
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Scan completed, no finding reached the fail threshold |
| 1 | At least one finding reached the fail threshold |
| 2 | Usage error, missing path or invalid configuration |
| 3 | Unexpected internal error |

By default the threshold is `warning`. `--fail-on critical` makes the command
advisory for errors but blocking for critical findings, and `--fail-on off`
never fails.

### GitHub code scanning

```yaml
- name: sentinel-lint
  run: node bin/sentinel-lint.mjs scan . --sarif --output sentinel.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

The SARIF log is 2.1.0, lists every rule under `tool.driver.rules`, maps
`critical` and `error` to `error`, `warning` to `warning` and `info` to `note`,
and gives every result a stable `partialFingerprints` hash that does not change
when a finding moves down a file.

## Rules

All 15 rules are ordinary plugins. There is no privileged path in the engine.

| Rule | Severity | Catches |
| ---- | -------- | ------- |
| `actions/script-injection` | critical | Untrusted context interpolated into a `run:` script |
| `actions/unpinned-action` | warning | Third-party action on a mutable tag or branch |
| `actions/write-all-permissions` | error | Workflow grants `write-all` token permissions |
| `actions/pull-request-target-checkout` | critical | `pull_request_target` checks out fork code |
| `mcp/plaintext-secret` | critical | Literal credential in an MCP manifest |
| `mcp/unpinned-npx-package` | warning | `npx` package without an exact version |
| `mcp/shell-metacharacter-arg` | error | Server argument a shell would interpret |
| `mcp/broad-filesystem-root` | error | Filesystem server rooted at `/` or `~` |
| `mcp/insecure-remote-url` | error | Remote MCP endpoint over plain HTTP |
| `mcp/invalid-config` | warning | Manifest that is not valid JSON |
| `repo/hardcoded-token` | critical | Vendor credential shape committed to source |
| `repo/dangerous-eval` | error | `eval` and `new Function` sinks |
| `repo/dangerous-html-sink` | error | `innerHTML`, `document.write`, `dangerouslySetInnerHTML` |
| `repo/child-process-injection` | error | `exec` command built from interpolated data |
| `repo/missing-security-policy` | warning | No `SECURITY.md` disclosure policy |

Rule details, examples and remediation live in [docs/rules.md](docs/rules.md).

## Configuration

`.sentinelrc.json` at the scan root, or pass `--config`. Comments and trailing
commas are accepted.

```json
{
  "failOn": "warning",
  "include": [],
  "exclude": ["vendor/**", "tests/fixtures/**"],
  "rules": {
    "repo/missing-security-policy": "off",
    "actions/unpinned-action": "error"
  },
  "plugins": ["./tools/sentinel/team-rules.mjs"],
  "maxFileSize": 1048576,
  "maxFiles": 20000
}
```

Rule values are `info`, `warning`, `error`, `critical` or `off`. Unknown rule
ids and unknown top level keys produce diagnostics instead of being ignored
silently.

## Inline suppression

```js
// sentinel-ignore-next-line
const parsed = eval(document); // documented exception

const parsed = eval(document); // sentinel-ignore-line repo/dangerous-eval

// sentinel-ignore-file repo/dangerous-html-sink -- generated template
```

A marker with no rule ids suppresses every rule for its target. Text after
`--` is a human reason and is ignored, so a sentence that mentions a rule id
cannot accidentally widen a suppression.

## Plugins

```js
// tools/sentinel/team-rules.mjs
import { defineRule } from 'sentinel-lint';

export const rules = [
  defineRule({
    id: 'team/internal-host',
    title: 'Internal hostname is hardcoded',
    severity: 'error',
    category: 'team',
    cwe: 'CWE-200',
    appliesTo: ['**/*.js', '**/*.mjs'],
    check(ctx) {
      return ctx.text.includes('internal.example.corp')
        ? [{ line: 1, column: 1, message: 'Use the service discovery name.' }]
        : [];
    },
  }),
];
```

A plugin may default export one rule, an array of rules, or export a named
`rules` array. Plugin code runs in the same process as the scanner, so a config
file from an untrusted repository is exactly as dangerous as a `postinstall`
script. Read plugin paths before scanning.

Plugin paths declared in a config file must resolve inside the directory that
holds that config, after symlinks are resolved, so a committed config cannot
reach into an unrelated directory. Pass `--plugin` on the command line for a
module stored elsewhere; paths named on the command line are not restricted.

## Programmatic API

```js
import { scan, formatSarif } from 'sentinel-lint';

const result = await scan({ root: process.cwd() });
process.stdout.write(formatSarif(result, { version: '0.1.1' }));
```

`scan` never throws for a rule failure. A rule that crashes or returns junk
produces a diagnostic, increments `stats.ruleErrors`, and the scan continues,
so one bad plugin cannot hide every other finding.

## What the rules are not

These are high precision heuristics, not a proof of safety. They do not perform
dataflow analysis, resolve transitive dependencies or replace review. A clean
scan means the known bad shapes are absent, nothing more. Report suspected
false negatives through [SECURITY.md](SECURITY.md).

## Development

```bash
node --test tests/        # 359 tests, no install step
node bin/sentinel-lint.mjs scan .   # self scan
```

Tests are deterministic, use the real filesystem only through temporary
directories, and never reach the network. New rules need fixtures for both the
finding case and the clean case.

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md)

## License

MIT
