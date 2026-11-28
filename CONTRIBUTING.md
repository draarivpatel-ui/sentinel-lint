# Contributing to sentinel-lint

Thanks for helping. This project is deliberately small: a rule engine, three
reporters, a CLI and a pack of rules. Everything below exists to keep it that
way.

## Ground rules

1. **Zero runtime dependencies.** `package.json` keeps `dependencies` empty.
   `fast-check` is development-only for the separate fuzz suite. Node.js built in
   modules are the only runtime imports.
2. **Node.js 18.18 or newer.** No syntax or API that is unavailable there.
3. **Deterministic output.** Two scans of identical input produce identical
   findings, in identical order. No timestamps, random ids or directory order.
4. **Plain ASCII in source, tests and docs.** No em dashes, no smart quotes, no
   non-ASCII arrows.
5. **No network and no personal paths.** Tests use temporary directories and
   never read outside them. Fixtures use synthetic values only.
6. **Small, explained changes.** One concern per pull request.

## Add a new security rule in 4 steps (5 minutes)

Most first rules take about five minutes to scaffold and fifteen minutes to
finish. The exact files are named in each ready-to-claim specification.

1. **Pick a specification.** Open [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md),
   choose an unclaimed item, and keep its rule id, globs, severity and acceptance
   criteria unchanged unless the issue discussion says otherwise.
2. **Add the rule.** Create or edit the `src/rules/*.mjs` file named in the
   specification and export a `defineRule` descriptor. Follow the closest existing
   rule in `src/rules/actions.mjs`, `src/rules/mcp.mjs` or `src/rules/repo.mjs`,
   then register the module in `src/rules/index.mjs`.
3. **Prove the behavior.** Add tests to the `tests/rules-*.test.mjs` file named in
   the specification with `scanTree` and `byRule` from `tests/helpers.mjs`. Cover
   one finding, one clean input and one near miss.
4. **Document and verify.** Add the rule section to `docs/rules.md`, add its row to
   the README rule table, then run exactly:

   ```bash
   npm test
   npm run self-scan
   ```

   Both commands must pass before you open the pull request.

## Getting started

```bash
git clone <your fork>
cd sentinel-lint
npm test          # 646 tests, no install step
npm run self-scan # self scan must stay clean
```

There is no build step, no bundler and no transpiler. `bin/sentinel-lint.mjs`
imports `src/cli.mjs`, which imports the same modules the tests import.

## The rule contract

```js
import { defineRule } from '../src/rule-api.mjs';

export const exampleRule = defineRule({
  id: 'demo/example-rule',          // category/rule-name, lowercase and hyphens
  title: 'One line description',    // shown in the terminal reporter
  category: 'demo',                 // defaults to the id prefix
  severity: 'warning',              // info, warning, error or critical
  cwe: 'CWE-200',                   // optional but expected for security rules
  docsUrl: 'docs/rules.md#demoexample-rule',
  rationale: 'Why this matters. This text becomes the SARIF full description.',
  fix: 'What to do instead. This text becomes the SARIF help text.',
  appliesTo: ['**/*.js'],           // file rules need globs or a match function
  check(ctx) {
    return [{ line: 1, column: 1, message: 'What is wrong here.' }];
  },
});
```

`defineRule` validates the descriptor once at load time. The engine calls
`check` with a context that contains:

| Field | File rules | Repository rules |
| ----- | ---------- | ---------------- |
| `ctx.text` | file contents | empty string |
| `ctx.lines` | pre-split lines | empty array |
| `ctx.file` | `{ path, name, ext, size, text }` | `null` |
| `ctx.path` | repository relative path | `null` |
| `ctx.root` | absolute scan root | absolute scan root |
| `ctx.files` | every scanned file record | every scanned file record |
| `ctx.paths` | every repository relative path | every repository relative path |
| `ctx.read` | read a scanned file by path, or `null` | read a scanned file by path, or `null` |
| `ctx.report` | report a finding | report a finding |

Return an array of findings, call `ctx.report`, or both. A finding needs a
1-based `line` and `column` for file rules. Line numbers beyond the end of the
file are rejected with a diagnostic, which protects editors and SARIF
consumers from impossible regions.

### Rule id and documentation anchor

The `id` is `category/rule-name`. The docs anchor is the id with every
character that is not a letter, digit or hyphen removed, lowercased:

- `actions/script-injection` becomes `actionsscript-injection`
- `mcp/broad-filesystem-root` becomes `mcpbroad-filesystem-root`

`docsUrl` must be `docs/rules.md#<anchor>` and `docs/rules.md` must have a
heading whose text is the rule id. The test suite enforces both.

### Quality bar for a new rule

- The pattern is specific enough that a clean repository does not match.
- Comments and string literals are ignored where they would cause noise.
- Every finding points at the smallest useful region.
- The fix text is actionable without opening the docs.
- The rule cannot loop forever on adversarial input: no nested quantifiers over
  the same character class, no unbounded backtracking.
- Findings are capped when a single file could produce thousands of them.

## Tests

Every rule needs at least:

1. A fixture that produces the finding, asserting rule id, line and a message
   fragment.
2. A fixture that must stay clean.
3. A near miss: the shape that looks similar but is safe.

Use the helpers in `tests/helpers.mjs`:

```js
import { byRule, scanTree } from './helpers.mjs';

test('my rule flags the bad shape', async (t) => {
  const result = await scanTree(t, { 'src/app.js': 'dangerousCall(userInput);\n' });
  const findings = byRule(result, 'demo/example-rule');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 1);
});
```

`scanTree` writes a temporary repository, runs the real engine and removes the
directory when the test finishes. Do not mock the engine: the value of these
tests is that they exercise the real file walker, glob matcher and suppression
logic.

Run everything with `npm test`. Failures print the assertion, the fixture line
and the reported position, which is usually enough to see whether the rule or
the expectation is wrong.

## Reporters and engine changes

The reporters are pure functions from a scan result to a string. If you change
the SARIF shape, update `tests/reporters.test.mjs` and keep `$schema`,
`version`, `tool.driver.rules`, `results[].ruleIndex` and
`partialFingerprints` intact. Those five fields are what GitHub code scanning
consumes.

Engine changes must preserve three properties:

- rule isolation: a throwing rule produces a diagnostic and never stops the scan
- determinism: file order, finding order and severity counts are stable
- bounded output: diagnostics are capped, as are pathological finding counts

## Pull requests

Open the pull request against `main` and fill in the template. A change is
ready when:

- `npm test` passes with no skipped tests
- `npm run self-scan` reports no findings
- new behavior has tests, and docs are updated in the same commit
- the pull request explains the failure mode, not only the code change

Small fixes (typos, message wording, a missed near miss) can go straight to a
pull request. New rules should reference an issue from
[GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md) or a matching bug report.

## Security work

Do not open a public issue for a bypass that lets a known bad shape pass the
scanner. Follow [SECURITY.md](SECURITY.md): a false negative is a security bug
in this project, because other people rely on the scanner to block that shape.

## License

Contributions are accepted under the MIT license in [LICENSE](LICENSE).
