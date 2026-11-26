import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ActionInputError,
  buildStepSummary,
  escapeSummaryCell,
  isSupportedNodeVersion,
  parseExtraArgs,
  runGitHubAction,
  splitExtraArgs,
} from '../bin/github-action.mjs';
import { VERSION } from '../src/version.mjs';
import { captureStream, makeResult, writeTree } from './helpers.mjs';

const REPO_ROOT = fileURLToPath(new URL('../', import.meta.url));
const API_URL = new URL('../src/rule-api.mjs', import.meta.url).href;

async function makeActionTemp(t) {
  const base = path.join(REPO_ROOT, '.sentinel-out');
  await mkdir(base, { recursive: true });
  const created = await mkdtemp(path.join(base, 'github-action-test-'));
  const resolved = await realpath(created);
  t.after(async () => {
    await rm(resolved, { recursive: true, force: true });
  });
  return resolved;
}

function parseOutput(text) {
  const values = {};
  for (const line of text.split('\n')) {
    if (line === '') continue;
    const equals = line.indexOf('=');
    if (equals === -1) continue;
    values[line.slice(0, equals)] = line.slice(equals + 1);
  }
  return values;
}

async function runAction(t, overrides = {}, prepare = null) {
  const temp = await makeActionTemp(t);
  if (prepare !== null) await prepare(temp);

  const sarifPath = path.join(temp, 'nested', 'scan.sarif');
  const outputPath = path.join(temp, 'github-output.txt');
  const summaryPath = path.join(temp, 'step-summary.md');
  const values = typeof overrides === 'function' ? overrides(temp) : overrides;
  const env = {
    GITHUB_WORKSPACE: REPO_ROOT,
    GITHUB_OUTPUT: outputPath,
    GITHUB_STEP_SUMMARY: summaryPath,
    SENTINEL_INPUT_PATH: 'examples/clean-repo',
    SENTINEL_INPUT_FORMAT: 'sarif',
    SENTINEL_INPUT_SARIF_FILE: sarifPath,
    SENTINEL_INPUT_FAIL_ON: 'high',
    ...values,
  };

  const stdout = captureStream();
  const stderr = captureStream();
  const code = await runGitHubAction(env, { stdout, stderr, cwd: REPO_ROOT });
  const outputText = await readFile(outputPath, 'utf8');
  let summary = '';
  try {
    summary = await readFile(summaryPath, 'utf8');
  } catch {
    summary = '';
  }

  return {
    temp,
    sarifPath,
    outputPath,
    summaryPath,
    summary,
    outputs: parseOutput(outputText),
    code,
    stdout: stdout.text(),
    stderr: stderr.text(),
  };
}

async function missing(candidate) {
  await assert.rejects(() => access(candidate), /ENOENT/);
}

test('the action scans examples/clean-repo and writes valid SARIF and outputs', async (t) => {
  const result = await runAction(t);

  assert.equal(result.code, 0);
  assert.equal(result.outputs['findings-count'], '0');
  assert.equal(result.outputs['exit-code'], '0');
  assert.equal(result.outputs['sarif-file'], result.sarifPath);
  assert.match(result.stdout, /0 findings in 5 files/);
  assert.match(result.stdout, /wrote SARIF report/);

  const sarif = JSON.parse(await readFile(result.sarifPath, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'sentinel-lint');
  assert.equal(sarif.runs[0].tool.driver.version, VERSION);
  assert.deepEqual(sarif.runs[0].results, []);
  assert.match(result.summary, /\*\*0 findings\*\* in \*\*5 files\*\*/);
});

test('the action reports examples/vulnerable-repo findings and exits one at the high threshold', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_PATH: 'examples/vulnerable-repo' });

  assert.equal(result.code, 1);
  const count = Number(result.outputs['findings-count']);
  assert.ok(count > 0);
  assert.equal(result.outputs['exit-code'], '1');

  const sarif = JSON.parse(await readFile(result.sarifPath, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, count);
  assert.ok(sarif.runs[0].results.some((entry) => entry.ruleId === 'actions/script-injection'));
  assert.ok(
    sarif.runs[0].results.every((entry) =>
      entry.locations[0].physicalLocation.artifactLocation.uri.startsWith('examples/vulnerable-repo/'),
    ),
  );
  assert.match(result.summary, /\| Severity \| Rule \| Location \| Message \|/);
});

test('fail-on none exits zero while still writing SARIF for a vulnerable repository', async (t) => {
  const result = await runAction(t, {
    SENTINEL_INPUT_PATH: 'examples/vulnerable-repo',
    SENTINEL_INPUT_FAIL_ON: 'none',
  });

  assert.equal(result.code, 0);
  assert.ok(Number(result.outputs['findings-count']) > 0);
  assert.equal(result.outputs['exit-code'], '0');
  const sarif = JSON.parse(await readFile(result.sarifPath, 'utf8'));
  assert.equal(sarif.runs[0].results.length, Number(result.outputs['findings-count']));
});

test('the critical threshold does not fail on an error-only finding', async (t) => {
  const result = await runAction(
    t,
    (temp) => ({
      SENTINEL_INPUT_PATH: path.join(temp, 'project'),
      SENTINEL_INPUT_FAIL_ON: 'critical',
    }),
    async (temp) => {
      await writeTree(path.join(temp, 'project'), {
        'SECURITY.md': '# Security\n',
        'src/app.js': 'eval(input);\n',
      });
    },
  );

  assert.equal(result.code, 0);
  assert.equal(result.outputs['findings-count'], '1');
  assert.equal(result.outputs['exit-code'], '0');
});

test('a file target scans only that file without repository policy findings', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_PATH: 'examples/clean-repo/src/app.js' });

  assert.equal(result.code, 0);
  assert.equal(result.outputs['findings-count'], '0');
  const sarif = JSON.parse(await readFile(result.sarifPath, 'utf8'));
  assert.deepEqual(sarif.runs[0].results, []);
  assert.match(result.summary, /\*\*0 findings\*\* in \*\*1 file\*\*/);
});

test('the text format writes a terminal report and no SARIF output', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_FORMAT: 'text' });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /no findings/);
  assert.equal(result.outputs['sarif-file'], '');
  await missing(result.sarifPath);
});

test('the json format writes a machine readable report and no SARIF output', async (t) => {
  const result = await runAction(t, {
    SENTINEL_INPUT_PATH: 'examples/vulnerable-repo',
    SENTINEL_INPUT_FORMAT: 'json',
    SENTINEL_INPUT_FAIL_ON: 'none',
  });

  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.tool.name, 'sentinel-lint');
  assert.equal(report.summary.findings, Number(result.outputs['findings-count']));
  assert.equal(result.outputs['sarif-file'], '');
  await missing(result.sarifPath);
});

test('command substitution in the path input is never executed', async (t) => {
  const pwned = path.join(tmpdir(), `sentinel-action-pwned-${process.pid}-${Math.random().toString(16).slice(2)}`);
  t.after(async () => {
    await rm(pwned, { force: true });
  });

  const result = await runAction(t, { SENTINEL_INPUT_PATH: `$(touch ${pwned})` });

  assert.equal(result.code, 2);
  assert.match(result.stderr, /scan path not found/);
  await missing(pwned);
});

test('command substitution in args remains a literal glob and is never executed', async (t) => {
  const pwned = path.join(tmpdir(), `sentinel-args-pwned-${process.pid}-${Math.random().toString(16).slice(2)}`);
  t.after(async () => {
    await rm(pwned, { force: true });
  });

  const result = await runAction(t, {
    SENTINEL_INPUT_ARGS: `--include '**/*' --include '$(touch ${pwned})'`,
  });

  assert.equal(result.code, 0);
  assert.equal(result.outputs['findings-count'], '0');
  await missing(pwned);
});

test('shell control text in args is rejected as unsupported input', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_ARGS: '; rm -rf /' });

  assert.equal(result.code, 2);
  assert.match(result.stderr, /not a supported long option/);
  assert.equal(result.outputs['exit-code'], '2');
  assert.equal(result.outputs['findings-count'], '0');
});

test('path traversal outside the workspace is rejected', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_PATH: '..' });

  assert.equal(result.code, 2);
  assert.match(result.stderr, /inside the GitHub workspace/);
});

test('sarif-file traversal outside the workspace is rejected', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_SARIF_FILE: '../scan.sarif' });

  assert.equal(result.code, 2);
  assert.match(result.stderr, /sarif-file must stay inside the GitHub workspace/);
});

test('an invalid format is rejected and outputs are still written', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_FORMAT: 'xml' });

  assert.equal(result.code, 2);
  assert.match(result.stderr, /format must be one of sarif, text or json/);
  assert.equal(result.outputs['exit-code'], '2');
  assert.equal(result.outputs['findings-count'], '0');
  assert.equal(result.outputs['sarif-file'], '');
});

test('an invalid fail-on value is rejected and outputs are still written', async (t) => {
  const result = await runAction(t, { SENTINEL_INPUT_FAIL_ON: 'loud' });

  assert.equal(result.code, 2);
  assert.match(result.stderr, /fail-on must be one of critical, high, medium, low or none/);
  assert.equal(result.outputs['exit-code'], '2');
});

test('the step summary escapes HTML, pipes, links and line breaks in findings', async (t) => {
  const result = await runAction(
    t,
    (temp) => ({
      SENTINEL_INPUT_PATH: path.join(temp, 'project'),
      SENTINEL_INPUT_ARGS: `--plugin '${path.join(temp, 'project', 'plugin-rule.mjs')}'`,
    }),
    async (temp) => {
      await writeTree(path.join(temp, 'project'), {
        'SECURITY.md': '# Security\n',
        'note.txt': 'trigger\n',
        'plugin-rule.mjs': `import { defineRule } from ${JSON.stringify(API_URL)};
export default defineRule({
  id: 'plugin/markdown-injection',
  title: 'Markdown injection fixture',
  severity: 'error',
  appliesTo: ['**/*.txt'],
  check: () => [{ line: 1, column: 1, message: '<img src=x> | [bad](https://example.com)\\nsecond' }],
});
`,
      });
    },
  );

  assert.equal(result.code, 1);
  assert.match(result.summary, /&lt;img src=x&gt;/);
  assert.match(result.summary, /&#124;/);
  assert.match(result.summary, /&#91;bad&#93;/);
  assert.equal(result.summary.includes('<img src=x>'), false);
  assert.equal(result.summary.includes('[bad](https://example.com)'), false);
  assert.equal(result.summary.includes('\\nsecond'), false);
});

test('extra args supports quoted values and validated scan flags', () => {
  const parsed = parseExtraArgs('--include "**/*.js" --exclude=vendor/** --max-findings 7 --quiet --no-color');
  assert.deepEqual(parsed.include, ['**/*.js']);
  assert.deepEqual(parsed.exclude, ['vendor/**']);
  assert.equal(parsed.maxFindings, 7);
  assert.equal(parsed.quiet, true);
  assert.equal(parsed.color, false);
});

test('splitExtraArgs rejects an unterminated quote', () => {
  assert.throws(() => splitExtraArgs('--include "unterminated'), ActionInputError);
});

test('parseExtraArgs rejects an unknown or input overriding flag', () => {
  assert.throws(() => parseExtraArgs('--format sarif'), ActionInputError);
  assert.throws(() => parseExtraArgs('--unknown value'), ActionInputError);
});

test('escapeSummaryCell escapes markdown and HTML significant characters', () => {
  assert.equal(escapeSummaryCell('<a&b> | [x]\nnext'), '&lt;a&amp;b&gt; &#124; &#91;x&#93; next');
});

test('buildStepSummary renders a compact escaped findings table', () => {
  const scan = makeResult({
    findings: [
      {
        severity: 'critical',
        ruleId: 'plugin/demo',
        file: 'src/a|b.js',
        line: 2,
        column: 3,
        message: '<script>alert(1)</script>',
      },
    ],
  });
  const summary = buildStepSummary(scan, { failOn: 'high' }, 1);
  assert.match(summary, /\| Severity \| Rule \| Location \| Message \|/);
  assert.match(summary, /src\/a&#124;b\.js:2:3/);
  assert.match(summary, /&lt;script&gt;alert\(1\)&lt;&#x2F;script&gt;|&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test('the Node.js version gate accepts 18.18 and newer supported versions', () => {
  assert.equal(isSupportedNodeVersion('18.18.0'), true);
  assert.equal(isSupportedNodeVersion('20.0.0'), true);
  assert.equal(isSupportedNodeVersion('18.17.1'), false);
  assert.equal(isSupportedNodeVersion('16.20.2'), false);
});
