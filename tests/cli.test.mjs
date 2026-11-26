import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { EXIT_CODES, UsageError, parseArgv, run } from '../src/cli.mjs';
import { RULE_COUNT } from '../src/rules/index.mjs';
import { VERSION } from '../src/version.mjs';
import { CLEAN_TREE, captureStream, makeTempDir, makeTree } from './helpers.mjs';

const API_URL = new URL('../src/rule-api.mjs', import.meta.url).href;

async function runCli(argv, cwd) {
  const stdout = captureStream();
  const stderr = captureStream();
  const code = await run(argv, { stdout, stderr, cwd });
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

const DIRTY_TREE = { 'SECURITY.md': '# Security\n', 'src/app.js': 'eval(input);\n' };

test('--version prints the package version', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['--version'], root);
  assert.equal(result.code, EXIT_CODES.ok);
  assert.equal(result.stdout.trim(), VERSION);
});

test('the version subcommand prints the package version', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['version'], root);
  assert.equal(result.code, EXIT_CODES.ok);
  assert.equal(result.stdout.trim(), VERSION);
});

test('--help prints usage and exit codes', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['--help'], root);
  assert.equal(result.code, EXIT_CODES.ok);
  assert.match(result.stdout, /Usage: sentinel-lint/);
  assert.match(result.stdout, /Exit codes: 0 clean/);
});

test('the help subcommand prints usage', async (t) => {
  const root = await makeTempDir(t);
  assert.match((await runCli(['help'], root)).stdout, /Commands:/);
});

test('an unknown option is a usage error', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['--nope'], root);
  assert.equal(result.code, EXIT_CODES.usage);
  assert.match(result.stderr, /unknown option "--nope"/);
});

test('a missing scan path is a usage error', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['scan', 'missing-directory'], root);
  assert.equal(result.code, EXIT_CODES.usage);
  assert.match(result.stderr, /scan path not found/);
});

test('a clean repository exits zero', async (t) => {
  const root = await makeTree(t, CLEAN_TREE);
  const result = await runCli(['scan', '.'], root);
  assert.equal(result.code, EXIT_CODES.ok);
  assert.match(result.stdout, /no findings/);
});

test('a repository with an error finding exits one', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.'], root);
  assert.equal(result.code, EXIT_CODES.findings);
  assert.match(result.stdout, /repo\/dangerous-eval/);
});

test('--fail-on critical ignores error findings', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.', '--fail-on', 'critical'], root);
  assert.equal(result.code, EXIT_CODES.ok);
});

test('--fail-on off never fails the build', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  assert.equal((await runCli(['scan', '.', '--fail-on', 'off'], root)).code, EXIT_CODES.ok);
});

test('--format json writes a parseable report and a stderr summary', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.', '--format', 'json'], root);
  const report = JSON.parse(result.stdout);
  assert.equal(report.reportVersion, 1);
  assert.equal(report.summary.findings, 1);
  assert.match(result.stderr, /sentinel-lint: 1 finding in \d+ files/);
});

test('--json is a shorthand for the JSON reporter', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.', '--json'], root);
  assert.equal(JSON.parse(result.stdout).tool.name, 'sentinel-lint');
});

test('--sarif writes a SARIF 2.1.0 log', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.', '--sarif'], root);
  const log = JSON.parse(result.stdout);
  assert.equal(log.version, '2.1.0');
  assert.equal(log.runs.length, 1);
  assert.equal(log.runs[0].results.length, 1);
});

test('--output writes the report to a file', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.', '--sarif', '--output', 'report.sarif'], root);
  assert.equal(result.code, EXIT_CODES.findings);
  assert.match(result.stderr, /wrote sarif report to report\.sarif/);
  const written = JSON.parse(await readFile(path.join(root, 'report.sarif'), 'utf8'));
  assert.equal(written.version, '2.1.0');
  assert.equal(result.stdout, '');
});

test('--output - writes the report to stdout', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.', '--json', '--output', '-'], root);
  assert.equal(JSON.parse(result.stdout).summary.findings, 1);
});

test('--quiet prints only the summary line', async (t) => {
  const root = await makeTree(t, DIRTY_TREE);
  const result = await runCli(['scan', '.', '--quiet'], root);
  assert.equal(result.stdout.includes('repo/dangerous-eval'), false);
  assert.match(result.stdout, /1 finding/);
});

test('--max-findings caps the terminal reporter', async (t) => {
  const root = await makeTree(t, {
    'SECURITY.md': '# Security\n',
    'src/app.js': 'eval(one);\ndocument.write(two);\n',
  });
  const result = await runCli(['scan', '.', '--max-findings', '1'], root);
  assert.match(result.stdout, /1 more finding not shown/);
});

test('an invalid --max-findings value is rejected', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['scan', '.', '--max-findings', '0'], root);
  assert.equal(result.code, EXIT_CODES.usage);
  assert.match(result.stderr, /positive integer/);
});

test('an unknown format is rejected', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['scan', '.', '--format', 'xml'], root);
  assert.equal(result.code, EXIT_CODES.usage);
  assert.match(result.stderr, /unknown format "xml"/);
});

test('a missing explicit config is a usage error', async (t) => {
  const root = await makeTree(t, CLEAN_TREE);
  const result = await runCli(['scan', '.', '--config', 'missing.json'], root);
  assert.equal(result.code, EXIT_CODES.usage);
  assert.match(result.stderr, /config file not found/);
});

test('the config file can raise the failure threshold', async (t) => {
  const root = await makeTree(t, { ...DIRTY_TREE, '.sentinelrc.json': '{\n  "failOn": "critical"\n}\n' });
  assert.equal((await runCli(['scan', '.'], root)).code, EXIT_CODES.ok);
});

test('the config file can switch a rule off', async (t) => {
  const root = await makeTree(t, {
    ...DIRTY_TREE,
    '.sentinelrc.json': '{\n  "rules": { "repo/dangerous-eval": "off" }\n}\n',
  });
  const result = await runCli(['scan', '.', '--fail-on', 'warning'], root);
  assert.equal(result.code, EXIT_CODES.ok);
  assert.equal(result.stdout.includes('repo/dangerous-eval'), false);
});

test('the rules command lists every active rule', async (t) => {
  const root = await makeTree(t, CLEAN_TREE);
  const result = await runCli(['rules'], root);
  assert.equal(result.code, EXIT_CODES.ok);
  assert.match(result.stdout, /actions\/script-injection/);
  assert.match(result.stdout, new RegExp(`${RULE_COUNT} active rules`));
});

test('the rules command accepts a JSON format', async (t) => {
  const root = await makeTree(t, CLEAN_TREE);
  const result = await runCli(['rules', '--format', 'json'], root);
  const rules = JSON.parse(result.stdout);
  assert.equal(rules.length, RULE_COUNT);
  assert.equal(typeof rules[0].docsUrl, 'string');
});

test('init writes a starter config', async (t) => {
  const root = await makeTempDir(t);
  const result = await runCli(['init', '.'], root);
  assert.equal(result.code, EXIT_CODES.ok);
  const config = JSON.parse(await readFile(path.join(root, '.sentinelrc.json'), 'utf8'));
  assert.equal(config.failOn, 'warning');
  assert.deepEqual(config.rules, {});
});

test('init refuses to overwrite without --force', async (t) => {
  const root = await makeTempDir(t);
  await runCli(['init', '.'], root);
  const second = await runCli(['init', '.'], root);
  assert.equal(second.code, EXIT_CODES.usage);
  assert.match(second.stderr, /already exists/);
  const forced = await runCli(['init', '.', '--force'], root);
  assert.equal(forced.code, EXIT_CODES.ok);
});

test('--plugin loads an extra rule module', async (t) => {
  const root = await makeTree(t, CLEAN_TREE);
  const plugin = `import { defineRule } from ${JSON.stringify(API_URL)};
export default defineRule({
  id: 'plugin/demo',
  title: 'Demo plugin rule',
  severity: 'warning',
  appliesTo: ['**/*.js'],
  check: () => [{ line: 1, column: 1, message: 'plugin finding' }],
});
`;
  await writeFile(path.join(root, 'plugin-rule.mjs'), plugin, 'utf8');
  const result = await runCli(['scan', '.', '--plugin', 'plugin-rule.mjs'], root);
  assert.equal(result.code, EXIT_CODES.findings);
  assert.match(result.stdout, /plugin\/demo/);
});

test('parseArgv normalizes a full scan invocation', () => {
  const options = parseArgv(['scan', 'repo', '--format', 'json', '--fail-on', 'error', '-o', 'out.json']);
  assert.equal(options.command, 'scan');
  assert.equal(options.target, 'repo');
  assert.equal(options.format, 'json');
  assert.equal(options.failOn, 'error');
  assert.equal(options.output, 'out.json');
});

test('parseArgv defaults to the scan command', () => {
  const options = parseArgv(['src', '--json']);
  assert.equal(options.command, 'scan');
  assert.equal(options.target, 'src');
  assert.equal(options.format, 'json');
});

test('parseArgv collects repeatable globs and plugins', () => {
  const options = parseArgv(['scan', '.', '--include', '**/*.js', '--include', '**/*.ts', '--plugin', 'a.mjs']);
  assert.deepEqual(options.include, ['**/*.js', '**/*.ts']);
  assert.deepEqual(options.plugins, ['a.mjs']);
});

test('parseArgv accepts equals separated values', () => {
  const options = parseArgv(['rules', '--format=json']);
  assert.equal(options.command, 'rules');
  assert.equal(options.format, 'json');
});

test('parseArgv rejects extra positionals', () => {
  assert.throws(() => parseArgv(['scan', 'one', 'two']), UsageError);
});

test('parseArgv rejects scan only flags on other commands', () => {
  assert.throws(() => parseArgv(['init', '--include', 'x']), UsageError);
  assert.throws(() => parseArgv(['rules', '--plugin', 'x.mjs']), UsageError);
});

test('parseArgv rejects an invalid fail-on value', () => {
  assert.throws(() => parseArgv(['scan', '--fail-on', 'loud']), UsageError);
});

test('parseArgv rejects a missing option value', () => {
  assert.throws(() => parseArgv(['scan', '--format']), UsageError);
});
