import test from 'node:test';
import assert from 'node:assert/strict';
import { RULE_COUNT } from '../src/rules/index.mjs';
import { REPORTER_NAMES, formatReport } from '../src/reporters/index.mjs';
import {
  SARIF_VERSION,
  artifactUri,
  fingerprintFor,
  formatSarif,
  toSarif,
} from '../src/reporters/sarif.mjs';
import { JSON_REPORT_VERSION, formatJson, toJson } from '../src/reporters/json.mjs';
import { formatTerminal, supportsColor } from '../src/reporters/terminal.mjs';
import { makeFinding, makeResult } from './helpers.mjs';

test('SARIF output declares the 2.1.0 schema', () => {
  const log = toSarif(makeResult());
  assert.equal(log.version, SARIF_VERSION);
  assert.equal(log.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(log.runs.length, 1);
});

test('the SARIF driver lists every rule sorted by id', () => {
  const driver = toSarif(makeResult(), { version: '9.9.9' }).runs[0].tool.driver;
  assert.equal(driver.name, 'sentinel-lint');
  assert.equal(driver.version, '9.9.9');
  assert.equal(driver.rules.length, RULE_COUNT);
  const ids = driver.rules.map((rule) => rule.id);
  assert.deepEqual(ids, [...ids].sort());
});

test('SARIF results map severity onto levels', () => {
  const result = makeResult({
    findings: [
      makeFinding({ ruleId: 'repo/hardcoded-token', severity: 'critical' }),
      makeFinding({ ruleId: 'actions/unpinned-action', severity: 'warning', line: 4 }),
      makeFinding({ ruleId: 'repo/dangerous-eval', severity: 'error' }),
    ],
  });
  const levels = toSarif(result).runs[0].results.map((entry) => entry.level);
  assert.deepEqual(levels, ['error', 'warning', 'error']);
});

test('SARIF results point at the matching rule index', () => {
  const log = toSarif(makeResult());
  const entry = log.runs[0].results[0];
  assert.equal(log.runs[0].tool.driver.rules[entry.ruleIndex].id, entry.ruleId);
});

test('SARIF regions carry 1 based positions', () => {
  const log = toSarif(makeResult({ findings: [makeFinding({ line: 7, column: 12 })] }));
  const region = log.runs[0].results[0].locations[0].physicalLocation.region;
  assert.equal(region.startLine, 7);
  assert.equal(region.startColumn, 12);
});

test('artifact URIs encode spaces and normalize separators', () => {
  assert.equal(artifactUri('src/my app.js'), 'src/my%20app.js');
  assert.equal(artifactUri('src\\app.js'), 'src/app.js');
});

test('SARIF results carry the encoded artifact URI', () => {
  const log = toSarif(makeResult({ findings: [makeFinding({ file: 'docs/my file.md' })] }));
  const location = log.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(location.artifactLocation.uri, 'docs/my%20file.md');
});

test('fingerprints are stable for identical findings', () => {
  const finding = makeFinding();
  assert.equal(fingerprintFor(finding), fingerprintFor({ ...finding }));
  assert.notEqual(fingerprintFor(finding), fingerprintFor({ ...finding, message: 'other' }));
});

test('fingerprints do not depend on the line number', () => {
  const first = makeFinding({ line: 1, column: 1 });
  const second = makeFinding({ line: 90, column: 4 });
  assert.equal(fingerprintFor(first), fingerprintFor(second));
});

test('formatSarif emits parseable text with a trailing newline', () => {
  const text = formatSarif(makeResult());
  assert.equal(text.endsWith('\n'), true);
  assert.equal(JSON.parse(text).version, '2.1.0');
});

test('diagnostics become invocation notifications', () => {
  const log = toSarif(
    makeResult({
      diagnostics: [{ code: 'rule-error', ruleId: 'repo/dangerous-eval', message: 'rule threw' }],
    }),
  );
  const notifications = log.runs[0].invocations[0].toolExecutionNotifications;
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].descriptor.id, 'rule-error');
  assert.equal(notifications[0].message.text, 'rule threw');
});

test('a scan with rule errors is marked unsuccessful', () => {
  const clean = toSarif(makeResult());
  const broken = toSarif(makeResult({ stats: { ruleErrors: 1 } }));
  assert.equal(clean.runs[0].invocations[0].executionSuccessful, true);
  assert.equal(broken.runs[0].invocations[0].executionSuccessful, false);
});

test('toJson reports a versioned shape', () => {
  const report = toJson(makeResult(), { version: '9.9.9' });
  assert.equal(report.reportVersion, JSON_REPORT_VERSION);
  assert.equal(report.tool.name, 'sentinel-lint');
  assert.equal(report.tool.version, '9.9.9');
  assert.equal(report.summary.findings, 1);
  assert.equal(report.findings[0].ruleId, 'repo/dangerous-eval');
  assert.equal(report.findings[0].severity, 'error');
  assert.ok(Array.isArray(report.rules));
});

test('formatJson emits parseable text with a trailing newline', () => {
  const text = formatJson(makeResult());
  assert.equal(text.endsWith('\n'), true);
  assert.equal(JSON.parse(text).summary.findings, 1);
});

test('the terminal reporter shows position, severity, rule and message', () => {
  const text = formatTerminal(makeResult());
  assert.match(text, /3:11/);
  assert.match(text, /ERROR/);
  assert.match(text, /repo\/dangerous-eval/);
  assert.match(text, /eval\(\) executes a string as code/);
});

test('the terminal reporter groups findings under one file header', () => {
  const text = formatTerminal(
    makeResult({
      findings: [makeFinding({ line: 1 }), makeFinding({ line: 5, column: 1 })],
    }),
  );
  assert.equal(text.split('src/app.js').length - 1, 1);
});

test('the terminal reporter prints the remediation line', () => {
  const text = formatTerminal(makeResult());
  assert.match(text, /fix: Replace it with a parser\./);
});

test('the terminal reporter quiet mode prints only the summary', () => {
  const text = formatTerminal(makeResult(), { quiet: true });
  assert.equal(text.includes('repo/dangerous-eval'), false);
  assert.equal(text.includes('sentinel-lint'), false);
  assert.match(text, /3 files scanned, 1 finding \(1 error\)/);
});

test('the terminal reporter truncates at maxFindings', () => {
  const findings = [makeFinding({ line: 1 }), makeFinding({ line: 2 }), makeFinding({ line: 3 })];
  const text = formatTerminal(makeResult({ findings }), { maxFindings: 1 });
  assert.match(text, /2 more findings not shown/);
  assert.equal(text.includes('1:11'), true);
});

test('the terminal reporter adds color only when asked', () => {
  const plain = formatTerminal(makeResult(), { color: false });
  const colored = formatTerminal(makeResult(), { color: true });
  assert.equal(plain.includes('\u001b['), false);
  assert.equal(colored.includes('\u001b['), true);
});

test('the terminal reporter summarises a clean scan', () => {
  const text = formatTerminal(makeResult({ findings: [] }));
  assert.match(text, /no findings/);
});

test('formatReport dispatches by name and rejects unknown names', () => {
  assert.deepEqual([...REPORTER_NAMES], ['terminal', 'json', 'sarif']);
  assert.equal(JSON.parse(formatReport('json', makeResult())).reportVersion, JSON_REPORT_VERSION);
  assert.equal(JSON.parse(formatReport('sarif', makeResult())).version, '2.1.0');
  assert.match(formatReport('terminal', makeResult()), /repo\/dangerous-eval/);
  assert.throws(() => formatReport('xml', makeResult()), TypeError);
});

test('supportsColor respects the terminal and the environment', () => {
  assert.equal(supportsColor({ isTTY: false }, {}), false);
  assert.equal(supportsColor({ isTTY: true }, {}), true);
  assert.equal(supportsColor({ isTTY: true }, { NO_COLOR: '1' }), false);
  assert.equal(supportsColor({ isTTY: false }, { FORCE_COLOR: '1' }), true);
});
