import test from 'node:test';
import assert from 'node:assert/strict';
import { BUILTIN_RULES } from '../src/rules/index.mjs';
import { toJson } from '../src/reporters/json.mjs';
import { toSarif } from '../src/reporters/sarif.mjs';
import { makeResult } from './helpers.mjs';

const NEW_RULE_IDS = [
  'agent/bidi-unicode-override',
  'agent/invisible-zero-width-unicode',
  'agent/shell-override-instruction',
  'agent/exfiltration-instruction',
  'actions/missing-permissions',
  'actions/env-file-injection',
  'container/missing-non-root-user',
  'container/explicit-root-user',
  'container/curl-pipe-shell',
  'container/remote-add',
  'container/privileged-mode',
  'container/host-network',
  'container/docker-socket-mount',
];

function driverRule(ruleId) {
  return toSarif(makeResult()).runs[0].tool.driver.rules.find((rule) => rule.id === ruleId);
}

test('every v0.3 security rule is present in the built in pack', () => {
  const ids = new Set(BUILTIN_RULES.map((rule) => rule.id));
  for (const ruleId of NEW_RULE_IDS) assert.ok(ids.has(ruleId), ruleId);
});

test('every v0.3 security rule carries CWE metadata', () => {
  for (const ruleId of NEW_RULE_IDS) {
    const rule = BUILTIN_RULES.find((entry) => entry.id === ruleId);
    assert.match(rule.cwe, /^CWE-\d+$/, ruleId);
  }
});

test('every v0.3 security rule carries OWASP metadata', () => {
  for (const ruleId of NEW_RULE_IDS) {
    const rule = BUILTIN_RULES.find((entry) => entry.id === ruleId);
    assert.ok(Array.isArray(rule.owasp), ruleId);
    assert.ok(rule.owasp.length > 0, ruleId);
  }
});

test('every v0.3 security rule carries remediation text', () => {
  for (const ruleId of NEW_RULE_IDS) {
    const rule = BUILTIN_RULES.find((entry) => entry.id === ruleId);
    assert.ok(rule.fix.length > 30, ruleId);
    assert.ok(rule.rationale.length > 60, ruleId);
  }
});

test('SARIF driver rules carry CWE tags', () => {
  const rule = driverRule('actions/env-file-injection');
  assert.ok(rule.properties.tags.includes('cwe-94'));
  assert.equal(rule.properties.cwe, 'CWE-94');
});

test('SARIF driver rules carry normalized OWASP tags', () => {
  const rule = driverRule('agent/bidi-unicode-override');
  assert.ok(rule.properties.tags.includes('owasp-llm01-2023-prompt-injection'));
});

test('SARIF driver rules preserve exact OWASP taxonomy values', () => {
  const rule = driverRule('container/privileged-mode');
  assert.deepEqual(rule.properties.owasp, ['A05:2021-Security Misconfiguration']);
});

test('SARIF rule help contains rationale and remediation', () => {
  const rule = driverRule('container/docker-socket-mount');
  assert.match(rule.help.text, /Docker socket controls the host daemon/);
  assert.match(rule.help.text, /Remediation: Remove the socket mount/);
});

test('SARIF driver rules keep high precision and severity metadata', () => {
  const rule = driverRule('agent/exfiltration-instruction');
  assert.equal(rule.properties.precision, 'high');
  assert.equal(rule.properties['security-severity'], '9.0');
  assert.equal(rule.defaultConfiguration.level, 'error');
});

test('SARIF tags include the security and category taxonomies', () => {
  const rule = driverRule('container/host-network');
  assert.ok(rule.properties.tags.includes('security'));
  assert.ok(rule.properties.tags.includes('container'));
});

test('SARIF driver metadata points at the matching rule documentation anchor', () => {
  const rule = driverRule('actions/missing-permissions');
  assert.equal(rule.helpUri, 'docs/rules.md#actionsmissing-permissions');
});

test('JSON rule metadata exposes OWASP taxonomy values', () => {
  const report = toJson(makeResult());
  const rule = report.rules.find((entry) => entry.id === 'container/remote-add');
  assert.deepEqual(rule.owasp, ['A08:2021-Software and Data Integrity Failures']);
});

test('rules without OWASP metadata serialize an empty OWASP list in JSON', () => {
  const report = toJson(makeResult());
  const rule = report.rules.find((entry) => entry.id === 'repo/dangerous-eval');
  assert.deepEqual(rule.owasp, []);
});

test('all CWE bearing SARIF rules use machine readable cwe tags', () => {
  const rules = toSarif(makeResult()).runs[0].tool.driver.rules;
  for (const rule of rules.filter((entry) => entry.properties.cwe)) {
    const expected = `cwe-${rule.properties.cwe.slice(4).toLowerCase()}`;
    assert.ok(rule.properties.tags.includes(expected), `${rule.id} missing ${expected}`);
  }
});
