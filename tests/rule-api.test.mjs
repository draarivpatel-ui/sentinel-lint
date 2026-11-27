import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  RuleDefinitionError,
  SEVERITIES,
  defineRule,
  meetsThreshold,
  severityRank,
} from '../src/rule-api.mjs';
import { BUILTIN_RULES, RULE_COUNT, loadBuiltinRules } from '../src/rules/index.mjs';
import { VERSION } from '../src/version.mjs';

const base = {
  id: 'demo/example-rule',
  title: 'Example rule',
  severity: 'warning',
  appliesTo: ['**/*.js'],
  check: () => [],
};

test('defineRule returns a frozen rule with the defaults applied', () => {
  const rule = defineRule(base);
  assert.equal(Object.isFrozen(rule), true);
  assert.equal(rule.category, 'demo');
  assert.equal(rule.scope, 'file');
  assert.equal(rule.cwe, null);
  assert.equal(rule.docsUrl, null);
  assert.equal(rule.fix, null);
  assert.equal(rule.match, null);
  assert.equal(rule.rationale, '');
});

test('defineRule keeps an explicit category', () => {
  const rule = defineRule({ ...base, category: 'supply-chain' });
  assert.equal(rule.category, 'supply-chain');
});

test('defineRule rejects non-object descriptors', () => {
  assert.throws(() => defineRule(null), RuleDefinitionError);
  assert.throws(() => defineRule([]), RuleDefinitionError);
  assert.throws(() => defineRule('rule'), RuleDefinitionError);
});

test('defineRule rejects an id without a category prefix', () => {
  assert.throws(() => defineRule({ ...base, id: 'plain-name' }), RuleDefinitionError);
});

test('defineRule rejects uppercase rule ids', () => {
  assert.throws(() => defineRule({ ...base, id: 'demo/Example' }), RuleDefinitionError);
});

test('defineRule rejects an empty title', () => {
  assert.throws(() => defineRule({ ...base, title: '   ' }), RuleDefinitionError);
});

test('defineRule rejects an unknown severity', () => {
  assert.throws(() => defineRule({ ...base, severity: 'severe' }), RuleDefinitionError);
});

test('defineRule rejects a missing check function', () => {
  assert.throws(() => defineRule({ ...base, check: undefined }), RuleDefinitionError);
});

test('defineRule rejects a malformed cwe', () => {
  assert.throws(() => defineRule({ ...base, cwe: 'CWE' }), RuleDefinitionError);
  assert.throws(() => defineRule({ ...base, cwe: 'CWE-xx' }), RuleDefinitionError);
});

test('defineRule accepts a well formed cwe', () => {
  const rule = defineRule({ ...base, cwe: 'CWE-798' });
  assert.equal(rule.cwe, 'CWE-798');
});

test('defineRule rejects an empty docsUrl', () => {
  assert.throws(() => defineRule({ ...base, docsUrl: '' }), RuleDefinitionError);
});

test('defineRule rejects a non-string fix', () => {
  assert.throws(() => defineRule({ ...base, fix: 42 }), RuleDefinitionError);
});

test('defineRule rejects an empty appliesTo array', () => {
  assert.throws(() => defineRule({ ...base, appliesTo: [] }), RuleDefinitionError);
});

test('defineRule rejects non-string globs', () => {
  assert.throws(() => defineRule({ ...base, appliesTo: ['ok', 7] }), RuleDefinitionError);
});

test('defineRule rejects an unknown scope', () => {
  assert.throws(() => defineRule({ ...base, scope: 'repository' }), RuleDefinitionError);
});

test('a file rule needs appliesTo or match', () => {
  assert.throws(() => defineRule({ ...base, appliesTo: undefined }), RuleDefinitionError);
  const matched = defineRule({ ...base, appliesTo: undefined, match: () => true });
  assert.equal(typeof matched.match, 'function');
});

test('a repo rule does not need appliesTo', () => {
  const rule = defineRule({ ...base, appliesTo: undefined, scope: 'repo' });
  assert.equal(rule.scope, 'repo');
  assert.deepEqual(rule.appliesTo, []);
});

test('defineRule copies appliesTo so caller mutation cannot change the rule', () => {
  const globs = ['**/*.js'];
  const rule = defineRule({ ...base, appliesTo: globs });
  globs.push('**/*.ts');
  assert.deepEqual([...rule.appliesTo], ['**/*.js']);
  assert.equal(Object.isFrozen(rule.appliesTo), true);
});

test('defineRule returns an already defined rule unchanged', () => {
  const rule = defineRule(base);
  assert.equal(defineRule(rule), rule);
});

test('defineRule accepts the null optional fields of a spread rule', () => {
  const rule = defineRule(base);
  const copy = defineRule({ ...rule, title: 'Renamed rule' });
  assert.equal(copy.title, 'Renamed rule');
  assert.equal(copy.cwe, null);
  assert.equal(copy.scope, 'file');
});

test('SEVERITIES is frozen and ordered from least to most severe', () => {
  assert.equal(Object.isFrozen(SEVERITIES), true);
  assert.deepEqual([...SEVERITIES], ['info', 'warning', 'error', 'critical']);
});

test('severityRank follows the declared order', () => {
  assert.equal(severityRank('info'), 0);
  assert.equal(severityRank('warning'), 1);
  assert.equal(severityRank('error'), 2);
  assert.equal(severityRank('critical'), 3);
});

test('severityRank returns -1 for unknown input', () => {
  assert.equal(severityRank('urgent'), -1);
  assert.equal(severityRank(''), -1);
});

test('meetsThreshold compares severities', () => {
  assert.equal(meetsThreshold('critical', 'warning'), true);
  assert.equal(meetsThreshold('warning', 'error'), false);
  assert.equal(meetsThreshold('error', 'error'), true);
});

test('meetsThreshold never matches off or an unknown threshold', () => {
  assert.equal(meetsThreshold('critical', 'off'), false);
  assert.equal(meetsThreshold('critical', 'none'), false);
  assert.equal(meetsThreshold('critical', 'severe'), false);
});

test('the built in pack ships at least twelve rules', () => {
  assert.ok(RULE_COUNT >= 12);
  assert.equal(RULE_COUNT, BUILTIN_RULES.length);
});

test('built in rule ids are unique', () => {
  const ids = BUILTIN_RULES.map((rule) => rule.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('every built in rule documents itself with a matching anchor', () => {
  for (const rule of BUILTIN_RULES) {
    const anchor = rule.id.replace(/[^A-Za-z0-9-]/g, '').toLowerCase();
    assert.equal(rule.docsUrl, `docs/rules.md#${anchor}`, rule.id);
  }
});

test('every built in rule carries a rationale, a fix and a valid severity', () => {
  for (const rule of BUILTIN_RULES) {
    assert.ok(rule.rationale.length > 20, `${rule.id} has a thin rationale`);
    assert.equal(typeof rule.fix, 'string', `${rule.id} has no fix text`);
    assert.ok(SEVERITIES.includes(rule.severity), rule.id);
    assert.ok(['file', 'repo'].includes(rule.scope), rule.id);
  }
});

test('loadBuiltinRules returns the same frozen pack', () => {
  const loaded = loadBuiltinRules();
  assert.equal(loaded, BUILTIN_RULES);
});

test('VERSION matches package.json', async () => {
  const raw = await readFile(new URL('../package.json', import.meta.url), 'utf8');
  assert.equal(JSON.parse(raw).version, VERSION);
});

test('the built in pack has no external runtime dependencies', async () => {
  const raw = await readFile(new URL('../package.json', import.meta.url), 'utf8');
  const manifest = JSON.parse(raw);
  assert.deepEqual(manifest.dependencies, {});
  assert.deepEqual(manifest.devDependencies, { 'fast-check': '4.10.3' });
});

test('defineRule defaults owasp metadata to a frozen empty array', () => {
  const rule = defineRule(base);
  assert.deepEqual(rule.owasp, []);
  assert.equal(Object.isFrozen(rule.owasp), true);
});

test('defineRule accepts OWASP taxonomy entries', () => {
  const rule = defineRule({ ...base, owasp: ['A03:2021-Injection', 'LLM01:2023 Prompt Injection'] });
  assert.deepEqual(rule.owasp, ['A03:2021-Injection', 'LLM01:2023 Prompt Injection']);
});

test('defineRule rejects non-array owasp metadata', () => {
  assert.throws(() => defineRule({ ...base, owasp: 'A03:2021-Injection' }), RuleDefinitionError);
});

test('defineRule rejects empty owasp entries', () => {
  assert.throws(() => defineRule({ ...base, owasp: [''] }), RuleDefinitionError);
  assert.throws(() => defineRule({ ...base, owasp: [42] }), RuleDefinitionError);
});

test('defineRule copies owasp entries so caller mutation cannot change the rule', () => {
  const owasp = ['A05:2021-Security Misconfiguration'];
  const rule = defineRule({ ...base, owasp });
  owasp.push('A03:2021-Injection');
  assert.deepEqual(rule.owasp, ['A05:2021-Security Misconfiguration']);
  assert.equal(Object.isFrozen(rule.owasp), true);
});
