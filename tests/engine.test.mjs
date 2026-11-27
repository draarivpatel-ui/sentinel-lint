import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveRules, scan } from '../src/engine.mjs';
import { defineRule } from '../src/rule-api.mjs';
import { loadBuiltinRules } from '../src/rules/index.mjs';
import { CLEAN_TREE, makeTree, scanTree } from './helpers.mjs';

function fileRule(id, check, extra = {}) {
  return defineRule({
    id,
    title: `Rule ${id}`,
    severity: 'warning',
    appliesTo: ['**/*.txt'],
    check,
    ...extra,
  });
}

test('a benign repository scans clean', async (t) => {
  const root = await makeTree(t, CLEAN_TREE);
  const result = await scan({ root });
  assert.deepEqual(result.findings, []);
  assert.equal(result.summary.findings, 0);
  assert.ok(result.summary.filesScanned >= 5);
});

test('two scans of the same tree produce identical findings', async (t) => {
  const treeData = {
    'a.js': 'eval(input);\n',
    'b.js': 'document.body.innerHTML = value;\n',
  };
  const first = await scanTree(t, treeData);
  const second = await scanTree(t, treeData);
  assert.equal(JSON.stringify(first.findings), JSON.stringify(second.findings));
});

test('findings sort by file, line, column and rule id', async (t) => {
  const result = await scanTree(t, {
    'SECURITY.md': '# Security\n',
    'b.js': 'eval(second);\n',
    'a.js': 'const x = 1;\neval(first);\ndocument.body.innerHTML = x;\n',
  });
  const paths = result.findings.map((finding) => `${finding.file}:${finding.line}`);
  assert.deepEqual(paths, ['a.js:2', 'a.js:3', 'b.js:1']);
});

test('a rule can return findings as an array', async (t) => {
  const rule = fileRule('demo/returns-array', () => [{ line: 1, column: 2, message: 'returned finding' }]);
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].message, 'returned finding');
  assert.equal(result.findings[0].column, 2);
});

test('a rule can report findings through ctx.report with positional arguments', async (t) => {
  const rule = fileRule('demo/positional-report', (ctx) => {
    ctx.report(1, 3, 'positional finding');
  });
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].message, 'positional finding');
  assert.equal(result.findings[0].column, 3);
});

test('a rule can report an object through ctx.report', async (t) => {
  const rule = fileRule('demo/object-report', (ctx) => {
    ctx.report({ line: 1, column: 1, message: 'object finding' });
  });
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings[0].message, 'object finding');
});

test('a missing message falls back to the rule title', async (t) => {
  const rule = fileRule('demo/title-fallback', () => [{ line: 1, column: 1 }]);
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings[0].message, 'Rule demo/title-fallback');
});

test('a rule that throws is isolated and reported', async (t) => {
  const boom = fileRule('demo/boom', () => {
    throw new Error('kaboom');
  });
  const ok = fileRule('demo/ok', () => [{ line: 1, column: 1, message: 'still here' }]);
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [boom, ok] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.stats.ruleErrors, 1);
  assert.ok(result.diagnostics.some((entry) => entry.code === 'rule-error' && /kaboom/.test(entry.message)));
});

test('a rule returning a non-array is reported', async (t) => {
  const rule = fileRule('demo/bad-return', () => ({ line: 1 }));
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 0);
  assert.ok(result.diagnostics.some((entry) => entry.code === 'invalid-finding'));
});

test('a non-object finding is reported and dropped', async (t) => {
  const rule = fileRule('demo/null-finding', () => [null]);
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 0);
  assert.equal(result.stats.ruleErrors, 1);
});

test('a line beyond the end of the file is reported and dropped', async (t) => {
  const rule = fileRule('demo/far-line', () => [{ line: 99, column: 1, message: 'far away' }]);
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 0);
  assert.ok(result.diagnostics.some((entry) => /only has \d+ lines/.test(entry.message)));
});

test('an out of range column is clamped to the line end', async (t) => {
  const rule = fileRule('demo/wide-column', () => [{ line: 1, column: 500, message: 'wide' }]);
  const result = await scanTree(t, { 'note.txt': 'hi\n' }, { rules: [rule] });
  assert.equal(result.findings[0].column, 3);
});

test('duplicate findings from one rule are reported once', async (t) => {
  const rule = fileRule('demo/duplicate', () => [
    { line: 1, column: 1, message: 'same' },
    { line: 1, column: 1, message: 'same' },
  ]);
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 1);
});

test('appliesTo globs limit the files a rule sees', async (t) => {
  const rule = fileRule('demo/python-only', () => [{ line: 1, column: 1, message: 'python' }], {
    appliesTo: ['**/*.py'],
  });
  const result = await scanTree(t, { 'note.txt': 'hello\n', 'app.py': 'print(1)\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].file, 'app.py');
});

test('match() limits the files a rule sees', async (t) => {
  const rule = defineRule({
    id: 'demo/match-filter',
    title: 'Match filter',
    severity: 'info',
    appliesTo: ['**/*.txt'],
    match: (file) => file.text.includes('MAGIC'),
    check: () => [{ line: 1, column: 1, message: 'matched' }],
  });
  const result = await scanTree(t, { 'yes.txt': 'MAGIC\n', 'no.txt': 'plain\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].file, 'yes.txt');
});

test('a throwing match() is reported and the file is skipped', async (t) => {
  const rule = defineRule({
    id: 'demo/match-throws',
    title: 'Match throws',
    severity: 'info',
    appliesTo: ['**/*.txt'],
    match: () => {
      throw new Error('bad match');
    },
    check: () => [{ line: 1, column: 1, message: 'never' }],
  });
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 0);
  assert.ok(result.diagnostics.some((entry) => entry.code === 'rule-match-error'));
});

test('a repo rule receives every path and can read files', async (t) => {
  let observed = null;
  const rule = defineRule({
    id: 'demo/repo-inspect',
    title: 'Repo inspect',
    severity: 'info',
    scope: 'repo',
    check(ctx) {
      observed = {
        paths: [...ctx.paths],
        note: ctx.read('note.txt'),
        escaped: ctx.read('../outside.txt'),
        absolute: ctx.read('/etc/hosts'),
      };
      return [];
    },
  });
  await scanTree(t, { 'note.txt': 'hello\n', 'src/app.js': 'const a = 1;\n' }, { rules: [rule] });
  assert.deepEqual(observed.paths, ['note.txt', 'src/app.js']);
  assert.equal(observed.note, 'hello\n');
  assert.equal(observed.escaped, null);
  assert.equal(observed.absolute, null);
});

test('a file rule receives read only repository context', async (t) => {
  let observed = null;
  const rule = fileRule('demo/file-inspect', (ctx) => {
    observed = {
      files: ctx.files.map((file) => file.path),
      paths: [...ctx.paths],
      sibling: ctx.read('data/values.txt'),
      escaped: ctx.read('../outside.txt'),
    };
    return [];
  });
  await scanTree(t, { 'note.txt': 'hello\n', 'data/values.txt': 'one\n' }, { rules: [rule] });
  assert.deepEqual(observed.files, ['data/values.txt', 'note.txt']);
  assert.deepEqual(observed.paths, ['data/values.txt', 'note.txt']);
  assert.equal(observed.sibling, 'one\n');
  assert.equal(observed.escaped, null);
});

test('a repo rule can report a finding without a file', async (t) => {
  const rule = defineRule({
    id: 'demo/repo-finding',
    title: 'Repo finding',
    severity: 'warning',
    scope: 'repo',
    check: () => [{ file: null, line: 1, column: 1, message: 'repository level' }],
  });
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].file, null);
  assert.equal(result.diagnostics.length, 0);
});

test('a repo rule reporting an unsafe path is reported', async (t) => {
  const rule = defineRule({
    id: 'demo/repo-unsafe-file',
    title: 'Unsafe file',
    severity: 'warning',
    scope: 'repo',
    check: () => [{ file: '../escape.txt', line: 1, column: 1, message: 'outside' }],
  });
  const result = await scanTree(t, { 'note.txt': 'hello\n' }, { rules: [rule] });
  assert.ok(result.diagnostics.some((entry) => entry.code === 'invalid-finding-file'));
});

test('inline suppression removes a finding and counts it', async (t) => {
  const result = await scanTree(t, {
    'src/app.js': '// sentinel-ignore-next-line repo/dangerous-eval\neval(input);\n',
  });
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'repo/dangerous-eval').length, 0);
  assert.equal(result.summary.suppressed, 1);
});

test('config severity overrides change the reported severity', async (t) => {
  const result = await scanTree(
    t,
    { 'src/app.js': 'eval(input);\n' },
    { config: { rules: { 'repo/dangerous-eval': 'info' } } },
  );
  const finding = result.findings.find((entry) => entry.ruleId === 'repo/dangerous-eval');
  assert.equal(finding.severity, 'info');
});

test('config can turn a rule off', async (t) => {
  const result = await scanTree(
    t,
    { 'src/app.js': 'eval(input);\n' },
    { config: { rules: { 'repo/dangerous-eval': 'off' } } },
  );
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'repo/dangerous-eval').length, 0);
  assert.equal(result.rules.some((rule) => rule.id === 'repo/dangerous-eval'), false);
});

test('config with an unknown rule id produces a diagnostic', async (t) => {
  const result = await scanTree(
    t,
    { 'note.txt': 'hello\n' },
    { config: { rules: { 'demo/not-real': 'error' } } },
  );
  assert.ok(result.diagnostics.some((entry) => entry.code === 'unknown-rule'));
});

test('include globs limit the scanned file set', async (t) => {
  const result = await scanTree(
    t,
    { 'README.md': '# demo\n', 'src/app.js': 'const a = 1;\n' },
    { config: { include: ['**/*.md'] } },
  );
  assert.deepEqual(
    result.files.map((file) => file.path),
    ['README.md'],
  );
});

test('exclude globs remove directories', async (t) => {
  const result = await scanTree(
    t,
    { 'keep.txt': 'a\n', 'src/app.js': 'const a = 1;\n' },
    { config: { exclude: ['src/**'] } },
  );
  assert.deepEqual(
    result.files.map((file) => file.path),
    ['keep.txt'],
  );
});

test('summary counts findings by severity', async (t) => {
  const result = await scanTree(t, {
    'SECURITY.md': '# Security\n',
    'src/app.js': 'eval(input);\ndocument.write(x);\n',
  });
  const { bySeverity } = result.summary;
  assert.equal(bySeverity.error, 2);
  assert.equal(bySeverity.critical, 0);
  assert.equal(result.summary.findings, 2);
});

test('resolveRules sorts by id and applies overrides', () => {
  const rules = loadBuiltinRules();
  const { rules: resolved, diagnostics } = resolveRules(rules, {
    rules: { 'repo/dangerous-eval': 'critical', 'actions/unpinned-action': 'off' },
  });
  assert.equal(diagnostics.length, 0);
  const ids = resolved.map((rule) => rule.id);
  assert.deepEqual(ids, [...ids].sort());
  assert.equal(ids.includes('actions/unpinned-action'), false);
  assert.equal(resolved.find((rule) => rule.id === 'repo/dangerous-eval').severity, 'critical');
});
