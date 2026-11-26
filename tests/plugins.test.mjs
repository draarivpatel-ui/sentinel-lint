import test from 'node:test';
import assert from 'node:assert/strict';
import { loadPluginRules, PluginError } from '../src/plugins.mjs';
import { makeTempDir, writeTree } from './helpers.mjs';

const API_URL = new URL('../src/rule-api.mjs', import.meta.url).href;

function pluginSource(body) {
  return `import { defineRule } from ${JSON.stringify(API_URL)};\n${body}\n`;
}

function ruleLiteral(id) {
  return `{
    id: ${JSON.stringify(id)},
    title: 'Plugin rule',
    severity: 'warning',
    appliesTo: ['**/*.js'],
    check: () => [{ line: 1, column: 1, message: 'plugin finding' }],
  }`;
}

test('a plugin can export one rule as the default export', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, { 'rule.mjs': pluginSource(`export default defineRule(${ruleLiteral('plugin/one')});`) });
  const rules = await loadPluginRules(['rule.mjs'], root);
  assert.deepEqual(
    rules.map((rule) => rule.id),
    ['plugin/one'],
  );
});

test('a plugin can export an array as the default export', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, {
    'rule.mjs': pluginSource(
      `export default [defineRule(${ruleLiteral('plugin/one')}), defineRule(${ruleLiteral('plugin/two')})];`,
    ),
  });
  const rules = await loadPluginRules(['rule.mjs'], root);
  assert.equal(rules.length, 2);
});

test('a plugin can export a named rules array', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, { 'rule.mjs': pluginSource(`export const rules = [defineRule(${ruleLiteral('plugin/named')})];`) });
  const rules = await loadPluginRules(['rule.mjs'], root);
  assert.equal(rules[0].id, 'plugin/named');
});

test('a missing plugin file is reported', async (t) => {
  const root = await makeTempDir(t);
  await assert.rejects(() => loadPluginRules(['nope.mjs'], root), PluginError);
});

test('a plugin with no rules is reported', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, { 'empty.mjs': 'export const version = 1;\n' });
  await assert.rejects(() => loadPluginRules(['empty.mjs'], root), /exported no rules/);
});

test('a plugin with an invalid rule is reported', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, { 'bad.mjs': 'export default { id: "nope" };\n' });
  await assert.rejects(() => loadPluginRules(['bad.mjs'], root), /invalid rule/);
});

test('a plugin with a syntax error is reported', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, { 'broken.mjs': 'export default (\n' });
  await assert.rejects(() => loadPluginRules(['broken.mjs'], root), /could not import plugin/);
});

test('a directory cannot be loaded as a plugin', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, { 'folder/rule.mjs': 'export const x = 1;\n' });
  await assert.rejects(() => loadPluginRules(['folder'], root), /not a file/);
});

test('a config plugin cannot escape the config directory', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, {
    'outside.mjs': pluginSource(`export default defineRule(${ruleLiteral('plugin/out')});`),
    'config/keep.txt': '',
  });
  await assert.rejects(
    () => loadPluginRules(['../outside.mjs'], `${root}/config`),
    /escapes the config directory/,
  );
});

test('an explicitly allowed plugin may sit outside the config directory', async (t) => {
  const root = await makeTempDir(t);
  await writeTree(root, {
    'outside.mjs': pluginSource(`export default defineRule(${ruleLiteral('plugin/out')});`),
    'config/keep.txt': '',
  });
  const rules = await loadPluginRules(['../outside.mjs'], `${root}/config`, {
    allowOutsideConfigDir: true,
  });
  assert.deepEqual(
    rules.map((rule) => rule.id),
    ['plugin/out'],
  );
});
