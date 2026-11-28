import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  CONFIG_FILE,
  ConfigError,
  DEFAULT_CONFIG,
  loadConfig,
  validateConfig,
} from '../src/config.mjs';
import { makeTempDir, makeTree } from './helpers.mjs';

test('the default config is frozen and documented', () => {
  assert.equal(Object.isFrozen(DEFAULT_CONFIG), true);
  assert.equal(DEFAULT_CONFIG.failOn, 'warning');
  assert.equal(DEFAULT_CONFIG.maxFileSize, 1048576);
  assert.equal(DEFAULT_CONFIG.maxFiles, 20000);
  assert.equal(CONFIG_FILE, '.sentinelrc.json');
});

test('validateConfig applies defaults for an empty object', () => {
  const { config, warnings } = validateConfig({});
  assert.deepEqual(warnings, []);
  assert.equal(config.failOn, 'warning');
  assert.deepEqual(config.include, []);
  assert.deepEqual(config.exclude, []);
  assert.deepEqual(config.rules, {});
  assert.deepEqual(config.plugins, []);
});

test('validateConfig returns defaults for undefined', () => {
  const { config } = validateConfig(undefined);
  assert.equal(config.failOn, 'warning');
});

test('validateConfig accepts a severity for failOn', () => {
  assert.equal(validateConfig({ failOn: 'critical' }).config.failOn, 'critical');
  assert.equal(validateConfig({ failOn: 'off' }).config.failOn, 'off');
});

test('validateConfig rejects an unknown failOn value', () => {
  assert.throws(() => validateConfig({ failOn: 'loud' }), ConfigError);
});

test('validateConfig warns about unknown keys but keeps going', () => {
  const { config, warnings } = validateConfig({ failOn: 'error', extra: true });
  assert.equal(config.failOn, 'error');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /unknown configuration key "extra"/);
});

test('validateConfig rejects a non-object document', () => {
  assert.throws(() => validateConfig([]), ConfigError);
  assert.throws(() => validateConfig('text'), ConfigError);
});

test('validateConfig rejects invalid globs', () => {
  assert.throws(() => validateConfig({ include: ['src/{a,b'] }), ConfigError);
  assert.throws(() => validateConfig({ exclude: [42] }), ConfigError);
});

test('validateConfig rejects non-string rule overrides', () => {
  assert.throws(() => validateConfig({ rules: { 'repo/dangerous-eval': 3 } }), ConfigError);
});

test('validateConfig rejects an unknown severity override', () => {
  assert.throws(() => validateConfig({ rules: { 'repo/dangerous-eval': 'loud' } }), ConfigError);
});

test('validateConfig keeps off and severity overrides', () => {
  const { config } = validateConfig({
    rules: { 'repo/dangerous-eval': 'off', 'actions/unpinned-action': 'error' },
  });
  assert.deepEqual(config.rules, {
    'repo/dangerous-eval': 'off',
    'actions/unpinned-action': 'error',
  });
});

test('validateConfig rejects a non-array plugins value', () => {
  assert.throws(() => validateConfig({ plugins: './rules.mjs' }), ConfigError);
  assert.throws(() => validateConfig({ plugins: [7] }), ConfigError);
});

test('validateConfig rejects non-positive limits', () => {
  assert.throws(() => validateConfig({ maxFiles: 0 }), ConfigError);
  assert.throws(() => validateConfig({ maxFileSize: 1.5 }), ConfigError);
});

test('loadConfig returns defaults when no config file exists', async (t) => {
  const root = await makeTempDir(t);
  const result = await loadConfig({ root, cwd: root });
  assert.equal(result.path, null);
  assert.equal(result.config.failOn, 'warning');
  assert.deepEqual(result.warnings, []);
});

test('loadConfig discovers .sentinelrc.json at the scan root', async (t) => {
  const root = await makeTree(t, {
    [CONFIG_FILE]: '{\n  "failOn": "error",\n  "rules": { "repo/dangerous-eval": "off" }\n}\n',
  });
  const result = await loadConfig({ root, cwd: root });
  assert.equal(result.path, path.join(root, CONFIG_FILE));
  assert.equal(result.config.failOn, 'error');
  assert.equal(result.config.rules['repo/dangerous-eval'], 'off');
});

test('loadConfig accepts JSONC comments in the config file', async (t) => {
  const root = await makeTree(t, {
    [CONFIG_FILE]: '{\n  // keep comments working\n  "failOn": "critical",\n}\n',
  });
  const result = await loadConfig({ root, cwd: root });
  assert.equal(result.config.failOn, 'critical');
});

test('loadConfig rejects an explicit config that does not exist', async (t) => {
  const root = await makeTempDir(t);
  await assert.rejects(() => loadConfig({ root, cwd: root, configPath: 'missing.json' }), ConfigError);
});

test('loadConfig rejects invalid JSON with a helpful message', async (t) => {
  const root = await makeTempDir(t);
  await writeFile(path.join(root, CONFIG_FILE), '{ "failOn": }', 'utf8');
  await assert.rejects(() => loadConfig({ root, cwd: root }), (error) => {
    assert.ok(error instanceof ConfigError);
    assert.match(error.message, /invalid JSON in config file/);
    return true;
  });
});

test('loadConfig keeps valid keys and reports an unknown one', async (t) => {
  const root = await makeTree(t, { [CONFIG_FILE]: '{"exclude": ["src/**"], "unknown": 1}\n' });
  const result = await loadConfig({ root, cwd: root });
  assert.deepEqual(result.config.exclude, ['src/**']);
  assert.equal(result.warnings.length, 1);
});

test('a __proto__ key cannot pollute the prototype', () => {
  const raw = JSON.parse('{"__proto__": {"polluted": true}, "failOn": "warning"}');
  const { config, warnings } = validateConfig(raw);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.getPrototypeOf(config), Object.prototype);
  assert.equal(warnings.length, 1);
});

test('rules cannot be assigned through __proto__', () => {
  const raw = JSON.parse('{"rules": {"__proto__": {"polluted": true}}}');
  assert.throws(() => validateConfig(raw), ConfigError);
  assert.equal({}.polluted, undefined);
});

test('validateConfig defaults trustedActions to an empty list', () => {
  assert.deepEqual(validateConfig({}).config.trustedActions, []);
  assert.deepEqual(validateConfig(undefined).config.trustedActions, []);
});

test('validateConfig accepts owner and repository trusted action prefixes', () => {
  const { config, warnings } = validateConfig({ trustedActions: ['example-org', 'example-org/example-action'] });
  assert.deepEqual(config.trustedActions, ['example-org', 'example-org/example-action']);
  assert.deepEqual(warnings, []);
});

test('validateConfig rejects a non-array trustedActions value', () => {
  assert.throws(() => validateConfig({ trustedActions: 'example-org' }), ConfigError);
});

test('validateConfig rejects action refs in trustedActions', () => {
  assert.throws(() => validateConfig({ trustedActions: ['example-org/example-action@v1'] }), ConfigError);
});

test('validateConfig rejects empty trustedActions entries', () => {
  assert.throws(() => validateConfig({ trustedActions: [''] }), ConfigError);
  assert.throws(() => validateConfig({ trustedActions: [42] }), ConfigError);
});

test('loadConfig reads trustedActions from the scan root config', async (t) => {
  const root = await makeTree(t, {
    [CONFIG_FILE]: '{"trustedActions": ["example-org/example-action"]}\n',
  });
  const result = await loadConfig({ root, cwd: root });
  assert.deepEqual(result.config.trustedActions, ['example-org/example-action']);
});

test('loadConfig returns empty trustedActions when no config file exists', async (t) => {
  const root = await makeTempDir(t);
  const result = await loadConfig({ root, cwd: root });
  assert.deepEqual(result.config.trustedActions, []);
});

test('validateConfig defaults trustedNonRootImages to an empty list', () => {
  assert.deepEqual(validateConfig({}).config.trustedNonRootImages, []);
  assert.deepEqual(validateConfig(undefined).config.trustedNonRootImages, []);
});

test('validateConfig accepts trusted non-root image repository prefixes', () => {
  const { config, warnings } = validateConfig({
    trustedNonRootImages: ['images.example.com/team/', 'localhost:5000/team/'],
  });
  assert.deepEqual(config.trustedNonRootImages, ['images.example.com/team/', 'localhost:5000/team/']);
  assert.deepEqual(warnings, []);
});

test('validateConfig rejects malformed trustedNonRootImages values', () => {
  assert.throws(() => validateConfig({ trustedNonRootImages: 'images.example.com/team/' }), ConfigError);
  assert.throws(() => validateConfig({ trustedNonRootImages: [''] }), ConfigError);
  assert.throws(() => validateConfig({ trustedNonRootImages: [42] }), ConfigError);
});

test('validateConfig rejects tags digests and whitespace in trustedNonRootImages', () => {
  assert.throws(() => validateConfig({ trustedNonRootImages: ['images.example.com/team/runtime:nonroot'] }), ConfigError);
  assert.throws(() => validateConfig({ trustedNonRootImages: ['images.example.com/team/runtime@sha256:abc'] }), ConfigError);
  assert.throws(() => validateConfig({ trustedNonRootImages: ['images.example.com/team runtime'] }), ConfigError);
});

test('validateConfig rejects uppercase malformed or escaping trustedNonRootImages prefixes', () => {
  assert.throws(() => validateConfig({ trustedNonRootImages: ['Images.example.com/team/'] }), ConfigError);
  assert.throws(() => validateConfig({ trustedNonRootImages: ['images.example.com/team/../evil'] }), ConfigError);
  assert.throws(() => validateConfig({ trustedNonRootImages: ['images.example.com//team/'] }), ConfigError);
});

test('validateConfig accepts and normalizes trusted artifact-only scratch stages', () => {
  const { config, warnings } = validateConfig({ trustedArtifactOnlyScratchStages: ['Artifacts', 'export-bin'] });
  assert.deepEqual(config.trustedArtifactOnlyScratchStages, ['artifacts', 'export-bin']);
  assert.deepEqual(warnings, []);
});

test('validateConfig rejects malformed trusted artifact-only scratch stages', () => {
  assert.throws(() => validateConfig({ trustedArtifactOnlyScratchStages: 'artifacts' }), ConfigError);
  assert.throws(() => validateConfig({ trustedArtifactOnlyScratchStages: ['bad/name'] }), ConfigError);
  assert.throws(() => validateConfig({ trustedArtifactOnlyScratchStages: [42] }), ConfigError);
});

test('loadConfig reads trustedNonRootImages from the scan root config', async (t) => {
  const root = await makeTree(t, {
    [CONFIG_FILE]: '{"trustedNonRootImages": ["images.example.com/team/"]}\n',
  });
  const result = await loadConfig({ root, cwd: root });
  assert.deepEqual(result.config.trustedNonRootImages, ['images.example.com/team/']);
});

test('validateConfig defaults trustedActionsLockEnforcement to false', () => {
  assert.equal(validateConfig({}).config.trustedActionsLockEnforcement, false);
  assert.equal(validateConfig(undefined).config.trustedActionsLockEnforcement, false);
});

test('validateConfig accepts an explicit actions lock enforcement policy', () => {
  assert.equal(validateConfig({ trustedActionsLockEnforcement: true }).config.trustedActionsLockEnforcement, true);
  assert.equal(validateConfig({ trustedActionsLockEnforcement: false }).config.trustedActionsLockEnforcement, false);
});

test('validateConfig rejects a non-boolean actions lock enforcement policy', () => {
  assert.throws(() => validateConfig({ trustedActionsLockEnforcement: 'true' }), ConfigError);
  assert.throws(() => validateConfig({ trustedActionsLockEnforcement: 1 }), ConfigError);
});

test('loadConfig ignores lock enforcement asserted inside the scan root', async (t) => {
  const root = await makeTree(t, {
    [CONFIG_FILE]: '{"trustedActionsLockEnforcement": true}\n',
  });
  const result = await loadConfig({ root, cwd: root });
  assert.equal(result.config.trustedActionsLockEnforcement, false);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0], /inside the scan root/);
});

test('loadConfig honors lock enforcement from an explicit config outside the scan root', async (t) => {
  const root = await makeTempDir(t);
  const outside = await makeTempDir(t);
  const policy = path.join(outside, 'policy.json');
  await writeFile(policy, '{"trustedActionsLockEnforcement": true}\n', 'utf8');
  const result = await loadConfig({ root, cwd: root, configPath: policy });
  assert.equal(result.config.trustedActionsLockEnforcement, true);
  assert.deepEqual(result.warnings, []);
});

test('loadConfig honors lock enforcement from an operator cwd config outside the scan root', async (t) => {
  const root = await makeTempDir(t);
  const outside = await makeTree(t, {
    [CONFIG_FILE]: '{"trustedActionsLockEnforcement": true}\n',
  });
  const result = await loadConfig({ root, cwd: outside });
  assert.equal(result.config.trustedActionsLockEnforcement, true);
  assert.deepEqual(result.warnings, []);
});
