import test from 'node:test';
import assert from 'node:assert/strict';
import { buildIgnoreMap, hasIgnoreMarkers } from '../src/ignore.mjs';

test('ignore-next-line suppresses every rule on the next line', () => {
  const map = buildIgnoreMap('// sentinel-ignore-next-line\nconst value = eval(input);\n');
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(2, 'repo/hardcoded-token'), true);
  assert.equal(map.isSuppressed(3, 'repo/dangerous-eval'), false);
});

test('ignore-next-line with rule ids suppresses only those rules', () => {
  const map = buildIgnoreMap('// sentinel-ignore-next-line repo/dangerous-eval\nconst value = eval(input);\n');
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(2, 'repo/hardcoded-token'), false);
});

test('ignore-line suppresses the line it appears on', () => {
  const map = buildIgnoreMap('const value = eval(input); // sentinel-ignore-line repo/dangerous-eval\n');
  assert.equal(map.isSuppressed(1, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(1, 'repo/dangerous-html-sink'), false);
});

test('ignore-file with no ids suppresses the whole file', () => {
  const map = buildIgnoreMap('// sentinel-ignore-file\nconst value = eval(input);\n');
  assert.equal(map.isFileIgnored(), true);
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(99, 'anything/else'), true);
});

test('ignore-file with ids suppresses only those rules across the file', () => {
  const map = buildIgnoreMap('// sentinel-ignore-file repo/dangerous-eval\nconst value = eval(input);\n');
  assert.equal(map.isFileIgnored('repo/dangerous-eval'), true);
  assert.equal(map.isFileIgnored('repo/hardcoded-token'), false);
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(2, 'repo/hardcoded-token'), false);
});

test('free text after a double dash is treated as a reason', () => {
  const map = buildIgnoreMap('// sentinel-ignore-next-line -- reviewed in SEC-12\nconst value = eval(input);\n');
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), true);
});

test('rule ids mentioned inside a reason do not change the target', () => {
  const map = buildIgnoreMap('// sentinel-ignore-next-line repo/dangerous-eval -- see repo/other-rule\n');
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(2, 'repo/other-rule'), false);
});

test('several rule ids can share one marker', () => {
  const map = buildIgnoreMap('// sentinel-ignore-next-line repo/dangerous-eval, repo/dangerous-html-sink\n');
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(2, 'repo/dangerous-html-sink'), true);
  assert.equal(map.isSuppressed(2, 'repo/hardcoded-token'), false);
});

test('two markers on the same line both apply', () => {
  const map = buildIgnoreMap(
    'x // sentinel-ignore-line repo/dangerous-eval sentinel-ignore-line repo/dangerous-html-sink\n',
  );
  assert.equal(map.isSuppressed(1, 'repo/dangerous-eval'), true);
  assert.equal(map.isSuppressed(1, 'repo/dangerous-html-sink'), true);
});

test('a marker on the last line targets the line after the file', () => {
  const map = buildIgnoreMap('const x = 1;\n// sentinel-ignore-next-line');
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), false);
  assert.equal(map.isSuppressed(3, 'repo/dangerous-eval'), true);
});

test('hasIgnoreMarkers detects a marker and rejects plain text', () => {
  assert.equal(hasIgnoreMarkers('// sentinel-ignore-file\n'), true);
  assert.equal(hasIgnoreMarkers('const sentinel = 1;\n'), false);
});

test('unrelated comments do not suppress anything', () => {
  const map = buildIgnoreMap('// just a note\nconst x = 1;\n');
  assert.equal(map.isSuppressed(2, 'repo/dangerous-eval'), false);
  assert.equal(map.isFileIgnored(), false);
});
