import test from 'node:test';
import assert from 'node:assert/strict';
import { assertValidGlob, globToRegExp, matchesAnyGlob, matchesGlob } from '../src/globs.mjs';

test('double star matches files at any depth', () => {
  assert.equal(matchesGlob('src/app.js', '**/*.js'), true);
  assert.equal(matchesGlob('app.js', '**/*.js'), true);
  assert.equal(matchesGlob('a/b/c/d.js', '**/*.js'), true);
});

test('double star respects the extension', () => {
  assert.equal(matchesGlob('src/app.ts', '**/*.js'), false);
});

test('a pattern without a slash matches at any depth', () => {
  assert.equal(matchesGlob('deep/nested/app.js', '*.js'), true);
  assert.equal(matchesGlob('app.js', '*.js'), true);
});

test('workflow globs are anchored to the directory', () => {
  assert.equal(matchesGlob('.github/workflows/ci.yml', '.github/workflows/*.yml'), true);
  assert.equal(matchesGlob('.github/workflows/nested/ci.yml', '.github/workflows/*.yml'), false);
});

test('question mark matches exactly one character', () => {
  assert.equal(matchesGlob('a.js', '?.js'), true);
  assert.equal(matchesGlob('ab.js', '?.js'), false);
});

test('brace alternation matches any branch', () => {
  assert.equal(matchesGlob('x.ts', '*.{js,ts}'), true);
  assert.equal(matchesGlob('x.js', '*.{js,ts}'), true);
  assert.equal(matchesGlob('x.css', '*.{js,ts}'), false);
});

test('character classes match a range', () => {
  assert.equal(matchesGlob('a1.js', 'a[0-9].js'), true);
  assert.equal(matchesGlob('ax.js', 'a[0-9].js'), false);
});

test('negated character classes match the complement', () => {
  assert.equal(matchesGlob('ax.js', 'a[!0-9].js'), true);
  assert.equal(matchesGlob('a1.js', 'a[!0-9].js'), false);
});

test('dotfiles match a star pattern', () => {
  assert.equal(matchesGlob('.sentinelrc.json', '*.json'), true);
});

test('double star with no slash matches every path', () => {
  assert.equal(matchesGlob('a/b/c', '**'), true);
});

test('directory scoped double star matches descendants', () => {
  assert.equal(matchesGlob('src/a/b.js', 'src/**'), true);
  assert.equal(matchesGlob('lib/b.js', 'src/**'), false);
});

test('leading dot slash is normalized', () => {
  assert.equal(matchesGlob('./src/app.js', 'src/*.js'), true);
});

test('backslashes are normalized to forward slashes', () => {
  assert.equal(matchesGlob('src\\app.js', 'src/*.js'), true);
});

test('matchesAnyGlob is true when one pattern matches', () => {
  assert.equal(matchesAnyGlob('app.mjs', ['*.js', '*.mjs']), true);
  assert.equal(matchesAnyGlob('app.css', ['*.js', '*.mjs']), false);
  assert.equal(matchesAnyGlob('app.css', []), false);
});

test('globToRegExp is anchored at both ends', () => {
  const regexp = globToRegExp('*.js');
  assert.equal(regexp.test('a.js'), true);
  assert.equal(regexp.test('a.jsx'), false);
});

test('an unbalanced brace is rejected', () => {
  assert.throws(() => globToRegExp('src/{a,b'), SyntaxError);
  assert.throws(() => assertValidGlob('src/{a,b'), SyntaxError);
});

test('an unbalanced bracket is rejected', () => {
  assert.throws(() => globToRegExp('src/[abc'), SyntaxError);
});

test('an empty pattern is rejected', () => {
  assert.throws(() => globToRegExp(''), TypeError);
});

test('assertValidGlob accepts ordinary patterns', () => {
  assert.doesNotThrow(() => assertValidGlob('**/*.mjs'));
  assert.doesNotThrow(() => assertValidGlob('.github/workflows/*.yml'));
});
