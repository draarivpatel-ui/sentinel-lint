import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  JsonDocumentError,
  globToRegExp,
  jsonToValue,
  matchesGlob,
  parseJsonDocument,
} from '../src/index.mjs';

const segment = fc.stringMatching(/^[a-z][a-z0-9]{0,5}$/);
const relativePath = fc.array(segment, { minLength: 1, maxLength: 5 }).map((parts) => parts.join('/'));

test('JSON and JSONC parser round trips generated JSON values', () => {
  fc.assert(
    fc.property(fc.jsonValue({ maxDepth: 4 }), (value) => {
      const text = JSON.stringify(value);
      const expected = JSON.parse(text);
      assert.deepEqual(jsonToValue(parseJsonDocument(text)), expected);
    }),
    { numRuns: 100 },
  );
});

test('JSON and JSONC parser failures stay typed and bounded', () => {
  fc.assert(
    fc.property(fc.string({ maxLength: 240 }), (input) => {
      try {
        parseJsonDocument(input);
      } catch (error) {
        assert.ok(error instanceof JsonDocumentError, `unexpected error type: ${error}`);
      }
    }),
    { numRuns: 100 },
  );
});

test('literal repository paths match their exact glob', () => {
  fc.assert(
    fc.property(relativePath, (path) => {
      assert.equal(matchesGlob(path, path), true);
      assert.equal(globToRegExp(path).test(path), true);
    }),
    { numRuns: 100 },
  );
});

test('double-star suffix globs match generated descendant paths', () => {
  fc.assert(
    fc.property(relativePath, segment, (path, leaf) => {
      const candidate = `${path}/${leaf}`;
      assert.equal(matchesGlob(candidate, `**/${leaf}`), true);
    }),
    { numRuns: 100 },
  );
});
