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

const DEFAULT_FUZZ_SEED = 20261127;

function fuzzSeed() {
  const raw = process.env.FUZZ_SEED;
  if (raw === undefined) return DEFAULT_FUZZ_SEED;
  if (!/^-?\d+$/.test(raw)) throw new Error('FUZZ_SEED must be an integer');
  const seed = Number(raw);
  if (!Number.isSafeInteger(seed)) throw new Error('FUZZ_SEED must be a safe integer');
  return seed;
}

function createRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

function trivia(random) {
  const choice = Math.floor(random() * 5);
  if (choice === 0) return ' ';
  if (choice === 1) return '\n';
  if (choice === 2) return '\t';
  if (choice === 3) return ' /* generated */ ';
  return '\n// generated\n';
}

function serializeJsonc(value, random) {
  if (Array.isArray(value)) {
    if (value.length === 0) return `[${trivia(random)}]`;
    let output = `[${trivia(random)}`;
    for (let index = 0; index < value.length; index += 1) {
      output += serializeJsonc(value[index], random);
      output += trivia(random);
      if (index < value.length - 1 || random() < 0.5) output += ',';
      output += trivia(random);
    }
    return `${output}]`;
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) return `{${trivia(random)}}`;
    let output = `{${trivia(random)}`;
    for (let index = 0; index < entries.length; index += 1) {
      const [key, entryValue] = entries[index];
      output += JSON.stringify(key);
      output += trivia(random);
      output += ':';
      output += trivia(random);
      output += serializeJsonc(entryValue, random);
      output += trivia(random);
      if (index < entries.length - 1 || random() < 0.5) output += ',';
      output += trivia(random);
    }
    return `${output}}`;
  }
  return JSON.stringify(value);
}

const segment = fc.stringMatching(/^[a-z][a-z0-9]{0,5}$/);
const relativePath = fc.array(segment, { minLength: 1, maxLength: 5 }).map((parts) => parts.join('/'));
const literalPunctuation = fc.constantFrom('.', '+', '(', ')', '$', '^', '|', '=', '@', ',', '!', ' ');
const literalSegment = fc
  .tuple(
    fc.stringMatching(/^[a-z0-9]{1,4}$/),
    literalPunctuation,
    fc.stringMatching(/^[a-z0-9]{1,4}$/),
  )
  .map(([before, punctuation, after]) => `${before}${punctuation}${after}`);
const literalPath = fc.array(literalSegment, { minLength: 2, maxLength: 5 }).map((parts) => parts.join('/'));
const malformedToken = fc.stringMatching(/^[A-Za-z0-9]{0,16}$/);
const malformedJsonc = fc.oneof(
  malformedToken.map((token) => `{"a":/*${token}`),
  malformedToken.map((token) => `{"a":"${token}`),
  malformedToken.map((token) => `{"a":1}${token}x`),
  malformedToken.map((token) => `[1,2 ${token}x]`),
  malformedToken.map((token) => `{${token}x:1}`),
  fc.integer({ min: 520, max: 530 }).map((depth) => `${'['.repeat(depth)}0${']'.repeat(depth)}`),
  fc.constant("{'a':1}"),
);

test('JSON parser round trips generated JSON values', () => {
  fc.assert(
    fc.property(fc.jsonValue({ maxDepth: 4 }), (value) => {
      const text = JSON.stringify(value);
      const expected = JSON.parse(text);
      assert.deepEqual(jsonToValue(parseJsonDocument(text)), expected);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('JSONC parser accepts generated comments and trailing commas', () => {
  fc.assert(
    fc.property(fc.jsonValue({ maxDepth: 4 }), fc.integer({ min: 0, max: 0xffffffff }), (value, entropy) => {
      const canonical = JSON.parse(JSON.stringify(value));
      const rendered = serializeJsonc(value, createRandom(entropy));
      const input = `/* generated */\n[\n// generated value\n${rendered},\n]\n`;
      assert.deepEqual(jsonToValue(parseJsonDocument(input)), [canonical]);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('malformed JSONC inputs are rejected with typed bounded errors', () => {
  fc.assert(
    fc.property(malformedJsonc, (input) => {
      let caught = null;
      try {
        parseJsonDocument(input);
      } catch (error) {
        caught = error;
      }
      assert.ok(caught instanceof JsonDocumentError, `expected JsonDocumentError for ${JSON.stringify(input)}`);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('JSON and JSONC parser failures stay typed', () => {
  fc.assert(
    fc.property(fc.string({ maxLength: 240 }), (input) => {
      try {
        parseJsonDocument(input);
      } catch (error) {
        assert.ok(error instanceof JsonDocumentError, `unexpected error type: ${error}`);
      }
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('literal repository paths match exactly and reject distinct nonmatches', () => {
  fc.assert(
    fc.property(literalPath, (path) => {
      assert.equal(matchesGlob(path, path), true);
      assert.equal(globToRegExp(path).test(path), true);
      assert.equal(matchesGlob(`${path}x`, path), false);
      assert.equal(matchesGlob(`x${path}`, path), false);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});

test('double-star suffix globs match descendants and reject differing leaves', () => {
  fc.assert(
    fc.property(relativePath, literalSegment, (path, leaf) => {
      const candidate = `${path}/${leaf}`;
      assert.equal(matchesGlob(candidate, `**/${leaf}`), true);
      assert.equal(matchesGlob(`${path}/x${leaf}`, `**/${leaf}`), false);
      assert.equal(matchesGlob(`${path}/${leaf}x`, `**/${leaf}`), false);
    }),
    { numRuns: 100, seed: fuzzSeed() },
  );
});
