import test from 'node:test';
import assert from 'node:assert/strict';
import {
  JsonDocumentError,
  getEntries,
  getMember,
  jsonToValue,
  parseJsonDocument,
  stringValue,
  walkJson,
} from '../src/json-pos.mjs';

const SAMPLE = ['{', '  "a": 1,', '  "b": {', '    "c": "d"', '  },', '  "e": [true, null]', '}', ''].join('\n');

test('object entries record key and value positions', () => {
  const root = parseJsonDocument(SAMPLE);
  const a = getMember(root, 'a');
  assert.equal(a.keyLine, 2);
  assert.equal(a.keyColumn, 3);
  assert.equal(a.value.line, 2);
  assert.equal(a.value.column, 8);
  assert.equal(a.value.value, 1);
});

test('nested objects keep their own positions', () => {
  const root = parseJsonDocument(SAMPLE);
  const b = getMember(root, 'b');
  assert.equal(b.value.type, 'object');
  const c = getMember(b.value, 'c');
  assert.equal(c.keyLine, 4);
  assert.equal(c.keyColumn, 5);
  assert.equal(stringValue(c.value), 'd');
});

test('arrays preserve items in order', () => {
  const root = parseJsonDocument(SAMPLE);
  const e = getMember(root, 'e');
  assert.equal(e.value.type, 'array');
  assert.equal(e.value.items.length, 2);
  assert.equal(e.value.items[0].value, true);
  assert.equal(e.value.items[1].value, null);
});

test('line comments are accepted', () => {
  const root = parseJsonDocument('{\n  // a note\n  "a": 1\n}\n');
  assert.equal(getMember(root, 'a').value.value, 1);
});

test('block comments are accepted', () => {
  const root = parseJsonDocument('{\n  /* a note */\n  "a": 1\n}\n');
  assert.equal(getMember(root, 'a').value.value, 1);
});

test('trailing commas in objects and arrays are accepted', () => {
  const root = parseJsonDocument('{"a": [1, 2,], "b": {"c": 3,},}');
  assert.equal(getMember(root, 'a').value.items.length, 2);
  assert.equal(getMember(getMember(root, 'b').value, 'c').value.value, 3);
});

test('string escapes are decoded', () => {
  assert.equal(parseJsonDocument('"a\\nb"').value, 'a\nb');
  assert.equal(parseJsonDocument('"\\u0041"').value, 'A');
  assert.equal(parseJsonDocument('"quote: \\""').value, 'quote: "');
});

test('numbers are parsed with exponent and sign', () => {
  assert.equal(parseJsonDocument('-12.5e2').value, -1250);
  assert.equal(parseJsonDocument('0').value, 0);
});

test('literals parse to their JavaScript values', () => {
  assert.equal(parseJsonDocument('true').value, true);
  assert.equal(parseJsonDocument('false').value, false);
  assert.equal(parseJsonDocument('null').value, null);
});

test('a byte order mark is ignored', () => {
  const root = parseJsonDocument('\uFEFF{"a": 1}');
  assert.equal(getMember(root, 'a').value.value, 1);
});

test('an unterminated string reports a position', () => {
  assert.throws(
    () => parseJsonDocument('{\n  "a": "b'),
    (error) => {
      assert.ok(error instanceof JsonDocumentError);
      assert.equal(typeof error.line, 'number');
      assert.equal(typeof error.column, 'number');
      assert.match(error.message, /unterminated string at line/);
      return true;
    },
  );
});

test('trailing content after the top level value is rejected', () => {
  assert.throws(() => parseJsonDocument('{} {}'), JsonDocumentError);
});

test('comments without end are rejected', () => {
  assert.throws(() => parseJsonDocument('{ /* nope'), JsonDocumentError);
});

test('nesting beyond the configured depth is rejected', () => {
  assert.throws(() => parseJsonDocument('[[[[1]]]]', { maxDepth: 2 }), JsonDocumentError);
});

test('getMember returns null for missing keys and non-objects', () => {
  const root = parseJsonDocument('{"a": 1}');
  assert.equal(getMember(root, 'missing'), null);
  assert.equal(getMember(null, 'a'), null);
  assert.equal(getMember(parseJsonDocument('[1]'), 'a'), null);
});

test('getEntries returns an empty list for non-objects', () => {
  assert.deepEqual(getEntries(parseJsonDocument('[1, 2]')), []);
  assert.deepEqual(getEntries(null), []);
  assert.equal(getEntries(parseJsonDocument('{"a": 1}')).length, 1);
});

test('stringValue returns null for non-strings', () => {
  assert.equal(stringValue(parseJsonDocument('1')), null);
  assert.equal(stringValue(null), null);
  assert.equal(stringValue(parseJsonDocument('"x"')), 'x');
});

test('walkJson visits every node exactly once', () => {
  const root = parseJsonDocument('{"a": [1, {"b": "c"}]}');
  const seen = [];
  walkJson(root, (node) => {
    seen.push(node.type);
  });
  assert.deepEqual(seen, ['object', 'array', 'number', 'object', 'string']);
});

test('jsonToValue converts a document into plain values', () => {
  const value = jsonToValue(parseJsonDocument('{"a": [1, true, null, "x"], "b": {"c": 2}}'));
  assert.deepEqual(value, { a: [1, true, null, 'x'], b: { c: 2 } });
});

test('jsonToValue accepts comments and trailing commas', () => {
  assert.deepEqual(jsonToValue(parseJsonDocument('{ // note\n  "a": 1,\n}')), { a: 1 });
});

test('jsonToValue keeps a prototype key as an own property', () => {
  const value = jsonToValue(parseJsonDocument('{"__proto__": {"polluted": true}}'));
  assert.equal(Object.hasOwn(value, '__proto__'), true);
  assert.equal({}.polluted, undefined);
});

test('duplicate keys resolve to the first entry', () => {
  const root = parseJsonDocument('{"a": 1, "a": 2}');
  assert.equal(getMember(root, 'a').value.value, 1);
});
