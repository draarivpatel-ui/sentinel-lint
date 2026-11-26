/**
 * A small JSON reader that keeps source positions and tolerates the JSONC
 * extensions commonly found in editor and MCP configuration files (line
 * comments, block comments and trailing commas).
 *
 * Every node records the 1-based line and column where it starts. Object
 * entries record the key position separately so a rule can point at either
 * the key or the value.
 */

export class JsonDocumentError extends Error {
  constructor(message, line, column) {
    super(`${message} at line ${line}, column ${column}`);
    this.name = 'JsonDocumentError';
    this.line = line;
    this.column = column;
  }
}

const NUMBER_PATTERN = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;

/**
 * Parse JSON/JSONC and return an annotated syntax tree.
 *
 * @param {string} input
 * @param {{ maxDepth?: number }} [options]
 * @returns {object} root node
 */
export function parseJsonDocument(input, options = {}) {
  if (typeof input !== 'string') throw new TypeError('parseJsonDocument expects a string');

  const maxDepth = options.maxDepth ?? 512;
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  let index = 0;
  let line = 1;
  let column = 1;

  function peek(offset = 0) {
    return text[index + offset];
  }

  function advance(count = 1) {
    for (let step = 0; step < count; step += 1) {
      if (index >= text.length) return;
      if (text[index] === '\n') {
        line += 1;
        column = 1;
      } else {
        column += 1;
      }
      index += 1;
    }
  }

  function fail(message) {
    throw new JsonDocumentError(message, line, column);
  }

  function skipTrivia() {
    for (;;) {
      const char = peek();
      if (char === ' ' || char === '\t' || char === '\n' || char === '\r') {
        advance();
        continue;
      }
      if (char === '/' && peek(1) === '/') {
        while (peek() !== undefined && peek() !== '\n') advance();
        continue;
      }
      if (char === '/' && peek(1) === '*') {
        advance(2);
        while (!(peek() === '*' && peek(1) === '/')) {
          if (peek() === undefined) fail('unterminated block comment');
          advance();
        }
        advance(2);
        continue;
      }
      return;
    }
  }

  function parseString() {
    const startLine = line;
    const startColumn = column;
    advance();
    let value = '';

    for (;;) {
      const char = peek();
      if (char === undefined) fail('unterminated string');
      if (char === '"') {
        advance();
        break;
      }
      if (char === '\\') {
        advance();
        const escape = peek();
        if (escape === undefined) fail('unterminated escape sequence');
        if (escape === '"' || escape === '\\' || escape === '/') {
          value += escape;
          advance();
        } else if (escape === 'b') {
          value += '\b';
          advance();
        } else if (escape === 'f') {
          value += '\f';
          advance();
        } else if (escape === 'n') {
          value += '\n';
          advance();
        } else if (escape === 'r') {
          value += '\r';
          advance();
        } else if (escape === 't') {
          value += '\t';
          advance();
        } else if (escape === 'u') {
          const hex = text.slice(index + 1, index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('invalid unicode escape');
          value += String.fromCharCode(Number.parseInt(hex, 16));
          advance(5);
        } else {
          fail(`invalid escape sequence "\\${escape}"`);
        }
        continue;
      }
      if (char.charCodeAt(0) < 0x20) fail('unescaped control character in string');
      value += char;
      advance();
    }

    return { type: 'string', line: startLine, column: startColumn, value };
  }

  function parseNumber() {
    const startLine = line;
    const startColumn = column;
    const match = NUMBER_PATTERN.exec(text.slice(index));
    if (match === null) fail('invalid number');
    const raw = match[0];
    const next = text[index + raw.length];
    if (next !== undefined && /[0-9A-Za-z._]/.test(next)) fail('invalid number');
    advance(raw.length);
    return { type: 'number', line: startLine, column: startColumn, value: Number(raw) };
  }

  function parseLiteral(word, value) {
    const startLine = line;
    const startColumn = column;
    if (!text.startsWith(word, index)) fail(`expected ${word}`);
    advance(word.length);
    return { type: 'literal', line: startLine, column: startColumn, value };
  }

  function parseArray(depth) {
    if (depth > maxDepth) fail('maximum nesting depth exceeded');
    const node = { type: 'array', line, column, items: [] };
    advance();
    skipTrivia();
    if (peek() === ']') {
      advance();
      return node;
    }
    for (;;) {
      node.items.push(parseValue(depth + 1));
      skipTrivia();
      if (peek() === ',') {
        advance();
        skipTrivia();
        if (peek() === ']') {
          advance();
          return node;
        }
        continue;
      }
      if (peek() === ']') {
        advance();
        return node;
      }
      fail('expected "," or "]"');
    }
  }

  function parseObject(depth) {
    if (depth > maxDepth) fail('maximum nesting depth exceeded');
    const node = { type: 'object', line, column, entries: [] };
    advance();
    skipTrivia();
    if (peek() === '}') {
      advance();
      return node;
    }
    for (;;) {
      skipTrivia();
      if (peek() !== '"') fail('expected a double quoted object key');
      const keyNode = parseString();
      skipTrivia();
      if (peek() !== ':') fail('expected ":" after object key');
      advance();
      const value = parseValue(depth + 1);
      node.entries.push({
        key: keyNode.value,
        keyLine: keyNode.line,
        keyColumn: keyNode.column,
        value,
      });
      skipTrivia();
      if (peek() === ',') {
        advance();
        skipTrivia();
        if (peek() === '}') {
          advance();
          return node;
        }
        continue;
      }
      if (peek() === '}') {
        advance();
        return node;
      }
      fail('expected "," or "}"');
    }
  }

  function parseValue(depth = 0) {
    skipTrivia();
    const char = peek();
    if (char === '{') return parseObject(depth);
    if (char === '[') return parseArray(depth);
    if (char === '"') return parseString();
    if (char === '-' || (char >= '0' && char <= '9')) return parseNumber();
    if (char === 't') return parseLiteral('true', true);
    if (char === 'f') return parseLiteral('false', false);
    if (char === 'n') return parseLiteral('null', null);
    if (char === undefined) fail('unexpected end of input');
    fail(`unexpected character "${char}"`);
  }

  const root = parseValue(0);
  skipTrivia();
  if (index < text.length) fail('unexpected trailing content after the top level value');
  return root;
}

/**
 * Find an object entry by key.
 * @returns {{key: string, keyLine: number, keyColumn: number, value: object} | null}
 */
export function getMember(objectNode, key) {
  if (!objectNode || objectNode.type !== 'object') return null;
  for (const entry of objectNode.entries) {
    if (entry.key === key) return entry;
  }
  return null;
}

/**
 * All entries of an object node, empty for other node types.
 */
export function getEntries(objectNode) {
  return objectNode && objectNode.type === 'object' ? objectNode.entries : [];
}

/**
 * String value of a node, or null.
 */
export function stringValue(node) {
  return node && node.type === 'string' ? node.value : null;
}

/**
 * Convert an annotated node tree into plain JavaScript values.
 * Objects become null prototype free plain objects, arrays become arrays and
 * scalars keep their parsed value. Used by the configuration loader.
 * @param {object} node
 * @returns {unknown}
 */
export function jsonToValue(node) {
  if (node === null || typeof node !== 'object') return null;
  if (node.type === 'object') {
    return Object.fromEntries(node.entries.map((entry) => [entry.key, jsonToValue(entry.value)]));
  }
  if (node.type === 'array') {
    return node.items.map((item) => jsonToValue(item));
  }
  return node.value;
}

/**
 * Depth first walk over every node.
 * @param {object} node
 * @param {(node: object) => void} visit
 */
export function walkJson(node, visit) {
  if (!node || typeof node !== 'object') return;
  visit(node);
  if (node.type === 'object') {
    for (const entry of node.entries) walkJson(entry.value, visit);
  } else if (node.type === 'array') {
    for (const item of node.items) walkJson(item, visit);
  }
}
