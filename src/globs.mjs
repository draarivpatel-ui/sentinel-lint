/**
 * Tiny dependency-free glob matcher.
 *
 * Supported syntax:
 *   **        any characters, including slashes
 *   two stars followed by a slash: zero or more leading directories
 *   *         any characters except a slash
 *   ?         exactly one character except a slash
 *   {a,b}     alternation
 *   [abc]     character class
 *
 * A pattern without a slash matches at any depth, exactly like minimatch.
 * All paths are normalized to forward slashes before matching.
 */

const cache = new Map();

function escapeRegExpChar(char) {
  return char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

/**
 * Convert a glob pattern into an anchored RegExp.
 * @param {string} pattern
 * @returns {RegExp}
 */
export function globToRegExp(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    throw new TypeError('glob pattern must be a non-empty string');
  }

  let source = pattern.replace(/\\/g, '/');
  if (source.startsWith('./')) source = source.slice(2);
  if (source.startsWith('/')) source = source.slice(1);
  if (!source.includes('/')) source = '**/' + source;

  let out = '';
  let index = 0;

  while (index < source.length) {
    const char = source[index];

    if (char === '*') {
      if (source[index + 1] === '*') {
        if (source[index + 2] === '/') {
          out += '(?:[^/]+/)*';
          index += 3;
        } else {
          out += '.*';
          index += 2;
        }
      } else {
        out += '[^/]*';
        index += 1;
      }
      continue;
    }

    if (char === '?') {
      out += '[^/]';
      index += 1;
      continue;
    }

    if (char === '{') {
      const end = source.indexOf('}', index + 1);
      if (end === -1) throw new SyntaxError(`unbalanced "{" in glob pattern: ${pattern}`);
      const alternatives = source
        .slice(index + 1, end)
        .split(',')
        .map((part) => part.split('').map(escapeRegExpChar).join(''));
      out += '(?:' + alternatives.join('|') + ')';
      index = end + 1;
      continue;
    }

    if (char === '[') {
      const end = source.indexOf(']', index + 1);
      if (end === -1) throw new SyntaxError(`unbalanced "[" in glob pattern: ${pattern}`);
      let body = source.slice(index + 1, end).replace(/\\/g, '\\\\');
      if (body.startsWith('!')) body = '^' + body.slice(1);
      out += '[' + body + ']';
      index = end + 1;
      continue;
    }

    out += escapeRegExpChar(char);
    index += 1;
  }

  return new RegExp('^' + out + '$');
}

function normalizePath(filePath) {
  let normalized = String(filePath).replace(/\\/g, '/');
  if (normalized.startsWith('./')) normalized = normalized.slice(2);
  return normalized;
}

/**
 * Test a repository relative path against a glob pattern.
 * @param {string} filePath
 * @param {string} pattern
 * @returns {boolean}
 */
export function matchesGlob(filePath, pattern) {
  let regexp = cache.get(pattern);
  if (regexp === undefined) {
    regexp = globToRegExp(pattern);
    cache.set(pattern, regexp);
  }
  return regexp.test(normalizePath(filePath));
}

/**
 * True when at least one pattern matches.
 * @param {string} filePath
 * @param {Iterable<string>} patterns
 * @returns {boolean}
 */
export function matchesAnyGlob(filePath, patterns) {
  for (const pattern of patterns) {
    if (matchesGlob(filePath, pattern)) return true;
  }
  return false;
}

/**
 * Throw when a pattern cannot be parsed. Used by config validation.
 * @param {string} pattern
 */
export function assertValidGlob(pattern) {
  globToRegExp(pattern);
}
