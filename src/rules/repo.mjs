/**
 * Adapter: repository and application security hygiene.
 *
 * These rules cover credentials committed to source, dangerous dynamic code
 * sinks and a missing vulnerability disclosure policy.
 */

import { defineRule } from '../rule-api.mjs';
import {
  findTokenMatches,
  isMcpConfigFile,
  looksLikePlaceholderLine,
  positionAt,
} from './helpers.mjs';

const DOCS = 'docs/rules.md#';
const JS_GLOBS = ['**/*.js', '**/*.mjs', '**/*.cjs', '**/*.jsx', '**/*.ts', '**/*.tsx'];
const MARKUP_GLOBS = ['**/*.html', '**/*.htm', '**/*.vue', '**/*.svelte'];

/**
 * Blank out JavaScript comments while preserving every character offset and
 * newline, so reported positions still match the original source. String
 * contents are preserved unless `strings` is true.
 */
export function maskJsSource(text, options = {}) {
  const maskStrings = options.strings === true;
  const chars = text.split('');
  let index = 0;

  while (index < chars.length) {
    const char = chars[index];
    const next = chars[index + 1];

    if (char === '/' && next === '/') {
      while (index < chars.length && chars[index] !== '\n') {
        chars[index] = ' ';
        index += 1;
      }
      continue;
    }

    if (char === '/' && next === '*') {
      chars[index] = ' ';
      chars[index + 1] = ' ';
      index += 2;
      while (index < chars.length && !(chars[index] === '*' && chars[index + 1] === '/')) {
        if (chars[index] !== '\n') chars[index] = ' ';
        index += 1;
      }
      if (index < chars.length) {
        chars[index] = ' ';
        chars[index + 1] = ' ';
        index += 2;
      }
      continue;
    }

    if (char === '"' || char === "'" || char === '`') {
      const quote = char;
      index += 1;
      while (index < chars.length) {
        if (chars[index] === '\\') {
          if (maskStrings && chars[index] !== '\n') chars[index] = ' ';
          index += 1;
          if (index < chars.length && maskStrings && chars[index] !== '\n') chars[index] = ' ';
          index += 1;
          continue;
        }
        if (chars[index] === quote) {
          index += 1;
          break;
        }
        if (quote !== '`' && chars[index] === '\n') break;
        if (maskStrings && chars[index] !== '\n') chars[index] = ' ';
        index += 1;
      }
      continue;
    }

    index += 1;
  }

  return chars.join('');
}

/**
 * Blank out HTML comments while preserving offsets.
 */
export function maskHtmlComments(text) {
  const chars = text.split('');
  let index = 0;
  while (index < chars.length) {
    if (chars[index] === '<' && chars[index + 1] === '!' && chars[index + 2] === '-' && chars[index + 3] === '-') {
      while (index < chars.length && !(chars[index] === '-' && chars[index + 1] === '-' && chars[index + 2] === '>')) {
        if (chars[index] !== '\n') chars[index] = ' ';
        index += 1;
      }
      for (let step = 0; step < 3 && index < chars.length; step += 1) {
        chars[index] = ' ';
        index += 1;
      }
      continue;
    }
    index += 1;
  }
  return chars.join('');
}

function isMarkupFile(file) {
  return /\.(?:html?|vue|svelte)$/i.test(file.name ?? '');
}

const hardcodedToken = defineRule({
  id: 'repo/hardcoded-token',
  title: 'Vendor credential pattern is committed to the repository',
  category: 'repo',
  severity: 'critical',
  cwe: 'CWE-798',
  docsUrl: DOCS + 'repohardcoded-token',
  rationale:
    'Credential shaped strings in tracked files are harvested by scanners and bots within minutes of a push. Git history keeps the value even after a later commit deletes it.',
  fix: 'Move the credential to a secret manager or CI secret, remove it from the file, and rotate it. Rewriting history is required if the repository is public.',
  match: (file) => !isMcpConfigFile(file),
  check(ctx) {
    const lines = ctx.lines;
    const findings = [];
    const matches = findTokenMatches(ctx.text);

    for (const match of matches) {
      if (findings.length >= 50) break;
      const { line, column } = positionAt(ctx.text, match.index);
      const lineText = lines[line - 1] ?? '';
      if (looksLikePlaceholderLine(lineText)) continue;
      findings.push({
        line,
        column,
        message: `Hardcoded ${match.kind} detected. Remove the value, rotate the credential, and load it from a secret store at runtime.`,
      });
    }

    return findings;
  },
});

const dangerousEval = defineRule({
  id: 'repo/dangerous-eval',
  title: 'Code uses a dynamic code execution sink',
  category: 'repo',
  severity: 'error',
  cwe: 'CWE-95',
  docsUrl: DOCS + 'repodangerous-eval',
  rationale:
    'eval and new Function execute arbitrary strings. When any part of the input is influenced by a user, a file or a network response, the result is remote code execution.',
  fix: 'Parse data with JSON.parse, a schema validator or a lookup table. If a rule engine truly needs dynamic behavior, expose a fixed set of operations instead of JavaScript source.',
  appliesTo: [...JS_GLOBS, ...MARKUP_GLOBS],
  check(ctx) {
    const component = ctx.file.ext === '.vue' || ctx.file.ext === '.svelte';
    const masked = component
      ? maskJsSource(maskHtmlComments(ctx.text), { strings: true })
      : isMarkupFile(ctx.file)
        ? maskHtmlComments(ctx.text)
        : maskJsSource(ctx.text, { strings: true });

    const sinks = [
      { name: 'eval()', regex: /(?<![\w.$])eval\s*\(/g },
      { name: 'new Function()', regex: /\bnew\s+Function\s*\(/g },
    ];

    const findings = [];
    const seen = new Set();
    for (const sink of sinks) {
      sink.regex.lastIndex = 0;
      let match = sink.regex.exec(masked);
      while (match !== null) {
        if (!seen.has(match.index)) {
          seen.add(match.index);
          const { line, column } = positionAt(masked, match.index);
          findings.push({
            line,
            column,
            message: `${sink.name} executes a string as code. Replace it with a parser or a fixed dispatch table.`,
          });
        }
        match = sink.regex.exec(masked);
      }
    }
    return findings;
  },
});

const dangerousHtmlSink = defineRule({
  id: 'repo/dangerous-html-sink',
  title: 'Code writes untrusted data into an HTML sink',
  category: 'repo',
  severity: 'error',
  cwe: 'CWE-79',
  docsUrl: DOCS + 'repodangerous-html-sink',
  rationale:
    'innerHTML, outerHTML, document.write and dangerouslySetInnerHTML turn strings into DOM. Without a sanitizer, any interpolated user or API value becomes cross site scripting.',
  fix: 'Use textContent, a templating engine that escapes by default, or a maintained sanitizer such as DOMPurify before assigning HTML.',
  appliesTo: [...JS_GLOBS, ...MARKUP_GLOBS],
  check(ctx) {
    let masked;
    if (ctx.file.ext === '.vue' || ctx.file.ext === '.svelte') {
      masked = maskJsSource(maskHtmlComments(ctx.text), { strings: true });
    } else if (isMarkupFile(ctx.file)) {
      masked = maskHtmlComments(ctx.text);
    } else {
      masked = maskJsSource(ctx.text, { strings: true });
    }

    const sinks = [
      { name: 'dangerouslySetInnerHTML', regex: /\bdangerouslySetInnerHTML\b/g },
      { name: 'innerHTML or outerHTML assignment', regex: /\.(?:inner|outer)HTML\s*=/g },
      { name: 'document.write()', regex: /\bdocument\.write(?:ln)?\s*\(/g },
    ];

    const findings = [];
    const seen = new Set();
    for (const sink of sinks) {
      sink.regex.lastIndex = 0;
      let match = sink.regex.exec(masked);
      while (match !== null) {
        if (!seen.has(match.index)) {
          seen.add(match.index);
          const { line, column } = positionAt(masked, match.index);
          findings.push({
            line,
            column,
            message: `${sink.name} writes a string into the DOM. Sanitize the value or use a text only API such as textContent.`,
          });
        }
        match = sink.regex.exec(masked);
      }
    }
    return findings;
  },
});

/**
 * Return the text of the first argument of a call, starting at its opening
 * parenthesis. Quotes and nested parentheses are respected.
 */
export function readCallArgument(text, openParenIndex) {
  const start = openParenIndex + 1;
  let depth = 0;
  let quote = null;

  for (let index = openParenIndex; index < text.length; index += 1) {
    const char = text[index];
    if (quote !== null) {
      if (char === '\\') {
        index += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'" || char === '`') {
      quote = char;
      continue;
    }
    if (char === '(') depth += 1;
    else if (char === ')') {
      depth -= 1;
      if (depth === 0) return text.slice(start, index);
    }
  }

  return text.slice(start, Math.min(text.length, start + 500));
}

const childProcessInjection = defineRule({
  id: 'repo/child-process-injection',
  title: 'Shell command is built from an interpolated value',
  category: 'repo',
  severity: 'error',
  cwe: 'CWE-78',
  docsUrl: DOCS + 'repochild-process-injection',
  rationale:
    'child_process.exec passes its command string to a shell. Interpolating a request parameter, filename or environment value lets that data terminate the command and start another one.',
  fix: 'Use execFile or spawn with an argument array, so each argument stays a literal value and no shell parses it.',
  appliesTo: JS_GLOBS,
  match: (file) => file.text.includes('child_process'),
  check(ctx) {
    const masked = maskJsSource(ctx.text);
    const findings = [];
    const regex = /\b(?:exec|execSync)\s*\(/g;
    let match = regex.exec(masked);

    while (match !== null) {
      const openParen = masked.indexOf('(', match.index);
      const argument = readCallArgument(masked, openParen);
      const hasInterpolatedTemplate = /`[^`]*\$\{/.test(argument);
      const hasConcatenation = /\+\s*[A-Za-z_$(`'"]/.test(argument);
      if (hasInterpolatedTemplate || hasConcatenation) {
        const { line, column } = positionAt(masked, match.index);
        findings.push({
          line,
          column,
          message:
            'child_process.exec receives a command assembled from interpolated data. Use execFile or spawn with an argument array instead.',
        });
      }
      match = regex.exec(masked);
    }

    return findings;
  },
});

const missingSecurityPolicy = defineRule({
  id: 'repo/missing-security-policy',
  title: 'Repository has no SECURITY.md disclosure policy',
  category: 'repo',
  severity: 'warning',
  docsUrl: DOCS + 'repomissing-security-policy',
  rationale:
    'Without a disclosure policy, reporters often open a public issue with reproduction steps, which is the same as publishing the vulnerability before a fix exists.',
  fix: 'Add SECURITY.md at the repository root or in .github/ with a private reporting channel and an expected response window.',
  scope: 'repo',
  check(ctx) {
    const candidates = new Set(['security.md', '.github/security.md', 'docs/security.md']);
    const present = ctx.paths.some((filePath) => candidates.has(filePath.toLowerCase()));
    if (present) return [];

    const readme = ctx.paths.find((filePath) => /^readme\.(?:md|markdown)$/i.test(filePath));
    return [
      {
        file: readme ?? null,
        line: 1,
        column: 1,
        message:
          'No SECURITY.md was found at the repository root, in .github/ or in docs/. Add a private vulnerability reporting policy.',
      },
    ];
  },
});

export const repoRules = Object.freeze([
  hardcodedToken,
  dangerousEval,
  dangerousHtmlSink,
  childProcessInjection,
  missingSecurityPolicy,
]);
