/**
 * Shared test utilities. This file is not a test file: the name does not match
 * the runner pattern, so node --test only loads it through imports.
 */

import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scan } from '../src/engine.mjs';
import { loadBuiltinRules } from '../src/rules/index.mjs';

/**
 * Create a temporary directory that is removed when the test finishes.
 * @param {object} t node:test context
 * @param {string} [prefix]
 * @returns {Promise<string>} Absolute, symlink free path.
 */
export async function makeTempDir(t, prefix = 'sentinel-lint-') {
  const created = await mkdtemp(path.join(tmpdir(), prefix));
  const resolved = await realpath(created);
  if (t !== undefined && t !== null && typeof t.after === 'function') {
    t.after(async () => {
      await rm(resolved, { recursive: true, force: true });
    });
  }
  return resolved;
}

/**
 * Write a tree of files. Keys are POSIX style relative paths.
 * @param {string} root
 * @param {Record<string, string | Buffer>} tree
 * @returns {Promise<string>}
 */
export async function writeTree(root, tree) {
  for (const [relative, content] of Object.entries(tree)) {
    const absolute = path.join(root, ...relative.split('/'));
    await mkdir(path.dirname(absolute), { recursive: true });
    await writeFile(absolute, content);
  }
  return root;
}

/**
 * Create a temp repository and return its path.
 * @param {object} t
 * @param {Record<string, string | Buffer>} tree
 * @returns {Promise<string>}
 */
export async function makeTree(t, tree) {
  const root = await makeTempDir(t);
  await writeTree(root, tree);
  return root;
}

/**
 * Write a tree to a temp directory and scan it.
 * @param {object} t
 * @param {Record<string, string | Buffer>} tree
 * @param {object} [options] Extra scan options.
 * @returns {Promise<object>}
 */
export async function scanTree(t, tree, options = {}) {
  const root = await makeTree(t, tree);
  return scan({ root, ...options });
}

/**
 * Findings for one rule id.
 * @param {object} result
 * @param {string} ruleId
 * @returns {object[]}
 */
export function byRule(result, ruleId) {
  return result.findings.filter((finding) => finding.ruleId === ruleId);
}

/**
 * A writable stream stand in that records everything written to it.
 * @returns {{isTTY: boolean, chunks: string[], write(chunk: string): boolean, text(): string}}
 */
export function captureStream() {
  const chunks = [];
  return {
    isTTY: false,
    chunks,
    write(chunk) {
      chunks.push(String(chunk));
      return true;
    },
    text() {
      return chunks.join('');
    },
  };
}

/**
 * Default finding used by reporter tests.
 * @param {object} [partial]
 * @returns {object}
 */
export function makeFinding(partial = {}) {
  return {
    ruleId: 'repo/dangerous-eval',
    title: 'Code uses a dynamic code execution sink',
    severity: 'error',
    category: 'repo',
    cwe: 'CWE-95',
    docsUrl: 'docs/rules.md#repodangerous-eval',
    fix: 'Replace it with a parser.',
    file: 'src/app.js',
    line: 3,
    column: 11,
    message: 'eval() executes a string as code.',
    ...partial,
  };
}

/**
 * Build a scan result shaped object for reporter tests.
 * @param {object} [partial]
 * @returns {object}
 */
export function makeResult(partial = {}) {
  const findings = (partial.findings ?? [makeFinding()]).map((finding) => makeFinding(finding));
  const bySeverity = { info: 0, warning: 0, error: 0, critical: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;
  const diagnostics = partial.diagnostics ?? [];
  return {
    root: '/repo',
    files: [],
    findings,
    diagnostics,
    diagnosticsTruncated: 0,
    stats: { suppressed: 0, ruleErrors: 0, filesScanned: 3, ...(partial.stats ?? {}) },
    summary: {
      filesScanned: 3,
      findings: findings.length,
      suppressed: 0,
      ruleErrors: 0,
      diagnostics: diagnostics.length,
      bySeverity,
      durationMs: 4,
      ...(partial.summary ?? {}),
    },
    rules: partial.rules ?? loadBuiltinRules(),
  };
}

/**
 * A benign repository that must produce no findings with the default config:
 * a disclosure policy, a pinned workflow and plain source.
 */
export const CLEAN_TREE = Object.freeze({
  'README.md': '# clean fixture\n\nA small repository used by the test suite.\n',
  'SECURITY.md': '# Security policy\n\nReport issues privately to the maintainers.\n',
  'package.json': '{\n  "name": "clean-fixture",\n  "version": "1.0.0",\n  "private": true\n}\n',
  '.github/workflows/ci.yml': [
    'name: ci',
    'on:',
    '  push:',
    '    branches: [main]',
    'jobs:',
    '  test:',
    '    runs-on: ubuntu-latest',
    '    permissions:',
    '      contents: read',
    '    steps:',
    '      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567',
    '      - name: greet',
    '        run: echo "hello from ci"',
    '',
  ].join('\n'),
  'src/app.js': ['export function add(left, right) {', '  return left + right;', '}', ''].join('\n'),
});
