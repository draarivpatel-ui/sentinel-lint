/**
 * Deterministic, symlink-safe repository walker.
 *
 * Safety properties:
 *   - symbolic links are never followed, so a link to /etc or a browser
 *     profile cannot pull content into a scan;
 *   - every resolved path must stay inside the scan root;
 *   - binary files and oversized files are skipped by default;
 *   - traversal order and the final file list are sorted, which keeps rule
 *     output and golden tests stable.
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { matchesAnyGlob } from './globs.mjs';

export const DEFAULT_SKIP_DIRS = Object.freeze([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'bower_components',
  '.venv',
  'venv',
  '__pycache__',
  '.mypy_cache',
  '.pytest_cache',
  '.ruff_cache',
  '.cache',
  'coverage',
  '.nyc_output',
  '.next',
  '.nuxt',
  '.svelte-kit',
  'dist',
  'build',
  'out',
  'target',
  'vendor',
  '.terraform',
  '.turbo',
  '.parcel-cache',
]);

const SKIP_FILES = new Set(['.DS_Store', 'Thumbs.db']);

function isBinary(buffer) {
  const limit = Math.min(buffer.length, 8192);
  for (let index = 0; index < limit; index += 1) {
    if (buffer[index] === 0) return true;
  }
  return false;
}

function strictDescendant(root, candidate) {
  return candidate === root || candidate.startsWith(root + path.sep);
}

/**
 * Walk a repository and return readable text files.
 *
 * @param {string} root Absolute or relative scan root.
 * @param {object} [options]
 * @param {number} [options.maxFileSize] Bytes, default 1048576.
 * @param {number} [options.maxFiles] Default 20000.
 * @param {number} [options.maxDepth] Default 32.
 * @param {string[]} [options.include] Whitelist globs, empty means everything.
 * @param {string[]} [options.exclude] Extra ignore globs.
 * @param {string[]} [options.skipDirs] Extra directory names to skip.
 * @returns {Promise<{root: string, files: object[], diagnostics: object[], stats: object}>}
 */
export async function walkRepository(root, options = {}) {
  const resolvedRoot = await fs.realpath(path.resolve(root));
  const stat = await fs.stat(resolvedRoot);
  if (!stat.isDirectory()) {
    throw new Error(`scan root is not a directory: ${root}`);
  }

  const maxFileSize = options.maxFileSize ?? 1024 * 1024;
  const maxFiles = options.maxFiles ?? 20000;
  const maxDepth = options.maxDepth ?? 32;
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  const skipDirs = new Set([...DEFAULT_SKIP_DIRS, ...(options.skipDirs ?? [])]);

  const files = [];
  const diagnostics = [];
  const stats = {
    directoriesVisited: 0,
    filesVisited: 0,
    filesScanned: 0,
    binarySkipped: 0,
    unreadableSkipped: 0,
    tooLargeSkipped: 0,
    symlinkSkipped: 0,
    ignoredSkipped: 0,
    limitReached: false,
  };

  const stack = [resolvedRoot];
  let budget = maxFiles;

  while (stack.length > 0) {
    if (stats.limitReached) break;

    const currentDir = stack.pop();
    const depth = path.relative(resolvedRoot, currentDir).split(path.sep).filter(Boolean).length;
    if (depth > maxDepth) {
      diagnostics.push({ code: 'depth-limit', message: `skipped deep directory ${path.relative(resolvedRoot, currentDir)}` });
      continue;
    }

    stats.directoriesVisited += 1;

    let entries;
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch (error) {
      diagnostics.push({
        code: 'unreadable-directory',
        message: `could not read directory ${path.relative(resolvedRoot, currentDir) || '.'}: ${error.code ?? error.message}`,
      });
      continue;
    }

    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));

    for (const entry of entries) {
      if (budget <= 0) {
        stats.limitReached = true;
        diagnostics.push({ code: 'file-limit', message: `stopped after ${maxFiles} files` });
        break;
      }

      const absolute = path.join(currentDir, entry.name);
      const relative = path.relative(resolvedRoot, absolute).split(path.sep).join('/');

      if (relative === '' || relative.startsWith('../')) {
        diagnostics.push({ code: 'path-outside-root', message: 'refused to scan a path outside the scan root' });
        continue;
      }

      if (!strictDescendant(resolvedRoot, path.resolve(absolute))) {
        diagnostics.push({ code: 'path-outside-root', message: `refused to scan ${relative}` });
        continue;
      }

      if (entry.isSymbolicLink()) {
        stats.symlinkSkipped += 1;
        continue;
      }

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) {
          stats.ignoredSkipped += 1;
          continue;
        }
        if (matchesAnyGlob(relative, exclude) || matchesAnyGlob(`${relative}/__probe__`, exclude)) {
          stats.ignoredSkipped += 1;
          continue;
        }
        stack.push(absolute);
        continue;
      }

      if (!entry.isFile()) continue;
      if (SKIP_FILES.has(entry.name)) continue;

      stats.filesVisited += 1;

      if (matchesAnyGlob(relative, exclude)) {
        stats.ignoredSkipped += 1;
        continue;
      }
      if (include.length > 0 && !matchesAnyGlob(relative, include)) {
        stats.ignoredSkipped += 1;
        continue;
      }

      let fileStat;
      try {
        fileStat = await fs.stat(absolute);
      } catch (error) {
        stats.unreadableSkipped += 1;
        diagnostics.push({ code: 'unreadable-file', message: `could not stat ${relative}: ${error.code ?? error.message}` });
        continue;
      }

      if (fileStat.size > maxFileSize) {
        stats.tooLargeSkipped += 1;
        continue;
      }

      let buffer;
      try {
        buffer = await fs.readFile(absolute);
      } catch (error) {
        stats.unreadableSkipped += 1;
        diagnostics.push({ code: 'unreadable-file', message: `could not read ${relative}: ${error.code ?? error.message}` });
        continue;
      }

      if (isBinary(buffer)) {
        stats.binarySkipped += 1;
        continue;
      }

      let text = buffer.toString('utf8');
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

      budget -= 1;
      files.push({
        path: relative,
        absolutePath: absolute,
        name: entry.name,
        ext: path.extname(entry.name).toLowerCase(),
        size: fileStat.size,
        text,
      });
    }
  }

  files.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  stats.filesScanned = files.length;

  return { root: resolvedRoot, files, diagnostics, stats };
}
