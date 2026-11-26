import test from 'node:test';
import assert from 'node:assert/strict';
import { symlink } from 'node:fs/promises';
import path from 'node:path';
import { walkRepository } from '../src/walk.mjs';
import { makeTree } from './helpers.mjs';

test('files are returned in sorted order with relative paths', async (t) => {
  const root = await makeTree(t, {
    'b.txt': 'b\n',
    'a.txt': 'a\n',
    'src/z.txt': 'z\n',
    'src/a.txt': 'a\n',
  });
  const walked = await walkRepository(root);
  assert.deepEqual(
    walked.files.map((file) => file.path),
    ['a.txt', 'b.txt', 'src/a.txt', 'src/z.txt'],
  );
  assert.equal(walked.stats.filesScanned, 4);
});

test('file records carry name, extension, size and text', async (t) => {
  const root = await makeTree(t, { 'src/app.mjs': 'export const a = 1;\n' });
  const walked = await walkRepository(root);
  const file = walked.files[0];
  assert.equal(file.name, 'app.mjs');
  assert.equal(file.ext, '.mjs');
  assert.equal(file.text, 'export const a = 1;\n');
  assert.equal(file.absolutePath, path.join(walked.root, 'src', 'app.mjs'));
});

test('node_modules and other build directories are skipped', async (t) => {
  const root = await makeTree(t, {
    'keep.txt': 'keep\n',
    'node_modules/pkg/index.js': 'module.exports = 1;\n',
    '.git/config': '[core]\n',
    'dist/bundle.js': 'var a = 1;\n',
  });
  const walked = await walkRepository(root);
  assert.deepEqual(
    walked.files.map((file) => file.path),
    ['keep.txt'],
  );
});

test('symbolic links are never followed', async (t) => {
  const root = await makeTree(t, { 'real.txt': 'real\n' });
  await symlink(path.join(root, 'real.txt'), path.join(root, 'link.txt'));
  await symlink(root, path.join(root, 'loop'));
  const walked = await walkRepository(root);
  assert.deepEqual(
    walked.files.map((file) => file.path),
    ['real.txt'],
  );
  assert.equal(walked.stats.symlinkSkipped, 2);
});

test('binary files are skipped', async (t) => {
  const root = await makeTree(t, { 'image.bin': Buffer.from([0x89, 0x00, 0x4e, 0x47]) });
  const walked = await walkRepository(root);
  assert.equal(walked.files.length, 0);
  assert.equal(walked.stats.binarySkipped, 1);
});

test('oversized files are skipped', async (t) => {
  const root = await makeTree(t, { 'big.txt': 'x'.repeat(200) });
  const walked = await walkRepository(root, { maxFileSize: 50 });
  assert.equal(walked.files.length, 0);
  assert.equal(walked.stats.tooLargeSkipped, 1);
});

test('a byte order mark is stripped from the text', async (t) => {
  const root = await makeTree(t, { 'bom.txt': '\uFEFFhello\n' });
  const walked = await walkRepository(root);
  assert.equal(walked.files[0].text, 'hello\n');
});

test('include globs restrict the file set', async (t) => {
  const root = await makeTree(t, { 'a.md': '# a\n', 'b.js': 'const b = 1;\n' });
  const walked = await walkRepository(root, { include: ['**/*.md'] });
  assert.deepEqual(
    walked.files.map((file) => file.path),
    ['a.md'],
  );
});

test('exclude globs remove files and directories', async (t) => {
  const root = await makeTree(t, {
    'keep.txt': 'keep\n',
    'skip.txt': 'skip\n',
    'vendor/lib.js': 'const v = 1;\n',
  });
  const walked = await walkRepository(root, { exclude: ['skip.txt', 'vendor/**'] });
  assert.deepEqual(
    walked.files.map((file) => file.path),
    ['keep.txt'],
  );
});

test('the file limit stops the walk and reports it', async (t) => {
  const root = await makeTree(t, { 'a.txt': 'a\n', 'b.txt': 'b\n', 'c.txt': 'c\n' });
  const walked = await walkRepository(root, { maxFiles: 1 });
  assert.equal(walked.files.length, 1);
  assert.equal(walked.stats.limitReached, true);
  assert.ok(walked.diagnostics.some((entry) => entry.code === 'file-limit'));
});

test('a missing root throws a clear error', async () => {
  await assert.rejects(() => walkRepository('/definitely/not/a/real/path'), /not a directory|ENOENT/);
});

test('stats count directories and visited files', async (t) => {
  const root = await makeTree(t, { 'a.txt': 'a\n', 'src/b.txt': 'b\n' });
  const walked = await walkRepository(root);
  assert.ok(walked.stats.directoriesVisited >= 2);
  assert.equal(walked.stats.filesVisited, 2);
  assert.equal(walked.stats.filesScanned, 2);
});
