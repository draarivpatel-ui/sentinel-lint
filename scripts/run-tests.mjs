import { readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const testsDir = fileURLToPath(new URL('../tests/', import.meta.url));
const entries = await readdir(testsDir, { withFileTypes: true });
const files = entries
  .filter((entry) => entry.isFile() && entry.name.endsWith('.test.mjs'))
  .map((entry) => path.join(testsDir, entry.name))
  .sort();

if (files.length === 0) {
  console.error('no test files found');
  process.exitCode = 1;
} else {
  const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
  if (result.error !== undefined) throw result.error;
  process.exitCode = result.status ?? 1;
}
