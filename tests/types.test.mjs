import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import * as api from '../src/index.mjs';

const TYPES_PATH = new URL('../types/index.d.ts', import.meta.url);
const PACKAGE_PATH = new URL('../package.json', import.meta.url);

async function declarationNames() {
  const text = await readFile(TYPES_PATH, 'utf8');
  const names = [...text.matchAll(/^export declare (?:function|const|class) (\w+)/gm)].map((match) => match[1]);
  return [...new Set(names)];
}

test('every declared value exists at runtime', async () => {
  const names = await declarationNames();
  assert.ok(names.length > 30);
  for (const name of names) {
    assert.ok(Object.hasOwn(api, name), `types/index.d.ts declares ${name} but the package does not export it`);
  }
});

test('every runtime export is declared', async () => {
  const names = new Set(await declarationNames());
  const runtime = Object.keys(api).sort();
  const missing = runtime.filter((name) => !names.has(name));
  assert.deepEqual(missing, []);
});

test('the declaration file is referenced by package.json', async () => {
  const manifest = JSON.parse(await readFile(PACKAGE_PATH, 'utf8'));
  assert.equal(manifest.types, './types/index.d.ts');
  assert.equal(manifest.exports['.'].types, './types/index.d.ts');
  await access(TYPES_PATH);
});

test('the declared entry points point at real files', async () => {
  const manifest = JSON.parse(await readFile(PACKAGE_PATH, 'utf8'));
  const entry = new URL(`../${manifest.main.replace(/^\.\//, '')}`, import.meta.url);
  await access(entry);
  const bin = new URL(`../${manifest.bin['sentinel-lint']}`, import.meta.url);
  await access(bin);
  assert.equal(path.basename(entry.pathname), 'index.mjs');
});
