import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { BUILTIN_RULES, RULE_COUNT } from '../src/rules/index.mjs';

function read(relative) {
  return readFile(new URL(`../${relative}`, import.meta.url), 'utf8');
}

function slugify(heading) {
  return heading
    .toLowerCase()
    .replace(/[^a-z0-9 -]/g, '')
    .trim()
    .replace(/ +/g, '-');
}

test('the README lists every built in rule', async () => {
  const readme = await read('README.md');
  for (const rule of BUILTIN_RULES) {
    assert.ok(readme.includes(rule.id), `README.md does not mention ${rule.id}`);
  }
});

test('docs/rules.md has an anchor for every built in rule', async () => {
  const docs = await read('docs/rules.md');
  const anchors = new Set([...docs.matchAll(/^#{2,4} (.+)$/gm)].map((match) => slugify(match[1])));
  for (const rule of BUILTIN_RULES) {
    const anchor = rule.id.replace(/[^A-Za-z0-9-]/g, '').toLowerCase();
    assert.ok(anchors.has(anchor), `docs/rules.md needs a heading for ${rule.id}`);
  }
});

test('the README states the current rule count and test count', async () => {
  const readme = await read('README.md');
  assert.match(readme, new RegExp(`\\b${RULE_COUNT}\\b security rules`));
  const tests = /(\d{3}) tests/.exec(readme);
  assert.ok(tests !== null, 'README.md must state the exact test count');
  assert.ok(Number(tests[1]) >= 120);
});

test('the community files are present', async () => {
  for (const relative of [
    'CONTRIBUTING.md',
    'SECURITY.md',
    'LICENSE',
    '.github/workflows/ci.yml',
    '.github/ISSUE_TEMPLATE/new-rule.md',
    '.github/PULL_REQUEST_TEMPLATE.md',
    'GOOD_FIRST_ISSUES.md',
  ]) {
    const text = await read(relative);
    assert.ok(text.length > 100, `${relative} is too short`);
  }
});

test('the license is MIT', async () => {
  const license = await read('LICENSE');
  assert.match(license, /MIT License/);
  assert.match(license, /THE SOFTWARE IS PROVIDED "AS IS"/);
});

test('continuous integration runs the test suite without external services', async () => {
  const workflow = await read('.github/workflows/ci.yml');
  assert.match(workflow, /npm test|node --test/);
  assert.match(workflow, /ubuntu-latest/);
  assert.equal(workflow.includes('secrets.'), false);
});

test('GOOD_FIRST_ISSUES.md contains twenty self contained specifications', async () => {
  const text = await read('GOOD_FIRST_ISSUES.md');
  const numbers = [...text.matchAll(/^### (\d+)\. /gm)].map((match) => Number(match[1]));
  assert.deepEqual(numbers, Array.from({ length: 20 }, (_, index) => index + 1));
  const sections = text.split(/^### \d+\. /m).slice(1);
  assert.equal(sections.length, 20);
  for (const [index, section] of sections.entries()) {
    assert.match(section, /Acceptance criteria/, `issue ${index + 1} has no acceptance criteria`);
    assert.match(section, /Files/, `issue ${index + 1} does not name the files to touch`);
  }
});
