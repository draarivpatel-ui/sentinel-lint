import test from 'node:test';
import assert from 'node:assert/strict';
import { byRule, scanTree } from './helpers.mjs';

const WORKFLOW = '.github/workflows/ci.yml';
const PINNED = '0123456789abcdef0123456789abcdef01234567';

function workflow(lines) {
  return { [WORKFLOW]: `${lines.join('\n')}\n` };
}

test('actions/script-injection flags a pull request title in run:', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'name: greet',
      'on: pull_request',
      'jobs:',
      '  greet:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "${{ github.event.pull_request.title }}"',
    ]),
  );
  const findings = byRule(result, 'actions/script-injection');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 7);
  assert.equal(findings[0].column, 20);
  assert.equal(findings[0].severity, 'critical');
  assert.equal(findings[0].category, 'actions');
  assert.equal(findings[0].cwe, 'CWE-94');
});

test('actions/script-injection flags github.head_ref', async (t) => {
  const result = await scanTree(t, workflow(['jobs:', '  b:', '    steps:', '      - run: echo ${{ github.head_ref }}']));
  assert.equal(byRule(result, 'actions/script-injection').length, 1);
});

test('actions/script-injection flags a dispatch input', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - run: ./deploy.sh ${{ inputs.target }}']),
  );
  assert.equal(byRule(result, 'actions/script-injection').length, 1);
});

test('actions/script-injection allows trusted context', async (t) => {
  const result = await scanTree(t, workflow(['jobs:', '  b:', '    steps:', '      - run: echo ${{ github.sha }}']));
  assert.equal(byRule(result, 'actions/script-injection').length, 0);
});

test('actions/script-injection ignores commented out scripts', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      # run: echo ${{ github.head_ref }}']),
  );
  assert.equal(byRule(result, 'actions/script-injection').length, 0);
});

test('actions/script-injection scans block scalar bodies', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  b:',
      '    steps:',
      '      - run: |',
      '          echo build',
      '          echo "${{ github.head_ref }}"',
    ]),
  );
  const findings = byRule(result, 'actions/script-injection');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 6);
});

test('actions/script-injection only applies to workflow files', async (t) => {
  const result = await scanTree(t, {
    'ci.yaml': 'jobs:\n  b:\n    steps:\n      - run: echo ${{ github.head_ref }}\n',
  });
  assert.equal(byRule(result, 'actions/script-injection').length, 0);
});

test('actions/unpinned-action flags a mutable tag', async (t) => {
  const result = await scanTree(t, workflow(['jobs:', '  b:', '    steps:', '      - uses: tj-actions/changed-files@v40']));
  const findings = byRule(result, 'actions/unpinned-action');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /mutable ref "v40"/);
});

test('actions/unpinned-action allows a full commit SHA', async (t) => {
  const result = await scanTree(t, workflow(['jobs:', '  b:', '    steps:', `      - uses: tj-actions/changed-files@${PINNED}`]));
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action exempts first party actions', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - uses: actions/checkout@v4', '      - uses: github/codeql-action/init@v3']),
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action exempts local and docker references', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - uses: ./.github/actions/build', '      - uses: docker://alpine:3.19']),
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action flags a missing version reference', async (t) => {
  const result = await scanTree(t, workflow(['jobs:', '  b:', '    steps:', '      - uses: some-org/some-action']));
  const findings = byRule(result, 'actions/unpinned-action');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /has no version reference/);
});

test('actions/write-all-permissions flags write-all', async (t) => {
  const result = await scanTree(t, workflow(['permissions: write-all', 'jobs:', '  b:', '    steps:']));
  const findings = byRule(result, 'actions/write-all-permissions');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 1);
});

test('actions/write-all-permissions flags a quoted value', async (t) => {
  const result = await scanTree(t, workflow(['permissions: "write-all"', 'jobs:', '  b:', '    steps:']));
  assert.equal(byRule(result, 'actions/write-all-permissions').length, 1);
});

test('actions/write-all-permissions allows scoped permissions', async (t) => {
  const result = await scanTree(t, workflow(['permissions:', '  contents: read', '  pull-requests: write', 'jobs:', '  b:', '    steps:']));
  assert.equal(byRule(result, 'actions/write-all-permissions').length, 0);
});

test('actions/pull-request-target-checkout flags a head sha checkout', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'name: label',
      'on:',
      '  pull_request_target:',
      '    types: [opened]',
      'jobs:',
      '  label:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      `      - uses: actions/checkout@${PINNED}`,
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
    ]),
  );
  const findings = byRule(result, 'actions/pull-request-target-checkout');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 11);
});

test('actions/pull-request-target-checkout flags a fork repository checkout', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: pull_request_target',
      'jobs:',
      '  b:',
      '    steps:',
      `      - uses: actions/checkout@${PINNED}`,
      '        with:',
      '          repository: ${{ github.event.pull_request.head.repo.full_name }}',
    ]),
  );
  const findings = byRule(result, 'actions/pull-request-target-checkout');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 7);
});

test('actions/pull-request-target-checkout allows the pull_request trigger', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: pull_request',
      'jobs:',
      '  b:',
      '    steps:',
      `      - uses: actions/checkout@${PINNED}`,
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
    ]),
  );
  assert.equal(byRule(result, 'actions/pull-request-target-checkout').length, 0);
});

test('actions/pull-request-target-checkout detects the list trigger form', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: [push, pull_request_target]',
      'jobs:',
      '  b:',
      '    steps:',
      `      - uses: actions/checkout@${PINNED}`,
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
    ]),
  );
  assert.equal(byRule(result, 'actions/pull-request-target-checkout').length, 1);
});
