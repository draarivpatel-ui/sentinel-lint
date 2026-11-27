import test from 'node:test';
import assert from 'node:assert/strict';
import { byRule, scanTree } from './helpers.mjs';

const WORKFLOW = '.github/workflows/ci.yml';
const PINNED = '0123456789abcdef0123456789abcdef01234567';

function workflow(lines) {
  return { [WORKFLOW]: `${lines.join('\n')}\n` };
}

function actionsLock({
  workflowPath = WORKFLOW,
  key = 'example-org/example-action@v1.0.0',
  ref = 'v1.0.0',
  commit = `sha1-${PINNED}`,
} = {}) {
  return [
    "version: 'v0.0.3'",
    'workflows:',
    `  '${workflowPath}':`,
    `    - '${key}'`,
    'dependencies:',
    `  '${key}':`,
    `    ref: '${ref}'`,
    `    commit: '${commit}'`,
    '    owner_id: 1',
    '    repo_id: 2',
    '',
  ].join('\n');
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

test('actions/script-injection applies to composite action metadata', async (t) => {
  const result = await scanTree(t, {
    'action.yml': 'runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ inputs.name }}\n',
  });
  assert.equal(byRule(result, 'actions/script-injection').length, 1);
});

test('actions/script-injection handles CRLF workflow line endings', async (t) => {
  const result = await scanTree(t, {
    [WORKFLOW]: 'jobs:\r\n  b:\r\n    steps:\r\n      - run: echo ${{ github.head_ref }}\r\n',
  });
  assert.equal(byRule(result, 'actions/script-injection').length, 1);
});

test('actions/unpinned-action flags a ref that is not commit pinned', async (t) => {
  const result = await scanTree(t, workflow(['jobs:', '  b:', '    steps:', '      - uses: tj-actions/changed-files@v40']));
  const findings = byRule(result, 'actions/unpinned-action');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /not commit-pinned in the workflow or lockfile/);
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

test('actions/unpinned-action exempts self-repository references', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - uses: $/.github/actions/build']),
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action does not exempt a dollar sign inside a third-party path', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example$action']),
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action flags a missing version reference', async (t) => {
  const result = await scanTree(t, workflow(['jobs:', '  b:', '    steps:', '      - uses: some-org/some-action']));
  const findings = byRule(result, 'actions/unpinned-action');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /has no version reference/);
});

test('actions/unpinned-action accepts a dependency pinned by actions.lock', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example-action@v1.0.0']),
    '.github/workflows/actions.lock': actionsLock(),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action canonicalizes owner and repository casing in actions.lock', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: Example-Org/Example-Action@v1.0.0']),
    '.github/workflows/actions.lock': actionsLock(),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action preserves ref casing when comparing actions.lock keys', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example-action@V1.0.0']),
    '.github/workflows/actions.lock': actionsLock(),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action still fires when the lockfile omits the dependency', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example-action@v1.0.0']),
    '.github/workflows/actions.lock': actionsLock({ key: 'example-org/other-action@v1.0.0' }),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action still fires when the lockfile commit is invalid', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example-action@v1.0.0']),
    '.github/workflows/actions.lock': actionsLock({ commit: 'sha1-not-a-commit' }),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action ignores a missing or unsupported lockfile schema version', async (t) => {
  const unsupported = actionsLock().replace("version: 'v0.0.3'", "version: 'v0.0.4'");
  const missing = actionsLock().split('\n').slice(1).join('\n');
  for (const lockfile of [unsupported, missing]) {
    const result = await scanTree(t, {
      ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example-action@v1.0.0']),
      '.github/workflows/actions.lock': lockfile,
    });
    assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
  }
});

test('actions/unpinned-action ignores a lockfile entry for another workflow', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example-action@v1.0.0']),
    '.github/workflows/actions.lock': actionsLock({ workflowPath: '.github/workflows/release.yml' }),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action does not canonicalize action path casing in actions.lock', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/repo/Actions/deploy@v1']),
    '.github/workflows/actions.lock': actionsLock({ key: 'example-org/repo/actions/deploy@v1', ref: 'v1' }),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action reads a flow dependency list in actions.lock', async (t) => {
  const result = await scanTree(t, {
    ...workflow(['jobs:', '  b:', '    steps:', '      - uses: example-org/example-action@v1.0.0']),
    '.github/workflows/actions.lock': [
      "version: 'v0.0.3'",
      'workflows:',
      "  '.github/workflows/ci.yml': ['example-org/example-action@v1.0.0']",
      'dependencies:',
      "  'example-org/example-action@v1.0.0':",
      "    ref: 'v1.0.0'",
      `    commit: 'sha1-${PINNED}'`,
      '',
    ].join('\n'),
  });
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
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

test('actions/script-injection sees through whitespace before the run colon', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - run : echo ${{ github.head_ref }}']),
  );
  assert.equal(byRule(result, 'actions/script-injection').length, 1);
});

test('actions/script-injection sees through a quoted run key', async (t) => {
  for (const key of ['"run"', "'run'"]) {
    const result = await scanTree(
      t,
      workflow(['jobs:', '  b:', '    steps:', `      - ${key}: echo \${{ github.head_ref }}`]),
    );
    assert.equal(
      byRule(result, 'actions/script-injection').length,
      1,
      `expected a finding for ${key}`,
    );
  }
});

test('actions/script-injection scans a plain multiline run value', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  b:',
      '    steps:',
      '      - run:',
      '          echo ${{ github.head_ref }}',
    ]),
  );
  const findings = byRule(result, 'actions/script-injection');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 5);
});

test('actions/script-injection resolves a YAML alias to its anchored script', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'x-script: &deploy |',
      '  echo ${{ github.head_ref }}',
      'jobs:',
      '  b:',
      '    steps:',
      '      - run: *deploy',
    ]),
  );
  const findings = byRule(result, 'actions/script-injection');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
});

test('actions/script-injection scans an expression that spans lines', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  b:',
      '    steps:',
      '      - run: |',
      '          echo ${{',
      '            github.event.issue.title',
      '          }}',
    ]),
  );
  const findings = byRule(result, 'actions/script-injection');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 5);
});

test('actions/script-injection ignores an expression in a block indicator comment', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  b:',
      '    steps:',
      '      - run: | # ${{ github.head_ref }}',
      '          echo hi',
    ]),
  );
  assert.equal(byRule(result, 'actions/script-injection').length, 0);
});

test('actions/write-all-permissions is case and decoration insensitive', async (t) => {
  for (const value of [
    'permissions: Write-All',
    'permissions: WRITE-ALL',
    "permissions: 'write-all'",
    'permissions: &permissions write-all',
  ]) {
    const result = await scanTree(t, workflow([value, 'jobs:', '  b:', '    steps:']));
    assert.equal(
      byRule(result, 'actions/write-all-permissions').length,
      1,
      `expected a finding for ${value}`,
    );
  }
});

test('actions/unpinned-action sees through whitespace before the uses colon', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - uses : evil/action@v1']),
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action sees through a quoted uses key', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  b:', '    steps:', '      - "uses": evil/action@v1']),
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/pull-request-target-checkout reads a flow mapping trigger', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: {push: {}, pull_request_target: {}}',
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

test('actions/pull-request-target-checkout reads a commented list trigger', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on:',
      '  - push',
      '  - pull_request_target # risky',
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

test('actions/pull-request-target-checkout flags a refs/pull checkout', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: pull_request_target',
      'jobs:',
      '  b:',
      '    steps:',
      `      - uses: actions/checkout@${PINNED}`,
      '        with:',
      '          ref: refs/pull/${{ github.event.pull_request.number }}/merge',
    ]),
  );
  assert.equal(byRule(result, 'actions/pull-request-target-checkout').length, 1);
});

test('actions/pull-request-target-checkout flags a multiline ref expression', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: pull_request_target',
      'jobs:',
      '  b:',
      '    steps:',
      `      - uses: actions/checkout@${PINNED}`,
      '        with:',
      '          ref: ${{',
      '            github.event.pull_request.head.sha',
      '          }}',
    ]),
  );
  assert.equal(byRule(result, 'actions/pull-request-target-checkout').length, 1);
});

test('actions/pull-request-target-checkout allows a trusted ref', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: pull_request_target',
      'jobs:',
      '  b:',
      '    steps:',
      `      - uses: actions/checkout@${PINNED}`,
      '        with:',
      '          ref: ${{ github.sha }}',
    ]),
  );
  assert.equal(byRule(result, 'actions/pull-request-target-checkout').length, 0);
});
