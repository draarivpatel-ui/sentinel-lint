import test from 'node:test';
import assert from 'node:assert/strict';
import { byRule, scanTree } from './helpers.mjs';
import { analyzeWorkflowPermissions, collectShellUnits, collectRunBlocks } from '../src/rules/actions.mjs';

const WORKFLOW = '.github/workflows/ci.yml';
const PINNED = '0123456789abcdef0123456789abcdef01234567';

function workflow(lines) {
  return { [WORKFLOW]: `${lines.join('\n')}\n` };
}

function baseWorkflow(extra = []) {
  return workflow([
    'name: ci',
    'on: push',
    'jobs:',
    '  test:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    ...extra,
  ]);
}

test('actions/missing-permissions accepts workflow level permissions', async (t) => {
  const result = await scanTree(
    t,
    workflow(['on: push', 'permissions:', '  contents: read', 'jobs:', '  test:', '    runs-on: ubuntu-latest', '    steps: []']),
  );
  assert.equal(byRule(result, 'actions/missing-permissions').length, 0);
});

test('actions/missing-permissions accepts job level permissions', async (t) => {
  const result = await scanTree(
    t,
    workflow(['on: push', 'jobs:', '  test:', '    runs-on: ubuntu-latest', '    permissions:', '      contents: read', '    steps: []']),
  );
  assert.equal(byRule(result, 'actions/missing-permissions').length, 0);
});

test('actions/missing-permissions flags a job with no permission coverage', async (t) => {
  const result = await scanTree(t, baseWorkflow(['      - run: echo ok']));
  const found = byRule(result, 'actions/missing-permissions');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 4);
  assert.match(found[0].message, /Job "test"/);
});

test('actions/missing-permissions reports each uncovered job', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: push',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps: []',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    steps: []',
    ]),
  );
  const found = byRule(result, 'actions/missing-permissions');
  assert.equal(found.length, 2);
  assert.deepEqual(found.map((finding) => finding.line), [3, 6]);
});

test('actions/missing-permissions covers only the job that declares permissions', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: push',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    permissions:',
      '      contents: read',
      '    steps: []',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    steps: []',
    ]),
  );
  const found = byRule(result, 'actions/missing-permissions');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /Job "release"/);
});

test('actions/missing-permissions ignores a step input named permissions', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'on: push',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: example/action@0123456789abcdef0123456789abcdef01234567',
      '        with:',
      '          permissions: nothing',
    ]),
  );
  assert.equal(byRule(result, 'actions/missing-permissions').length, 1);
});

test('actions/missing-permissions does not apply to composite action metadata', async (t) => {
  const result = await scanTree(t, {
    'action.yml': 'runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ok\n',
  });
  assert.equal(byRule(result, 'actions/missing-permissions').length, 0);
});

test('actions/missing-permissions accepts a quoted permissions key', async (t) => {
  const result = await scanTree(
    t,
    workflow(['on: push', '"permissions":', '  contents: read', 'jobs:', '  test:', '    steps: []']),
  );
  assert.equal(byRule(result, 'actions/missing-permissions').length, 0);
});

test('analyzeWorkflowPermissions reads quoted job names', () => {
  const analysis = analyzeWorkflowPermissions(['on: push', 'jobs:', '  "build-linux":', '    runs-on: ubuntu-latest']);
  assert.equal(analysis.jobs.length, 1);
  assert.equal(analysis.jobs[0].name, 'build-linux');
  assert.equal(analysis.jobs[0].hasPermissions, false);
});

test('analyzeWorkflowPermissions reads flow style permission mappings', () => {
  const analysis = analyzeWorkflowPermissions(['on: push', 'permissions: { contents: read }', 'jobs:', '  test:', '    steps: []']);
  assert.equal(analysis.topLevelPermissions, true);
});

test('actions/missing-permissions workflow without jobs reports the first content line', async (t) => {
  const result = await scanTree(t, workflow(['# comment', 'on: push']));
  const found = byRule(result, 'actions/missing-permissions');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 2);
});

test('actions/write-all-permissions still wins over missing permissions when write-all is explicit', async (t) => {
  const result = await scanTree(t, workflow(['on: push', 'permissions: write-all', 'jobs:', '  test:', '    steps: []']));
  assert.equal(byRule(result, 'actions/write-all-permissions').length, 1);
  assert.equal(byRule(result, 'actions/missing-permissions').length, 0);
});

test('actions/env-file-injection flags a pull request title written to GITHUB_ENV', async (t) => {
  const result = await scanTree(
    t,
    baseWorkflow(['      - run: echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"']),
  );
  const found = byRule(result, 'actions/env-file-injection');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /GITHUB_ENV/);
  assert.equal(found[0].severity, 'critical');
});

test('actions/env-file-injection flags an issue body written to GITHUB_PATH', async (t) => {
  const result = await scanTree(
    t,
    baseWorkflow(['      - run: echo "${{ github.event.issue.body }}" >> "$GITHUB_PATH"']),
  );
  const found = byRule(result, 'actions/env-file-injection');
  assert.equal(found.length, 1);
  assert.match(found[0].message, /GITHUB_PATH/);
});

test('actions/env-file-injection supports PowerShell environment syntax', async (t) => {
  const result = await scanTree(
    t,
    baseWorkflow(['      - run: echo "${{ github.head_ref }}" | Out-File -Append $env:GITHUB_ENV']),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 1);
});

test('actions/env-file-injection handles braced runner variables', async (t) => {
  const result = await scanTree(
    t,
    baseWorkflow(['      - run: echo "${{ github.head_ref }}" >> "${GITHUB_ENV}"']),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 1);
});

test('actions/env-file-injection follows an expression across lines', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  test:',
      '    steps:',
      '      - run: |',
      '          echo "${{',
      '            github.event.issue.title',
      '          }}" >> "$GITHUB_ENV"',
    ]),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 1);
});

test('actions/env-file-injection detects heredoc content written to GITHUB_ENV', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  test:',
      '    steps:',
      '      - run: |',
      '          cat <<EOF >> "$GITHUB_ENV"',
      '          TITLE=${{ github.event.pull_request.title }}',
      '          EOF',
    ]),
  );
  const found = byRule(result, 'actions/env-file-injection');
  assert.equal(found.length, 1);
  assert.equal(found[0].line, 6);
});

test('actions/env-file-injection follows shell continuation lines', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  test:',
      '    steps:',
      '      - run: |',
      '          echo "TITLE=${{ github.event.issue.title }}" \\',
      '            >> "$GITHUB_ENV"',
    ]),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 1);
});

test('actions/env-file-injection reports only one finding for several expressions in one write', async (t) => {
  const result = await scanTree(
    t,
    baseWorkflow(['      - run: echo "${{ github.head_ref }}-${{ github.event.issue.title }}" >> "$GITHUB_ENV"']),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 1);
});

test('actions/env-file-injection ignores trusted context in a runner file write', async (t) => {
  const result = await scanTree(
    t,
    baseWorkflow(['      - run: echo "SHA=${{ github.sha }}" >> "$GITHUB_ENV"']),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 0);
});

test('actions/env-file-injection ignores untrusted context printed only to stdout', async (t) => {
  const result = await scanTree(
    t,
    baseWorkflow(['      - run: echo "${{ github.event.issue.title }}"']),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 0);
  assert.equal(byRule(result, 'actions/script-injection').length, 1);
});

test('actions/env-file-injection does not merge independent commands in one run block', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  test:',
      '    steps:',
      '      - run: |',
      '          echo "SAFE=1" >> "$GITHUB_ENV"',
      '          echo "${{ github.event.issue.title }}"',
    ]),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 0);
});

test('actions/env-file-injection ignores a commented out expression', async (t) => {
  const result = await scanTree(
    t,
    workflow([
      'jobs:',
      '  test:',
      '    steps:',
      '      - run: |',
      '          # echo "${{ github.event.issue.title }}" >> "$GITHUB_ENV"',
      '          echo ok',
    ]),
  );
  assert.equal(byRule(result, 'actions/env-file-injection').length, 0);
});

test('actions/env-file-injection handles CRLF workflow input', async (t) => {
  const result = await scanTree(t, {
    [WORKFLOW]: 'jobs:\r\n  test:\r\n    steps:\r\n      - run: echo "${{ github.head_ref }}" >> "$GITHUB_ENV"\r\n',
  });
  assert.equal(byRule(result, 'actions/env-file-injection').length, 1);
});

test('collectShellUnits keeps heredoc bodies with the opening command', () => {
  const lines = ['jobs:', '  test:', '    steps:', '      - run: |', '          cat <<EOF >> "$GITHUB_ENV"', '          A=1', '          EOF'];
  const blocks = collectRunBlocks(lines);
  const units = collectShellUnits(lines, blocks[0]);
  assert.equal(units.length, 1);
  assert.match(units[0].text, /A=1/);
});

test('actions/unpinned-action accepts a configured trusted repository prefix', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  test:', '    steps:', '      - uses: example-org/example-action@v1']),
    { config: { trustedActions: ['example-org/example-action'] } },
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action trusted owner prefixes cover nested action paths', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  test:', '    steps:', '      - uses: example-org/repo/actions/deploy@main']),
    { config: { trustedActions: ['example-org'] } },
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action still flags an owner outside the allowlist', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  test:', '    steps:', '      - uses: other-org/other-action@v1']),
    { config: { trustedActions: ['example-org'] } },
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action matching is case insensitive for allowlist entries', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  test:', '    steps:', '      - uses: Example-Org/Example-Action@v1']),
    { config: { trustedActions: ['example-org'] } },
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 0);
});

test('actions/unpinned-action does not trust a prefix that is only a partial repository name', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  test:', '    steps:', '      - uses: example-org/example-action-extra@v1']),
    { config: { trustedActions: ['example-org/example-action'] } },
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});

test('actions/unpinned-action is unchanged when no allowlist is configured', async (t) => {
  const result = await scanTree(
    t,
    workflow(['jobs:', '  test:', '    steps:', '      - uses: example-org/example-action@v1']),
  );
  assert.equal(byRule(result, 'actions/unpinned-action').length, 1);
});
