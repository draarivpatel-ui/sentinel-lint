import test from 'node:test';
import assert from 'node:assert/strict';
import {
  arrayStrings,
  findTokenMatches,
  getMcpServers,
  isMcpConfigFile,
  isPlaceholderSecret,
  isSecretishName,
  looksLikePathOrEndpoint,
  looksLikePlaceholderLine,
  positionAt,
  tryParseJson,
} from '../src/rules/helpers.mjs';
import {
  collectRunBlocks,
  hasPullRequestTarget,
  isPinnedActionRef,
  isUntrustedExpression,
  parseUses,
} from '../src/rules/actions.mjs';
import { maskHtmlComments, maskJsSource, readCallArgument } from '../src/rules/repo.mjs';

function fileOf(name, text = '') {
  return { name, text };
}

test('isMcpConfigFile recognises the documented manifest names', () => {
  assert.equal(isMcpConfigFile(fileOf('mcp.json')), true);
  assert.equal(isMcpConfigFile(fileOf('.mcp.json')), true);
  assert.equal(isMcpConfigFile(fileOf('claude_desktop_config.json')), true);
  assert.equal(isMcpConfigFile(fileOf('mcp-config.json')), true);
});

test('isMcpConfigFile sniffs renamed manifests by content', () => {
  assert.equal(isMcpConfigFile(fileOf('tooling.json', '{ "mcpServers": {} }')), true);
  assert.equal(isMcpConfigFile(fileOf('tooling.json', '{ "name": "x" }')), false);
  assert.equal(isMcpConfigFile(fileOf('tooling.json', '{ "\\u006dcpServers": {} }')), true);
});

test('isMcpConfigFile ignores other extensions', () => {
  assert.equal(isMcpConfigFile(fileOf('mcp.yaml', '"mcpServers": {}')), false);
});

test('isMcpConfigFile is case insensitive on the file name', () => {
  assert.equal(isMcpConfigFile(fileOf('MCP.JSON', '{"mcpServers": {}}')), true);
});

test('tryParseJson returns a success result for JSONC', () => {
  const parsed = tryParseJson('{ // note\n "a": 1, }');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.root.type, 'object');
});

test('tryParseJson returns a failure result instead of throwing', () => {
  const parsed = tryParseJson('{ nope }');
  assert.equal(parsed.ok, false);
  assert.equal(typeof parsed.error.message, 'string');
});

test('getMcpServers reads the mcpServers shape', () => {
  const parsed = tryParseJson('{"mcpServers": {"one": {"command": "node"}, "two": {"url": "https://x"}}}');
  const servers = getMcpServers(parsed.root);
  assert.deepEqual(
    servers.map((server) => server.name),
    ['one', 'two'],
  );
  assert.equal(servers[0].node.type, 'object');
});

test('getMcpServers reads the servers shape', () => {
  const parsed = tryParseJson('{"servers": {"solo": {"command": "node"}}}');
  assert.equal(getMcpServers(parsed.root).length, 1);
});

test('getMcpServers skips non-object entries and missing containers', () => {
  assert.deepEqual(getMcpServers(tryParseJson('{"mcpServers": {"x": 1}}').root), []);
  assert.deepEqual(getMcpServers(tryParseJson('{"other": {}}').root), []);
});

test('positionAt returns 1 based coordinates', () => {
  assert.deepEqual(positionAt('abc', 0), { line: 1, column: 1 });
  assert.deepEqual(positionAt('abc\ndef', 4), { line: 2, column: 1 });
  assert.deepEqual(positionAt('abc\ndef', 6), { line: 2, column: 3 });
});

test('arrayStrings returns only string items with positions', () => {
  const parsed = tryParseJson('["a", 2, "c"]');
  const items = arrayStrings(parsed.root);
  assert.deepEqual(
    items.map((item) => item.value),
    ['a', null, 'c'],
  );
  assert.equal(items[0].index, 0);
  assert.equal(items[0].node.column, 2);
});

test('arrayStrings returns an empty list for non-arrays', () => {
  assert.deepEqual(arrayStrings(null), []);
  assert.deepEqual(arrayStrings(tryParseJson('{}').root), []);
});

test('isPlaceholderSecret accepts environment references and obvious dummies', () => {
  for (const value of [
    '',
    '   ',
    '${GITHUB_TOKEN}',
    '$GITHUB_TOKEN',
    '${{ secrets.GITHUB_TOKEN }}',
    '<your key here>',
    'changeme',
    'YOUR_API_KEY',
    'redacted',
    'dummy',
    'xxxxxx',
  ]) {
    assert.equal(isPlaceholderSecret(value), true, value);
  }
});

test('isPlaceholderSecret rejects literal looking values', () => {
  assert.equal(isPlaceholderSecret('abc123def456'), false);
  assert.equal(isPlaceholderSecret('Bearer xyz'), false);
  assert.equal(isPlaceholderSecret(42), true);
});

test('looksLikePathOrEndpoint accepts paths and URLs', () => {
  assert.equal(looksLikePathOrEndpoint('https://api.example.com/v1'), true);
  assert.equal(looksLikePathOrEndpoint('/etc/service/token'), true);
  assert.equal(looksLikePathOrEndpoint('~/keys/service.pem'), true);
  assert.equal(looksLikePathOrEndpoint('C:\\keys\\service.key'), true);
  assert.equal(looksLikePathOrEndpoint('secret-value'), false);
});

test('isSecretishName matches credential vocabulary', () => {
  assert.equal(isSecretishName('GITHUB_TOKEN'), true);
  assert.equal(isSecretishName('api_key'), true);
  assert.equal(isSecretishName('apiKey'), true);
  assert.equal(isSecretishName('PASSWORD'), true);
  assert.equal(isSecretishName('MODEL_NAME'), false);
});

test('findTokenMatches finds a synthetic GitHub token', () => {
  const token = `ghp_${'A'.repeat(36)}`;
  const matches = findTokenMatches(`const key = "${token}";`);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].kind, 'GitHub token');
  assert.equal(matches[0].index, 13);
});

test('findTokenMatches finds a synthetic AWS access key id', () => {
  const token = `AKIA${'A'.repeat(16)}`;
  assert.equal(findTokenMatches(token)[0].kind, 'AWS access key id');
});

test('findTokenMatches prefers the Anthropic pattern over the generic one', () => {
  const token = `sk-ant-${'a'.repeat(24)}`;
  const matches = findTokenMatches(token);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].kind, 'Anthropic API key');
});

test('findTokenMatches detects private key blocks', () => {
  const matches = findTokenMatches('-----BEGIN RSA PRIVATE KEY-----\nMIIB');
  assert.equal(matches.length, 1);
  assert.equal(matches[0].kind, 'private key block');
});

test('findTokenMatches returns nothing for ordinary text', () => {
  assert.deepEqual(findTokenMatches('const model = "gpt-4o-mini";'), []);
});

test('looksLikePlaceholderLine recognises documentation lines', () => {
  assert.equal(looksLikePlaceholderLine('// example: ghp_xxx'), true);
  assert.equal(looksLikePlaceholderLine('const key = "ghp_abc";'), false);
});

test('collectRunBlocks reads a single line run', () => {
  const blocks = collectRunBlocks(['    run: echo hi']);
  assert.deepEqual(blocks, [{ startLine: 1, endLine: 1 }]);
});

test('collectRunBlocks reads a block scalar', () => {
  const lines = ['      - run: |', '          echo one', '          echo two', '      - name: after'];
  const blocks = collectRunBlocks(lines);
  assert.deepEqual(blocks, [{ startLine: 1, endLine: 3 }]);
});

test('collectRunBlocks ignores empty and comment values', () => {
  assert.deepEqual(collectRunBlocks(['    run:', '    run: # later']), []);
});

test('collectRunBlocks tolerates blank lines inside a block', () => {
  const lines = ['      - run: |', '          echo one', '', '          echo two'];
  assert.deepEqual(collectRunBlocks(lines), [{ startLine: 1, endLine: 4 }]);
});

test('isUntrustedExpression accepts attacker controlled contexts', () => {
  assert.equal(isUntrustedExpression('github.head_ref'), true);
  assert.equal(isUntrustedExpression('github.event.pull_request.title'), true);
  assert.equal(isUntrustedExpression('github.event.issue.body'), true);
  assert.equal(isUntrustedExpression('github.event.inputs.name'), true);
  assert.equal(isUntrustedExpression('github.event.client_payload.branch'), true);
  assert.equal(isUntrustedExpression('inputs.who'), true);
});

test('isUntrustedExpression rejects trusted contexts', () => {
  assert.equal(isUntrustedExpression('github.sha'), false);
  assert.equal(isUntrustedExpression('github.event.issue.user.login'), false);
  assert.equal(isUntrustedExpression('secrets.GITHUB_TOKEN'), false);
  assert.equal(isUntrustedExpression('matrix.node'), false);
});

test('parseUses reads a plain uses line', () => {
  assert.deepEqual(parseUses('      - uses: owner/repo@v1'), { spec: 'owner/repo@v1', column: 15 });
});

test('parseUses reads a quoted uses line', () => {
  assert.deepEqual(parseUses('    uses: "owner/repo@v1"'), { spec: 'owner/repo@v1', column: 12 });
});

test('parseUses returns null for other lines', () => {
  assert.equal(parseUses('    name: build'), null);
});

test('isPinnedActionRef accepts only full commit SHAs', () => {
  assert.equal(isPinnedActionRef('0123456789abcdef0123456789abcdef01234567'), true);
  assert.equal(isPinnedActionRef('ABCDEF0123456789abcdef0123456789ABCDEF01'), true);
  assert.equal(isPinnedActionRef('v4'), false);
  assert.equal(isPinnedActionRef('0123456789abcdef0123456789abcdef0123456'), false);
  assert.equal(isPinnedActionRef('main'), false);
});

test('maskJsSource blanks comments and preserves length', () => {
  const source = 'const a = 1; // eval(x)\n/* new Function() */\nconst b = 2;\n';
  const masked = maskJsSource(source);
  assert.equal(masked.length, source.length);
  assert.equal(masked.split('\n').length, source.split('\n').length);
  assert.equal(masked.includes('eval(x)'), false);
  assert.equal(masked.includes('new Function'), false);
  assert.equal(masked.includes('const a = 1;'), true);
});

test('maskJsSource keeps string contents by default', () => {
  const masked = maskJsSource('const a = "eval(x)";');
  assert.equal(masked.includes('eval(x)'), true);
});

test('maskJsSource can blank string contents', () => {
  const masked = maskJsSource('const a = "eval(x)";', { strings: true });
  assert.equal(masked.includes('eval(x)'), false);
  assert.equal(masked.length, 'const a = "eval(x)";'.length);
});

test('maskHtmlComments blanks comments and preserves length', () => {
  const source = '<p>hi</p><!-- eval(x) -->\n<p>bye</p>';
  const masked = maskHtmlComments(source);
  assert.equal(masked.length, source.length);
  assert.equal(masked.includes('eval(x)'), false);
  assert.equal(masked.includes('<p>hi</p>'), true);
});

test('readCallArgument returns the first argument', () => {
  const text = 'exec("ls", (a + b))';
  assert.equal(readCallArgument(text, 4), '"ls", (a + b)');
});

test('readCallArgument respects parentheses inside strings', () => {
  const text = 'exec("f(a)")';
  assert.equal(readCallArgument(text, 4), '"f(a)"');
});

test('readCallArgument stops at an unbalanced call', () => {
  const text = 'exec("open"';
  assert.equal(readCallArgument(text, 4), '"open"');
});

test('collectRunBlocks accepts whitespace before the run colon', () => {
  assert.deepEqual(collectRunBlocks(['    run : echo hi']), [{ startLine: 1, endLine: 1 }]);
});

test('collectRunBlocks accepts quoted run keys', () => {
  assert.deepEqual(collectRunBlocks(['      - "run": echo hi']), [{ startLine: 1, endLine: 1 }]);
  assert.deepEqual(collectRunBlocks(["      - 'run': |", '          echo hi']), [
    { startLine: 1, endLine: 2 },
  ]);
});

test('collectRunBlocks reads a plain multiline run value', () => {
  const lines = ['      - run:', '          echo one', '      - name: after'];
  assert.deepEqual(collectRunBlocks(lines), [{ startLine: 1, endLine: 2 }]);
});

test('collectRunBlocks resolves an alias to an anchored block', () => {
  const lines = ['x-run: &deploy |', '  echo hi', 'jobs:', '  steps:', '    - run: *deploy'];
  assert.deepEqual(collectRunBlocks(lines), [{ startLine: 1, endLine: 2 }]);
});

test('collectRunBlocks resolves an alias to an inline anchored scalar', () => {
  const lines = ['x-run: &deploy echo hi', 'jobs:', '  steps:', '    - run: *deploy'];
  assert.deepEqual(collectRunBlocks(lines), [{ startLine: 1, endLine: 1 }]);
});

test('hasPullRequestTarget reads flow and commented list forms', () => {
  assert.equal(hasPullRequestTarget(['on: {push: {}, pull_request_target: {}}']), true);
  assert.equal(hasPullRequestTarget(['on:', '  - push', '  - pull_request_target # risky']), true);
  assert.equal(hasPullRequestTarget(['on:', '  [push, pull_request_target]']), true);
  assert.equal(hasPullRequestTarget(['on: pull_request']), false);
  assert.equal(hasPullRequestTarget(['# on: pull_request_target']), false);
});

test('parseUses accepts whitespace before the colon and quoted keys', () => {
  assert.deepEqual(parseUses('      - uses : owner/repo@v1'), { spec: 'owner/repo@v1', column: 16 });
  assert.deepEqual(parseUses('      - "uses": owner/repo@v1'), {
    spec: 'owner/repo@v1',
    column: 17,
  });
  assert.deepEqual(parseUses("      - 'uses': 'owner/repo@v1'"), {
    spec: 'owner/repo@v1',
    column: 18,
  });
});

test('hasPullRequestTarget reads a multiline flow collection', () => {
  assert.equal(
    hasPullRequestTarget(['on: {', '  push: {},', '  pull_request_target: {}', '}']),
    true,
  );
  assert.equal(hasPullRequestTarget(['on: [', '  push,', '  pull_request_target', ']']), true);
});

test('collectRunBlocks keeps an anchored plain scalar that ends with a pipe', () => {
  const lines = ['x-run: &deploy', '  echo ${{ github.head_ref }} &deploy |', 'jobs:', '  - run: *deploy'];
  assert.deepEqual(collectRunBlocks(lines), [{ startLine: 2, endLine: 2 }]);
});
