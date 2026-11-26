import test from 'node:test';
import assert from 'node:assert/strict';
import { byRule, scanTree } from './helpers.mjs';

const TOKEN = `ghp_${'A'.repeat(36)}`;

test('repo/hardcoded-token flags a vendor token shape', async (t) => {
  const result = await scanTree(t, { 'src/config.js': `export const key = "${TOKEN}";\n` });
  const findings = byRule(result, 'repo/hardcoded-token');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 1);
  assert.equal(findings[0].severity, 'critical');
  assert.equal(findings[0].cwe, 'CWE-798');
});

test('repo/hardcoded-token flags a token in a JSON file', async (t) => {
  const result = await scanTree(t, { 'config.json': `{\n  "token": "${TOKEN}"\n}\n` });
  assert.equal(byRule(result, 'repo/hardcoded-token').length, 1);
});

test('repo/hardcoded-token ignores documentation placeholder lines', async (t) => {
  const result = await scanTree(t, { 'docs/setup.md': `Use a token like ${TOKEN} when testing, for example.\n` });
  assert.equal(byRule(result, 'repo/hardcoded-token').length, 0);
});

test('repo/hardcoded-token leaves MCP manifests to the mcp rules', async (t) => {
  const result = await scanTree(t, {
    'mcp.json': `{\n  "mcpServers": {\n    "one": {\n      "command": "node",\n      "env": { "SERVICE_TOKEN": "${TOKEN}" }\n    }\n  }\n}\n`,
  });
  assert.equal(byRule(result, 'repo/hardcoded-token').length, 0);
  assert.equal(byRule(result, 'mcp/plaintext-secret').length, 1);
});

test('repo/dangerous-eval flags eval', async (t) => {
  const result = await scanTree(t, { 'src/app.js': 'const value = eval(input);\n' });
  const findings = byRule(result, 'repo/dangerous-eval');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 1);
  assert.equal(findings[0].column, 15);
});

test('repo/dangerous-eval ignores comments', async (t) => {
  const result = await scanTree(t, { 'src/app.js': '// eval(input) was removed for security reasons\n' });
  assert.equal(byRule(result, 'repo/dangerous-eval').length, 0);
});

test('repo/dangerous-eval ignores string contents', async (t) => {
  const result = await scanTree(t, { 'src/app.js': 'const label = "eval(input)";\n' });
  assert.equal(byRule(result, 'repo/dangerous-eval').length, 0);
});

test('repo/dangerous-eval flags new Function', async (t) => {
  const result = await scanTree(t, { 'src/app.js': 'const fn = new Function("return 1");\n' });
  const findings = byRule(result, 'repo/dangerous-eval');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /new Function\(\)/);
});

test('repo/dangerous-html-sink flags innerHTML assignment', async (t) => {
  const result = await scanTree(t, { 'src/app.js': 'document.body.innerHTML = userInput;\n' });
  const findings = byRule(result, 'repo/dangerous-html-sink');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].cwe, 'CWE-79');
});

test('repo/dangerous-html-sink flags dangerouslySetInnerHTML in JSX', async (t) => {
  const result = await scanTree(t, {
    'src/View.jsx': 'export const View = (props) => <div dangerouslySetInnerHTML={{ __html: props.html }} />;\n',
  });
  assert.equal(byRule(result, 'repo/dangerous-html-sink').length, 1);
});

test('repo/dangerous-html-sink flags document.write', async (t) => {
  const result = await scanTree(t, { 'src/legacy.js': 'document.write(payload);\n' });
  assert.equal(byRule(result, 'repo/dangerous-html-sink').length, 1);
});

test('repo/child-process-injection flags an interpolated exec', async (t) => {
  const result = await scanTree(t, {
    'src/run.js': `import { exec } from 'node:child_process';\nexec(\`ls \${directory}\`);\n`,
  });
  const findings = byRule(result, 'repo/child-process-injection');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
  assert.equal(findings[0].cwe, 'CWE-78');
});

test('repo/child-process-injection flags string concatenation', async (t) => {
  const result = await scanTree(t, {
    'src/run.js': `import { exec } from 'node:child_process';\nexec('ls ' + directory);\n`,
  });
  assert.equal(byRule(result, 'repo/child-process-injection').length, 1);
});

test('repo/child-process-injection allows a constant command', async (t) => {
  const result = await scanTree(t, {
    'src/run.js': `import { exec } from 'node:child_process';\nexec('ls -la');\n`,
  });
  assert.equal(byRule(result, 'repo/child-process-injection').length, 0);
});

test('repo/child-process-injection allows an execFile argument array', async (t) => {
  const result = await scanTree(t, {
    'src/run.js': `import { execFile } from 'node:child_process';\nexecFile('ls', ['-la'], callback);\n`,
  });
  assert.equal(byRule(result, 'repo/child-process-injection').length, 0);
});

test('repo/missing-security-policy warns when no policy exists', async (t) => {
  const result = await scanTree(t, { 'package.json': '{"name": "demo"}\n' });
  const findings = byRule(result, 'repo/missing-security-policy');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, null);
  assert.equal(findings[0].severity, 'warning');
  assert.match(findings[0].message, /No SECURITY.md/);
});

test('repo/missing-security-policy points at the README when one exists', async (t) => {
  const result = await scanTree(t, {
    'README.md': '# demo\n',
    'package.json': '{"name": "demo"}\n',
  });
  const findings = byRule(result, 'repo/missing-security-policy');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'README.md');
});

test('repo/missing-security-policy is satisfied by a root SECURITY.md', async (t) => {
  const result = await scanTree(t, { 'SECURITY.md': '# Security\n', 'package.json': '{}\n' });
  assert.equal(byRule(result, 'repo/missing-security-policy').length, 0);
});

test('repo/missing-security-policy is satisfied by .github/SECURITY.md', async (t) => {
  const result = await scanTree(t, { '.github/SECURITY.md': '# Security\n', 'package.json': '{}\n' });
  assert.equal(byRule(result, 'repo/missing-security-policy').length, 0);
});

test('repo findings carry remediation metadata', async (t) => {
  const result = await scanTree(t, { 'src/app.js': 'eval(input);\n' });
  const finding = byRule(result, 'repo/dangerous-eval')[0];
  assert.equal(finding.category, 'repo');
  assert.equal(finding.docsUrl, 'docs/rules.md#repodangerous-eval');
  assert.equal(typeof finding.fix, 'string');
  assert.equal(finding.title, 'Code uses a dynamic code execution sink');
});
