import test from 'node:test';
import assert from 'node:assert/strict';
import { byRule, scanTree } from './helpers.mjs';

const TOKEN = `ghp_${'A'.repeat(36)}`;

function manifest(serverBody) {
  return {
    'mcp.json': `{
  "mcpServers": {
    "github": {
${serverBody}
    }
  }
}
`,
  };
}

function envServer(name, value, extra = '') {
  return `      "command": "node",
      "args": ["server.js"],
${extra}      "env": {
        "${name}": "${value}"
      }`;
}

test('mcp/plaintext-secret flags a token shaped env value', async (t) => {
  const result = await scanTree(t, manifest(envServer('GITHUB_PERSONAL_ACCESS_TOKEN', TOKEN)));
  const findings = byRule(result, 'mcp/plaintext-secret');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 7);
  assert.equal(findings[0].severity, 'critical');
  assert.match(findings[0].message, /matches a GitHub token pattern/);
});

test('mcp/plaintext-secret flags a secretish env name with a literal value', async (t) => {
  const result = await scanTree(t, manifest(envServer('API_TOKEN', 'abc123def456')));
  assert.equal(byRule(result, 'mcp/plaintext-secret').length, 1);
});

test('mcp/plaintext-secret ignores environment references and placeholders', async (t) => {
  for (const value of ['${GITHUB_TOKEN}', '<your token here>', 'changeme']) {
    const result = await scanTree(t, manifest(envServer('GITHUB_TOKEN', value)));
    assert.equal(byRule(result, 'mcp/plaintext-secret').length, 0, value);
  }
});

test('mcp/plaintext-secret ignores file paths stored under secretish names', async (t) => {
  const result = await scanTree(t, manifest(envServer('API_KEY_PATH', '/etc/keys/api')));
  assert.equal(byRule(result, 'mcp/plaintext-secret').length, 0);
});

test('mcp/plaintext-secret ignores unremarkable env entries', async (t) => {
  const result = await scanTree(t, manifest(envServer('MODEL_NAME', 'gpt-4o-mini')));
  assert.equal(byRule(result, 'mcp/plaintext-secret').length, 0);
});

test('mcp/plaintext-secret flags an authorization header literal', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "headers": {
        "Authorization": "Bearer abcdef123456"
      }`),
  );
  const findings = byRule(result, 'mcp/plaintext-secret');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /sends header "Authorization"/);
});

test('mcp/plaintext-secret ignores a templated authorization header', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "headers": {
        "Authorization": "Bearer \${GITHUB_TOKEN}"
      }`),
  );
  assert.equal(byRule(result, 'mcp/plaintext-secret').length, 0);
});

test('mcp/plaintext-secret flags a credential in a URL query', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "url": "https://mcp.example.com/sse?api_key=abcd1234"`),
  );
  const findings = byRule(result, 'mcp/plaintext-secret');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /query parameter "api_key"/);
});

test('mcp/plaintext-secret flags a token passed as an argument', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "args": ["server.js", "--token", "${TOKEN}"]`),
  );
  const findings = byRule(result, 'mcp/plaintext-secret');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /argument 3/);
});

test('mcp/plaintext-secret reads the servers shape', async (t) => {
  const result = await scanTree(t, {
    'mcp.json': `{
  "servers": {
    "one": {
      "command": "node",
      "env": { "SERVICE_SECRET": "abcdef123456" }
    }
  }
}
`,
  });
  assert.equal(byRule(result, 'mcp/plaintext-secret').length, 1);
});

test('mcp/unpinned-npx-package flags an unversioned package', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "some-server"]`),
  );
  const findings = byRule(result, 'mcp/unpinned-npx-package');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /some-server@<version>/);
});

test('mcp/unpinned-npx-package allows an exact version', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "some-server@1.2.3"]`),
  );
  assert.equal(byRule(result, 'mcp/unpinned-npx-package').length, 0);
});

test('mcp/unpinned-npx-package flags an unversioned scoped package', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "@scope/server"]`),
  );
  assert.equal(byRule(result, 'mcp/unpinned-npx-package').length, 1);
});

test('mcp/unpinned-npx-package allows a versioned scoped package', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "@scope/server@2.0.0"]`),
  );
  assert.equal(byRule(result, 'mcp/unpinned-npx-package').length, 0);
});

test('mcp/unpinned-npx-package flags the latest tag', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "some-server@latest"]`),
  );
  assert.equal(byRule(result, 'mcp/unpinned-npx-package').length, 1);
});

test('mcp/unpinned-npx-package understands the package flag', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "-p", "some-server"]`),
  );
  assert.equal(byRule(result, 'mcp/unpinned-npx-package').length, 1);
});

test('mcp/unpinned-npx-package ignores other launchers', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "args": ["server.js"]`),
  );
  assert.equal(byRule(result, 'mcp/unpinned-npx-package').length, 0);
});

test('mcp/shell-metacharacter-arg flags a command separator', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "args": ["server.js", "value; rm -rf workspace"]`),
  );
  const findings = byRule(result, 'mcp/shell-metacharacter-arg');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /";"/);
});

test('mcp/shell-metacharacter-arg flags backtick substitution', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "args": ["server.js", "\`id\`"]`),
  );
  const findings = byRule(result, 'mcp/shell-metacharacter-arg');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /backtick/);
});

test('mcp/shell-metacharacter-arg allows plain arguments', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "args": ["server.js", "--workspace", "./project"]`),
  );
  assert.equal(byRule(result, 'mcp/shell-metacharacter-arg').length, 0);
});

test('mcp/broad-filesystem-root flags the filesystem root', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "server-filesystem@1.0.0", "/"]`),
  );
  const findings = byRule(result, 'mcp/broad-filesystem-root');
  assert.equal(findings.length, 1);
});

test('mcp/broad-filesystem-root flags an equals form root', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "server-filesystem@1.0.0", "--root=/"]`),
  );
  assert.equal(byRule(result, 'mcp/broad-filesystem-root').length, 1);
});

test('mcp/broad-filesystem-root allows a project subdirectory', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "npx",
      "args": ["-y", "server-filesystem@1.0.0", "/home/user/project"]`),
  );
  assert.equal(byRule(result, 'mcp/broad-filesystem-root').length, 0);
});

test('mcp/insecure-remote-url flags a plaintext endpoint', async (t) => {
  const result = await scanTree(t, manifest('      "url": "http://mcp.example.com/sse"'));
  const findings = byRule(result, 'mcp/insecure-remote-url');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /non-TLS endpoint/);
});

test('mcp/insecure-remote-url allows loopback endpoints', async (t) => {
  const result = await scanTree(t, manifest('      "url": "http://127.0.0.1:8080/sse"'));
  assert.equal(byRule(result, 'mcp/insecure-remote-url').length, 0);
});

test('mcp/insecure-remote-url allows TLS endpoints', async (t) => {
  const result = await scanTree(t, manifest('      "url": "https://mcp.example.com/sse"'));
  assert.equal(byRule(result, 'mcp/insecure-remote-url').length, 0);
});

test('mcp/insecure-remote-url flags a plaintext endpoint in arguments', async (t) => {
  const result = await scanTree(
    t,
    manifest(`      "command": "node",
      "args": ["server.js", "--url", "http://internal.example.com"]`),
  );
  assert.equal(byRule(result, 'mcp/insecure-remote-url').length, 1);
});

test('mcp/invalid-config flags a truncated manifest', async (t) => {
  const result = await scanTree(t, { 'mcp.json': '{ "mcpServers": {\n' });
  const findings = byRule(result, 'mcp/invalid-config');
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /not valid JSON/);
});

test('mcp/invalid-config accepts JSONC manifests', async (t) => {
  const result = await scanTree(t, {
    'mcp.json': `{
  // the stdio server used by the editor
  "mcpServers": {
    "one": {
      "command": "node",
      "args": ["server.js"],
    },
  },
}
`,
  });
  assert.equal(byRule(result, 'mcp/invalid-config').length, 0);
});
