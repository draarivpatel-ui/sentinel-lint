/**
 * Adapter: MCP client and Claude Desktop manifests.
 *
 * The rules understand both documented shapes:
 *   { "mcpServers": { "name": { "command": ..., "args": [...], "env": {...} } } }
 *   { "servers":    { "name": { "command": ..., "args": [...], "env": {...} } } }
 */

import path from 'node:path';
import { defineRule } from '../rule-api.mjs';
import {
  arrayStrings,
  findTokenMatches,
  getMcpServers,
  isMcpConfigFile,
  isPlaceholderSecret,
  isSecretishName,
  looksLikePathOrEndpoint,
  tryParseJson,
} from './helpers.mjs';
import { getEntries, getMember, stringValue } from '../json-pos.mjs';

const DOCS = 'docs/rules.md#';

function isTemplated(value) {
  return /\$\{|\{\{|%\(|%[A-Z_]+%/.test(value);
}

function serverName(server) {
  return server.name;
}

function sanitizeForMessage(value, limit = 48) {
  const flattened = String(value).replace(/[\r\n\t]/g, ' ');
  return flattened.length > limit ? `${flattened.slice(0, limit)}...` : flattened;
}

function isLoopback(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0';
}

function collectInsecureUrls(text) {
  const urls = [];
  const regex = /\bhttps?:\/\/[^\s"'`<>\\]+/gi;
  let match = regex.exec(text);
  while (match !== null) {
    urls.push(match[0]);
    match = regex.exec(text);
  }
  return urls;
}

function packageNameOf(spec) {
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    const at = spec.indexOf('@', 1);
    if (at === -1) return spec;
    return at > slash ? spec.slice(0, at) : spec;
  }
  const at = spec.indexOf('@');
  return at === -1 ? spec : spec.slice(0, at);
}

function isPinnedPackageSpec(spec) {
  const trimmed = String(spec).trim();
  if (trimmed.length === 0) return true;
  if (/^(?:https?:|git\+|file:|\.{1,2}\/|\/)/i.test(trimmed)) return true;

  let version;
  if (trimmed.startsWith('@')) {
    const at = trimmed.indexOf('@', 1);
    if (at === -1) return false;
    version = trimmed.slice(at + 1);
  } else {
    const at = trimmed.indexOf('@');
    if (at === -1) return false;
    version = trimmed.slice(at + 1);
  }

  if (version.length === 0) return false;
  return !/^(?:latest|next|beta|canary|nightly|\*)$/i.test(version);
}

function findNpxPackage(args) {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg.value === null) continue;
    const value = arg.value;
    if (value === '-p' || value === '--package') {
      const next = args[index + 1];
      return next !== undefined && next.value !== null ? { ...next, value: next.value } : null;
    }
    if (value.startsWith('--package=')) return { ...arg, value: value.slice('--package='.length) };
    if (value === '-c' || value === '--call') return null;
    if (value.startsWith('-')) continue;
    return arg;
  }
  return null;
}

const plaintextSecret = defineRule({
  id: 'mcp/plaintext-secret',
  title: 'MCP configuration stores a credential as a literal value',
  category: 'mcp',
  severity: 'critical',
  cwe: 'CWE-798',
  docsUrl: DOCS + 'mcpplaintext-secret',
  rationale:
    'MCP manifests are commonly committed and shared. Literal API keys, tokens and passwords in env, headers or URLs leak to everyone with repository read access and to anyone who copies the config.',
  fix: 'Replace the literal with an environment variable reference or a secret manager lookup, and rotate any credential that was committed.',
  match: isMcpConfigFile,
  check(ctx) {
    const parsed = tryParseJson(ctx.text);
    if (!parsed.ok) return [];

    const findings = [];
    for (const server of getMcpServers(parsed.root)) {
      const envEntry = getMember(server.node, 'env');
      for (const entry of getEntries(envEntry === null ? null : envEntry.value)) {
        const value = stringValue(entry.value);
        if (value === null || isPlaceholderSecret(value) || looksLikePathOrEndpoint(value) || isTemplated(value)) {
          continue;
        }
        const tokenKind = findTokenMatches(value)[0]?.kind ?? null;
        const secretName = isSecretishName(entry.key);
        if (!secretName && tokenKind === null) continue;
        findings.push({
          line: entry.value.line,
          column: entry.value.column,
          message: `MCP server "${serverName(server)}" sets env.${entry.key} to a literal value${tokenKind === null ? '' : ` that matches a ${tokenKind} pattern`}. Use a secret reference instead.`,
        });
      }

      const headersEntry = getMember(server.node, 'headers');
      for (const entry of getEntries(headersEntry === null ? null : headersEntry.value)) {
        if (!/(?:authorization|proxy-authorization|api-key|x-api-key|x-auth-token)/i.test(entry.key)) continue;
        const value = stringValue(entry.value);
        if (value === null || isPlaceholderSecret(value) || isTemplated(value)) continue;
        findings.push({
          line: entry.value.line,
          column: entry.value.column,
          message: `MCP server "${serverName(server)}" sends header "${entry.key}" with a literal credential. Load it from the environment at runtime.`,
        });
      }

      for (const field of ['url', 'httpUrl', 'serverUrl']) {
        const urlEntry = getMember(server.node, field);
        const value = urlEntry === null ? null : stringValue(urlEntry.value);
        if (value === null || isTemplated(value)) continue;
        let parsedUrl;
        try {
          parsedUrl = new URL(value);
        } catch {
          continue;
        }
        for (const [name, paramValue] of parsedUrl.searchParams) {
          if (!isSecretishName(name) || paramValue.length === 0 || isPlaceholderSecret(paramValue)) continue;
          findings.push({
            line: urlEntry.value.line,
            column: urlEntry.value.column,
            message: `MCP server "${serverName(server)}" embeds a credential in query parameter "${name}" of its ${field}. Query strings end up in logs and shell history.`,
          });
        }
      }

      const argsEntry = getMember(server.node, 'args');
      for (const arg of arrayStrings(argsEntry === null ? null : argsEntry.value)) {
        if (arg.value === null || isPlaceholderSecret(arg.value)) continue;
        const kind = findTokenMatches(arg.value)[0]?.kind ?? null;
        if (kind === null) continue;
        findings.push({
          line: arg.node.line,
          column: arg.node.column,
          message: `MCP server "${serverName(server)}" passes a ${kind} shaped value in argument ${arg.index + 1}. Move it to an environment variable.`,
        });
      }
    }

    return dedupe(findings);
  },
});

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.line}|${finding.column}|${finding.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const unpinnedNpx = defineRule({
  id: 'mcp/unpinned-npx-package',
  title: 'MCP server launches an unpinned npx package',
  category: 'mcp',
  severity: 'warning',
  cwe: 'CWE-1357',
  docsUrl: DOCS + 'mcpunpinned-npx-package',
  rationale:
    'npx without a version resolves the latest registry release on every launch. A compromised or hijacked release executes with the privileges of the MCP client and can read every tool input.',
  fix: 'Pin an exact version, for example "server-package@1.4.2", and update it deliberately.',
  match: isMcpConfigFile,
  check(ctx) {
    const parsed = tryParseJson(ctx.text);
    if (!parsed.ok) return [];

    const findings = [];
    for (const server of getMcpServers(parsed.root)) {
      const commandEntry = getMember(server.node, 'command');
      const command = commandEntry === null ? null : stringValue(commandEntry.value);
      if (command === null) continue;
      const base = path.basename(command.replace(/\\/g, '/')).toLowerCase();
      if (base !== 'npx' && base !== 'npx.cmd') continue;

      const argsEntry = getMember(server.node, 'args');
      const args = arrayStrings(argsEntry === null ? null : argsEntry.value);
      const pkg = findNpxPackage(args);
      if (pkg === null || isPinnedPackageSpec(pkg.value)) continue;

      findings.push({
        line: pkg.node.line,
        column: pkg.node.column,
        message: `MCP server "${serverName(server)}" runs npx with "${pkg.value}" and no exact version. A new upstream release can execute unreviewed code; pin "${packageNameOf(pkg.value)}@<version>".`,
      });
    }
    return findings;
  },
});

const shellMetacharacters = defineRule({
  id: 'mcp/shell-metacharacter-arg',
  title: 'MCP server argument contains shell metacharacters',
  category: 'mcp',
  severity: 'error',
  cwe: 'CWE-78',
  docsUrl: DOCS + 'mcpshell-metacharacter-arg',
  rationale:
    'An MCP server that forwards manifest arguments into a shell can be turned into command execution. Arguments containing separators, pipes, substitutions or newlines are a strong signal that a shell will interpret data as code.',
  fix: 'Pass literal arguments as an array without shell interpretation, or reject arguments that contain shell metacharacters.',
  match: isMcpConfigFile,
  check(ctx) {
    const parsed = tryParseJson(ctx.text);
    if (!parsed.ok) return [];

    const findings = [];
    for (const server of getMcpServers(parsed.root)) {
      const commandEntry = getMember(server.node, 'command');
      const command = commandEntry === null ? null : stringValue(commandEntry.value);
      if (command !== null) {
        const labels = metacharacterLabels(command);
        if (labels.length > 0) {
          findings.push({
            line: commandEntry.value.line,
            column: commandEntry.value.column,
            message: `MCP server "${serverName(server)}" command contains ${labels.join(', ')}; command strings must not be assembled from manifest data.`,
          });
        }
      }

      const argsEntry = getMember(server.node, 'args');
      for (const arg of arrayStrings(argsEntry === null ? null : argsEntry.value)) {
        if (arg.value === null) continue;
        const labels = metacharacterLabels(arg.value);
        if (labels.length === 0) continue;
        findings.push({
          line: arg.node.line,
          column: arg.node.column,
          message: `MCP server "${serverName(server)}" argument ${arg.index + 1} contains ${labels.join(', ')}. A shell would interpret that data as syntax.`,
        });
      }
    }
    return findings;
  },
});

function metacharacterLabels(value) {
  const labels = [];
  if (/;/.test(value)) labels.push('";"');
  if (/&&/.test(value)) labels.push('"&&"');
  if (/\|\|/.test(value)) labels.push('"||"');
  if (/\|/.test(value) && !/\|\|/.test(value)) labels.push('"|"');
  if (/`/.test(value)) labels.push('backtick substitution');
  if (/\$\(/.test(value)) labels.push('"$(" substitution');
  if (/[\r\n]/.test(value)) labels.push('a newline');
  return labels;
}

const broadFilesystemRoot = defineRule({
  id: 'mcp/broad-filesystem-root',
  title: 'MCP filesystem server is scoped to an entire filesystem root',
  category: 'mcp',
  severity: 'error',
  cwe: 'CWE-732',
  docsUrl: DOCS + 'mcpbroad-filesystem-root',
  rationale:
    'A filesystem MCP server rooted at / or ~ can read and often write every file the client user can reach, including SSH keys, browser profiles and other repositories.',
  fix: 'Scope the server to one project directory, for example "./workspace" or "~/code/my-app".',
  match: isMcpConfigFile,
  check(ctx) {
    const parsed = tryParseJson(ctx.text);
    if (!parsed.ok) return [];

    const findings = [];
    for (const server of getMcpServers(parsed.root)) {
      const argsEntry = getMember(server.node, 'args');
      for (const arg of arrayStrings(argsEntry === null ? null : argsEntry.value)) {
        if (arg.value === null || !isBroadRootArgument(arg.value)) continue;
        findings.push({
          line: arg.node.line,
          column: arg.node.column,
          message: `MCP server "${serverName(server)}" is given the broad root "${sanitizeForMessage(arg.value, 24)}". Restrict it to a project subdirectory.`,
        });
      }
    }
    return findings;
  },
});

const BROAD_ROOT = /^(?:\/|\/\*{1,2}|~[\\/]?\*{0,2}|[A-Za-z]:[\\/]?\*?|[\\/]{2,})$/;

function isBroadRootArgument(value) {
  const trimmed = value.trim();
  if (BROAD_ROOT.test(trimmed)) return true;
  const equals = trimmed.indexOf('=');
  if (equals > 0) return BROAD_ROOT.test(trimmed.slice(equals + 1).trim());
  return false;
}

const insecureRemoteUrl = defineRule({
  id: 'mcp/insecure-remote-url',
  title: 'MCP server connects over plaintext HTTP',
  category: 'mcp',
  severity: 'error',
  cwe: 'CWE-319',
  docsUrl: DOCS + 'mcpinsecure-remote-url',
  rationale:
    'Plain HTTP exposes MCP tool calls, tool results and authorization headers to any network observer. Remote MCP endpoints should use TLS.',
  fix: 'Use an https:// endpoint, or a local stdio server or Unix socket for local development.',
  match: isMcpConfigFile,
  check(ctx) {
    const parsed = tryParseJson(ctx.text);
    if (!parsed.ok) return [];

    const findings = [];
    for (const server of getMcpServers(parsed.root)) {
      const candidates = [];
      for (const field of ['url', 'httpUrl', 'serverUrl']) {
        const entry = getMember(server.node, field);
        const value = entry === null ? null : stringValue(entry.value);
        if (value !== null && /^http:\/\//i.test(value)) {
          candidates.push({ line: entry.value.line, column: entry.value.column, value });
        }
      }

      const argsEntry = getMember(server.node, 'args');
      for (const arg of arrayStrings(argsEntry === null ? null : argsEntry.value)) {
        if (arg.value === null) continue;
        for (const url of collectInsecureUrls(arg.value)) {
          // The collector also returns https URLs so the same argument can
          // be reported once; only plaintext HTTP is unsafe here.
          if (!/^http:\/\//i.test(url)) continue;
          candidates.push({ line: arg.node.line, column: arg.node.column, value: url });
        }
      }

      const seen = new Set();
      for (const candidate of candidates) {
        let parsedUrl;
        try {
          parsedUrl = new URL(candidate.value);
        } catch {
          continue;
        }
        if (isLoopback(parsedUrl.hostname)) continue;
        const key = `${candidate.line}:${candidate.column}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          line: candidate.line,
          column: candidate.column,
          message: `MCP server "${serverName(server)}" uses a non-TLS endpoint (${parsedUrl.protocol}//${parsedUrl.host}). Traffic and credentials can be read or modified in transit.`,
        });
      }
    }
    return findings;
  },
});

const invalidConfig = defineRule({
  id: 'mcp/invalid-config',
  title: 'MCP configuration is not valid JSON',
  category: 'mcp',
  severity: 'warning',
  docsUrl: DOCS + 'mcpinvalid-config',
  rationale:
    'A manifest that cannot be parsed may be silently ignored by the MCP client, or parsed differently by the client and the scanner, which hides every other finding for that file.',
  fix: 'Fix the reported syntax error and re-run the scanner. JSONC comments and trailing commas are accepted.',
  match: isMcpConfigFile,
  check(ctx) {
    const parsed = tryParseJson(ctx.text);
    if (parsed.ok) return [];
    return [
      {
        line: parsed.error.line ?? 1,
        column: parsed.error.column ?? 1,
        message: `MCP configuration is not valid JSON: ${parsed.error.message}.`,
      },
    ];
  },
});

export const mcpRules = Object.freeze([
  plaintextSecret,
  unpinnedNpx,
  shellMetacharacters,
  broadFilesystemRoot,
  insecureRemoteUrl,
  invalidConfig,
]);
