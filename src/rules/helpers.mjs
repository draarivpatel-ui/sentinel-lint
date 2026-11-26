/**
 * Shared helpers for the built in rule pack.
 *
 * Nothing in this file performs I/O. Rules receive file text and return
 * findings, which keeps every rule deterministic and easy to unit test.
 */

import { getMember, parseJsonDocument } from '../json-pos.mjs';

const MCP_BASENAMES = new Set([
  'mcp.json',
  '.mcp.json',
  'claude_desktop_config.json',
  'mcp-config.json',
  'mcp_servers.json',
]);

/**
 * True for files that look like an MCP or Claude Desktop manifest.
 * Extension plus content sniff keeps renamed manifests discoverable without
 * treating every JSON file as an MCP config.
 */
export function isMcpConfigFile(file) {
  const name = (file.name ?? '').toLowerCase();
  if (MCP_BASENAMES.has(name)) return true;
  if (!name.endsWith('.json')) return false;
  return file.text.includes('"mcpServers"');
}

/**
 * Parse a document and return a discriminated result instead of throwing.
 */
export function tryParseJson(text) {
  try {
    return { ok: true, root: parseJsonDocument(text) };
  } catch (error) {
    return { ok: false, error };
  }
}

/**
 * Collect server objects from both documented manifest shapes.
 * @returns {{name: string, node: object, line: number, column: number}[]}
 */
export function getMcpServers(rootNode) {
  const servers = [];
  const seen = new Set();
  for (const containerKey of ['mcpServers', 'servers']) {
    const container = getMember(rootNode, containerKey);
    if (container === null || container.value.type !== 'object') continue;
    for (const entry of container.value.entries) {
      if (entry.value.type !== 'object') continue;
      const key = `${entry.key}|${entry.keyLine}:${entry.keyColumn}`;
      if (seen.has(key)) continue;
      seen.add(key);
      servers.push({ name: entry.key, node: entry.value, line: entry.keyLine, column: entry.keyColumn });
    }
  }
  return servers;
}

/**
 * 1-based line and column for a character offset.
 */
export function positionAt(text, offset) {
  let line = 1;
  let column = 1;
  const limit = Math.min(Math.max(offset, 0), text.length);
  for (let index = 0; index < limit; index += 1) {
    if (text.charCodeAt(index) === 10) {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

/**
 * String items from an array node paired with their positions.
 */
export function arrayStrings(arrayNode) {
  if (!arrayNode || arrayNode.type !== 'array') return [];
  const result = [];
  for (let index = 0; index < arrayNode.items.length; index += 1) {
    const item = arrayNode.items[index];
    result.push({
      index,
      value: item.type === 'string' ? item.value : null,
      node: item,
      line: item.line,
      column: item.column,
    });
  }
  return result;
}

/**
 * Values that are clearly not literal secrets: empty strings, environment
 * references, CLI style placeholders and obvious dummy values.
 */
export function isPlaceholderSecret(value) {
  if (typeof value !== 'string') return true;
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  if (/^\$(?:\{[A-Za-z_][A-Za-z0-9_]*(?::[^}]*)?\}|[A-Za-z_][A-Za-z0-9_]*)$/.test(trimmed)) return true;
  if (/^\$\{\{.*\}\}$/.test(trimmed)) return true;
  if (/^<[^>]*>$/.test(trimmed)) return true;
  if (/^(?:changeme|change-me|replace[-_ ]?me|your[-_ ].*|example|placeholder|redacted|dummy|none|null|todo|tbd|x{3,}|\*+)$/i.test(trimmed)) {
    return true;
  }
  return false;
}

/**
 * File paths and plain endpoints are not secrets even when they sit under an
 * API_KEY style variable name.
 */
export function looksLikePathOrEndpoint(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (/^https?:\/\//i.test(trimmed)) return true;
  if (/^(?:\.{0,2}\/|~\/|\/|[A-Za-z]:[\\/]|\\\\)/.test(trimmed)) return true;
  if (!/\s/.test(trimmed) && /\.(?:pem|key|crt|cer|json|ya?ml|txt|env|toml)$/i.test(trimmed)) return true;
  return false;
}

/**
 * Variable names that strongly suggest a credential.
 */
export function isSecretishName(name) {
  return /(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|bearer)/i.test(
    String(name),
  );
}

/**
 * Vendor token shapes. These are regexes over synthetic formats only; no real
 * credential is embedded anywhere in this package.
 */
export const TOKEN_PATTERNS = Object.freeze([
  {
    kind: 'AWS access key id',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    kind: 'GitHub token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
  },
  {
    kind: 'GitHub fine grained token',
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  {
    kind: 'Slack token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    kind: 'Stripe live key',
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g,
  },
  {
    kind: 'Google API key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    kind: 'npm token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  {
    kind: 'Anthropic API key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    kind: 'OpenAI style API key',
    regex: /\bsk-(?!ant-)[A-Za-z0-9]{32,}\b/g,
  },
  {
    kind: 'Hugging Face token',
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
  },
  {
    kind: 'private key block',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
]);

/**
 * True when a source line is clearly a documentation placeholder rather than
 * a committed credential.
 */
export function looksLikePlaceholderLine(lineText) {
  return /(example|placeholder|redacted|dummy|fake|sample|xxxx|your[-_ ]|insert[-_ ]|token[-_ ]here|key[-_ ]here|test[-_ ]only)/i.test(
    String(lineText),
  );
}

/**
 * Find all vendor token matches with positions, dropping overlaps.
 * @returns {{kind: string, line: number, column: number, index: number}[]}
 */
export function findTokenMatches(text) {
  const matches = [];
  for (const { kind, regex } of TOKEN_PATTERNS) {
    regex.lastIndex = 0;
    let match = regex.exec(text);
    while (match !== null) {
      matches.push({ kind, index: match.index, value: match[0] });
      if (match[0].length === 0) regex.lastIndex += 1;
      match = regex.exec(text);
    }
  }

  matches.sort((left, right) => left.index - right.index || right.value.length - left.value.length);

  const kept = [];
  let coveredUntil = -1;
  for (const match of matches) {
    if (match.index < coveredUntil) continue;
    kept.push(match);
    coveredUntil = match.index + match.value.length;
  }
  return kept;
}
