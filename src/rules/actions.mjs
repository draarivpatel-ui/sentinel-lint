/**
 * Adapter: GitHub Actions workflow files.
 *
 * Workflow YAML is intentionally read line by line instead of through a full
 * YAML parser. Every rule here only needs indentation, keys and scalar values,
 * and a line based reader degrades gracefully on the partially malformed
 * workflows that real repositories contain.
 */

import { defineRule } from '../rule-api.mjs';

const WORKFLOW_GLOBS = [
  '.github/workflows/*.yml',
  '.github/workflows/*.yaml',
  'action.yml',
  'action.yaml',
  '.github/actions/*/action.yml',
  '.github/actions/*/action.yaml',
];
const REPOSITORY_WORKFLOW_GLOBS = ['.github/workflows/*.yml', '.github/workflows/*.yaml'];
const DOCS = 'docs/rules.md#';

function leadingIndent(line) {
  const match = /^[ \t]*/.exec(line);
  return match === null ? 0 : match[0].length;
}

function workflowLines(text) {
  return String(text).split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
}

function isCommentLine(line) {
  return /^\s*#/.test(line);
}

// A mapping key spelled run, "run" or 'run', with optional whitespace before
// the colon. YAML permits all of those spellings and GitHub resolves them to
// the same step field.
const RUN_KEY_RE = /^([ \t]*)(?:-[ \t]+)?(?:(['"])run\2|run)[ \t]*:[ \t]*(.*)$/;

/**
 * Drop YAML node decorations such as anchors and tags from a scalar value.
 * @param {string} value
 * @returns {string}
 */
function stripNodeProperties(value) {
  let rest = String(value).trim();
  for (;;) {
    const match = /^(?:&[A-Za-z0-9_-]+|![^\s]+)[ \t]+/.exec(rest);
    if (match === null) return rest;
    rest = rest.slice(match[0].length);
  }
}

/**
 * True when a scalar value starts a literal or folded block scalar.
 * @param {string} rest
 * @returns {boolean}
 */
function isBlockIndicator(rest) {
  return /^[|>][-+0-9]*[ \t]*(?:#.*)?$/.test(rest);
}

/**
 * Last zero-based line index that still belongs to the indented block that
 * starts after `startIndex`.
 */
function findBlockEnd(lines, startIndex, baseIndent) {
  let end = startIndex;
  let cursor = startIndex + 1;
  while (cursor < lines.length) {
    const line = lines[cursor];
    if (line.trim() === '') {
      const next = lines[cursor + 1];
      if (next !== undefined && leadingIndent(next) > baseIndent) {
        cursor += 1;
        continue;
      }
      break;
    }
    if (leadingIndent(line) <= baseIndent) break;
    end = cursor;
    cursor += 1;
  }
  return end;
}

/**
 * Anchors whose value is expected to be a script. Aliases such as
 * "run: *deploy" are resolved by YAML before the runner sees the workflow,
 * so the anchored text must be scanned as if it appeared inline.
 */
function collectAnchoredBlocks(lines) {
  const anchors = new Map();
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (isCommentLine(line)) continue;
    const match = /(?:^|[\s:-])&([A-Za-z0-9_-]+)(?=\s|$)/.exec(line);
    if (match === null) continue;
    const name = match[1];
    const after = line.slice(match.index + match[0].length);
    const rest = stripNodeProperties(after);
    const baseIndent = leadingIndent(line);
    if (isBlockIndicator(rest)) {
      const end = findBlockEnd(lines, index, baseIndent);
      if (end > index) anchors.set(name, { startLine: index + 1, endLine: end + 1 });
    } else if (rest === '' || rest.startsWith('#')) {
      const end = findBlockEnd(lines, index, baseIndent);
      if (end > index) anchors.set(name, { startLine: index + 2, endLine: end + 1 });
    } else {
      anchors.set(name, { startLine: index + 1, endLine: index + 1 });
    }
  }
  return anchors;
}

/**
 * Return the inclusive 1-based line ranges that hold `run:` script content.
 *
 * Quoted keys, whitespace before the colon, plain multiline scalars and
 * aliases are all valid YAML that GitHub executes, so they are collected the
 * same way as the common block scalar form.
 */
export function collectRunBlocks(lines) {
  const anchors = collectAnchoredBlocks(lines);
  const blocks = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = RUN_KEY_RE.exec(lines[index]);
    if (match === null) continue;
    const baseIndent = match[1].length;
    const rest = stripNodeProperties(match[3] ?? '');

    if (isBlockIndicator(rest)) {
      const end = findBlockEnd(lines, index, baseIndent);
      blocks.push({ startLine: index + 1, endLine: end + 1 });
      index = end;
      continue;
    }

    if (rest === '' || rest.startsWith('#')) {
      // A plain multiline scalar: the script begins on the next line.
      const end = findBlockEnd(lines, index, baseIndent);
      if (end > index) {
        blocks.push({ startLine: index + 1, endLine: end + 1 });
        index = end;
      }
      continue;
    }

    const alias = /^\*([A-Za-z0-9_-]+)$/.exec(rest);
    if (alias !== null && anchors.has(alias[1])) {
      blocks.push(anchors.get(alias[1]));
      continue;
    }

    blocks.push({ startLine: index + 1, endLine: index + 1 });
  }
  return blocks;
}

/**
 * True when a line is a mapping key plus YAML node decorations whose value
 * is a literal or folded block indicator, for example "run: |" or
 * "x-script: &deploy >-". Such a line is metadata, not executable script.
 */
function isIndicatorLine(line) {
  const key = /^[ \t]*(?:-[ \t]+)?(?:[^:#]+:[ \t]*)?/.exec(line);
  const rest = key === null ? line : line.slice(key[0].length);
  return isBlockIndicator(stripNodeProperties(rest));
}

/**
 * First line inside a block that holds executable script text. An indicator
 * line is skipped so a "${{ ... }}" inside a trailing comment there is not
 * reported as an injection.
 */
function blockContentStart(lines, block) {
  const line = lines[block.startLine - 1] ?? '';
  return isIndicatorLine(line) ? block.startLine + 1 : block.startLine;
}

/**
 * 1-based line and column of a character offset inside a block of text.
 */
function positionIn(text, offset) {
  let line = 1;
  let lineStart = 0;
  for (let index = 0; index < offset; index += 1) {
    if (text.charCodeAt(index) === 10) {
      line += 1;
      lineStart = index + 1;
    }
  }
  return { line, column: offset - lineStart + 1 };
}

/**
 * True when a GitHub expression reads input that an outside contributor can
 * control. These values must never be interpolated into a shell script.
 */
export function isUntrustedExpression(expression) {
  const compact = String(expression).replace(/\s+/g, '');
  if (/\bgithub\.head_ref\b/.test(compact)) return true;
  if (/\bgithub\.event\.inputs\b/.test(compact)) return true;
  if (/\bgithub\.event\.client_payload\b/.test(compact)) return true;
  if (/\bgithub\.event\.[A-Za-z0-9_.\[\]*-]*\.(?:title|body|message|email|page_name|head_branch)\b/.test(compact)) {
    return true;
  }
  if (/\bgithub\.event\.[A-Za-z0-9_.\[\]*-]*\.head\.(?:ref|label)\b/.test(compact)) return true;
  if (/(?:^|[^\w.])inputs\.[A-Za-z0-9_-]+/.test(compact)) return true;
  return false;
}

const scriptInjection = defineRule({
  id: 'actions/script-injection',
  title: 'Untrusted GitHub context is interpolated into a shell script',
  category: 'actions',
  severity: 'critical',
  cwe: 'CWE-94',
  docsUrl: DOCS + 'actionsscript-injection',
  rationale:
    'Pull request titles, issue bodies, commit messages and dispatch inputs are attacker controlled. Interpolating them into run: before the shell runs turns data into commands, a well documented Actions injection class.',
  fix: 'Put the value in an env: variable and reference the shell variable ("$TITLE"), which the shell treats as data. Never place ${{ github.event... }} directly in run:.',
  appliesTo: WORKFLOW_GLOBS,
  check(ctx) {
    const lines = workflowLines(ctx.text);
    const blocks = collectRunBlocks(lines);
    if (blocks.length === 0) return [];

    const findings = [];
    for (const block of blocks) {
      const contentStart = blockContentStart(lines, block);
      if (contentStart > block.endLine) continue;
      const blockLines = lines.slice(contentStart - 1, block.endLine);
      const text = blockLines.join('\n');
      // Joined text lets an expression span lines inside a block scalar,
      // which GitHub accepts and a per line regex would miss.
      const regex = /\$\{\{\s*([\s\S]*?)\s*\}\}/g;
      let match = regex.exec(text);
      while (match !== null) {
        const position = positionIn(text, match.index);
        const lineText = blockLines[position.line - 1] ?? '';
        if (isCommentLine(lineText)) {
          match = regex.exec(text);
          continue;
        }
        const expression = match[1];
        if (isUntrustedExpression(expression)) {
          const snippet =
            expression.length > 70 ? `${expression.slice(0, 70)}...` : expression;
          findings.push({
            line: contentStart + position.line - 1,
            column: position.column,
            message: `Untrusted expression "\${{ ${snippet} }}" is interpolated directly into a shell script. Assign it to env: and use the shell variable instead.`,
          });
        }
        match = regex.exec(text);
      }
    }
    return findings;
  },
});

export function parseUses(line) {
  // YAML also accepts `uses :` and a quoted key; both resolve to the same
  // step field at runtime, so an unpinned action must not slip past here.
  const match = /^[ \t]*(?:-[ \t]+)?(?:(['"])uses\1|uses)[ \t]*:[ \t]*(['"]?)([^'"\s#]+)\2/.exec(
    line,
  );
  if (match === null) return null;
  return { spec: match[3], column: match[0].indexOf(match[3]) + 1 };
}

export function isPinnedActionRef(ref) {
  return /^[0-9a-fA-F]{40}$/.test(ref);
}

const FIRST_PARTY_ACTION_OWNERS = new Set(['actions', 'github']);

function configuredTrustedActions(config) {
  if (config === null || typeof config !== 'object' || !Array.isArray(config.trustedActions)) return [];
  return config.trustedActions.map((entry) => String(entry).toLowerCase());
}

function isTrustedActionPath(pathPart, trustedActions) {
  const normalized = String(pathPart).toLowerCase();
  for (const trusted of trustedActions) {
    if (normalized === trusted || normalized.startsWith(`${trusted}/`)) return true;
  }
  return false;
}

const ACTIONS_LOCK_PATH = '.github/workflows/actions.lock';
const LOCKFILE_COMMIT_RE = /^sha1-[0-9a-fA-F]{40}$/;

function stripYamlComment(text) {
  let quote = null;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote !== null) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quote === '"' && char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) {
        if (quote === "'" && text[index + 1] === "'") {
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '#' && (index === 0 || /\s/.test(text[index - 1]))) {
      return text.slice(0, index);
    }
  }
  return text;
}

function yamlScalar(raw) {
  const value = stripYamlComment(String(raw)).trim();
  if (value.length >= 2 && value[0] === "'" && value[value.length - 1] === "'") {
    return value.slice(1, -1).replace(/''/g, "'");
  }
  if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') {
    try {
      const parsed = JSON.parse(value);
      return typeof parsed === 'string' ? parsed : null;
    } catch {
      return null;
    }
  }
  return value;
}

function splitYamlMapping(line) {
  const indent = leadingIndent(line);
  let quote = null;
  let escaped = false;
  for (let index = indent; index < line.length; index += 1) {
    const char = line[index];
    if (quote !== null) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quote === '"' && char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) {
        if (quote === "'" && line[index + 1] === "'") {
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === ':' && (index + 1 === line.length || /\s/.test(line[index + 1]))) {
      return {
        indent,
        key: yamlScalar(line.slice(indent, index)),
        rawValue: line.slice(index + 1),
      };
    }
  }
  return null;
}

function yamlListItem(line) {
  const match = /^[ \t]*-[ \t]+(.*)$/.exec(line);
  return match === null ? null : yamlScalar(match[1]);
}

function parseYamlFlowSequence(raw) {
  const value = stripYamlComment(String(raw)).trim();
  if (!value.startsWith('[') || !value.endsWith(']')) return null;
  const inner = value.slice(1, -1).trim();
  if (inner === '') return [];
  const items = [];
  let start = 0;
  let quote = null;
  let escaped = false;
  for (let index = 0; index <= inner.length; index += 1) {
    const char = inner[index];
    const atEnd = index === inner.length;
    if (!atEnd && quote !== null) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quote === '"' && char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) {
        if (quote === "'" && inner[index + 1] === "'") {
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (!atEnd && (char === '"' || char === "'")) {
      quote = char;
      continue;
    }
    if (atEnd || char === ',') {
      const item = yamlScalar(inner.slice(start, index));
      if (item === null) return null;
      items.push(item);
      start = index + 1;
    }
  }
  return items;
}

function canonicalActionKey(spec) {
  const at = spec.lastIndexOf('@');
  const pathPart = at === -1 ? spec : spec.slice(0, at);
  const ref = at === -1 ? null : spec.slice(at + 1);
  const parts = pathPart.split('/');
  if (parts.length > 0) parts[0] = parts[0].toLowerCase();
  if (parts.length > 1) parts[1] = parts[1].toLowerCase();
  return `${parts.join('/')}${ref === null ? '' : `@${ref}`}`;
}

export function parseActionsLock(text) {
  const workflows = new Map();
  const dependencies = new Map();
  let version = null;
  let section = null;
  let currentWorkflow = null;
  let currentWorkflowIndent = -1;
  let currentDependency = null;
  let currentDependencyIndent = -1;

  for (const line of workflowLines(text)) {
    if (line.trim() === '' || isCommentLine(line)) continue;
    const indent = leadingIndent(line);
    if (indent === 0) {
      const mapping = splitYamlMapping(line);
      if (mapping !== null && mapping.key === 'version') {
        version = yamlScalar(mapping.rawValue);
      }
      section = mapping !== null && mapping.key === 'workflows'
        ? 'workflows'
        : mapping !== null && mapping.key === 'dependencies'
          ? 'dependencies'
          : null;
      currentWorkflow = null;
      currentWorkflowIndent = -1;
      currentDependency = null;
      currentDependencyIndent = -1;
      continue;
    }

    if (section === 'workflows') {
      const item = yamlListItem(line);
      if (item !== null && currentWorkflow !== null && indent > currentWorkflowIndent) {
        if (item.length > 0) workflows.get(currentWorkflow).push(canonicalActionKey(item));
        continue;
      }
      const mapping = splitYamlMapping(line);
      if (mapping === null || mapping.key === null || mapping.key === '') continue;
      const sequence = parseYamlFlowSequence(mapping.rawValue);
      const entries = sequence === null ? [] : sequence.filter((entry) => entry.length > 0).map(canonicalActionKey);
      workflows.set(mapping.key, entries);
      currentWorkflow = mapping.key;
      currentWorkflowIndent = mapping.indent;
      continue;
    }

    if (section === 'dependencies') {
      const mapping = splitYamlMapping(line);
      if (mapping === null || mapping.key === null || mapping.key === '') continue;
      const value = stripYamlComment(mapping.rawValue).trim();
      if (value === '') {
        currentDependency = canonicalActionKey(mapping.key);
        currentDependencyIndent = mapping.indent;
        if (!dependencies.has(currentDependency)) dependencies.set(currentDependency, { commit: null });
        continue;
      }
      if (
        currentDependency !== null &&
        indent > currentDependencyIndent &&
        mapping.key === 'commit'
      ) {
        dependencies.get(currentDependency).commit = yamlScalar(mapping.rawValue);
      }
    }
  }

  return { version, workflows, dependencies };
}

const actionsLockCache = new WeakMap();

function readActionsLock(ctx) {
  if (typeof ctx.read !== 'function') return null;
  let text = null;
  try {
    text = ctx.read(ACTIONS_LOCK_PATH);
  } catch {
    return null;
  }
  if (typeof text !== 'string') return null;
  const cacheKey = Array.isArray(ctx.files) ? ctx.files : null;
  if (cacheKey !== null) {
    const cached = actionsLockCache.get(cacheKey);
    if (cached !== undefined && cached.text === text) return cached.parsed;
  }
  const parsed = parseActionsLock(text);
  if (cacheKey !== null) actionsLockCache.set(cacheKey, { text, parsed });
  return parsed;
}

function isPinnedByActionsLock(spec, workflowPath, lock) {
  if (lock === null || lock.version !== 'v0.0.3') return false;
  const key = canonicalActionKey(spec);
  const workflowEntries = lock.workflows.get(workflowPath);
  if (!Array.isArray(workflowEntries) || !workflowEntries.includes(key)) return false;
  const dependency = lock.dependencies.get(key);
  return dependency !== undefined && LOCKFILE_COMMIT_RE.test(dependency.commit ?? '');
}

const unpinnedAction = defineRule({
  id: 'actions/unpinned-action',
  title: 'Third-party action is referenced by a mutable tag or branch',
  category: 'actions',
  severity: 'warning',
  cwe: 'CWE-1357',
  docsUrl: DOCS + 'actionsunpinned-action',
  rationale:
    'A tag such as v4 or a branch such as main can be moved by the action owner, and a compromised release then runs in your workflow with your secrets. A full commit SHA freezes the reviewed code. First party actions, workspace local actions, self-repository actions and references pinned by a workflow lockfile are exempt.',
  fix: 'Pin the action to a full 40 character commit SHA and let a dependency bot update it deliberately.',
  appliesTo: WORKFLOW_GLOBS,
  check(ctx) {
    const findings = [];
    const lines = workflowLines(ctx.text);
    const lock = readActionsLock(ctx);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (isCommentLine(line)) continue;
      const parsed = parseUses(line);
      if (parsed === null) continue;
      const { spec, column } = parsed;
      if (spec.startsWith('./') || spec.startsWith('$/') || spec.startsWith('docker://')) continue;

      const at = spec.lastIndexOf('@');
      const pathPart = at === -1 ? spec : spec.slice(0, at);
      const owner = pathPart.split('/')[0].toLowerCase();
      if (FIRST_PARTY_ACTION_OWNERS.has(owner)) continue;
      if (isTrustedActionPath(pathPart, configuredTrustedActions(ctx.config))) continue;

      const ref = at === -1 ? null : spec.slice(at + 1);
      if (ref !== null && isPinnedActionRef(ref)) continue;
      if (isPinnedByActionsLock(spec, ctx.path, lock)) continue;

      findings.push({
        line: index + 1,
        column,
        message:
          ref === null
            ? `Third-party action "${spec}" has no version reference and is not commit-pinned in the workflow or lockfile; pin it to a full 40 character commit SHA.`
            : `Third-party action "${spec}" uses ref "${ref}" but is not commit-pinned in the workflow or lockfile; pin it to a full 40 character commit SHA.`,
      });
    }
    return findings;
  },
});

const writeAllPermissions = defineRule({
  id: 'actions/write-all-permissions',
  title: 'Workflow grants write-all token permissions',
  category: 'actions',
  severity: 'error',
  cwe: 'CWE-272',
  docsUrl: DOCS + 'actionswrite-all-permissions',
  rationale:
    'GITHUB_TOKEN with write-all lets any compromised step push code, publish packages, modify releases or edit issues. Most jobs only need read access to their own repository.',
  fix: 'Declare least privilege, for example permissions: { contents: read }, and grant write scopes only on the job that needs them.',
  appliesTo: WORKFLOW_GLOBS,
  check(ctx) {
    const findings = [];
    const lines = workflowLines(ctx.text);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (isCommentLine(line)) continue;
      const match = /^([ \t]*)(?:-[ \t]+)?(?:(['"])permissions\2|permissions)[ \t]*:[ \t]*(.*)$/.exec(
        line,
      );
      if (match === null) continue;
      const value = stripNodeProperties(match[3] ?? '');
      if (value === '' || value.startsWith('#')) continue;
      const token = /^[^\s#]+/.exec(value);
      if (token === null) continue;
      let scalar = token[0];
      if (scalar.length >= 2) {
        const quote = scalar[0];
        if ((quote === '"' || quote === "'") && scalar[scalar.length - 1] === quote) {
          scalar = scalar.slice(1, -1);
        }
      }
      // Permission values are matched case-insensitively so "Write-All"
      // cannot bypass a lowercase comparison.
      if (scalar.toLowerCase() !== 'write-all') continue;
      findings.push({
        line: index + 1,
        column: match[1].length + 1,
        message:
          'This workflow grants the GITHUB_TOKEN write-all permissions. Declare the smallest read and write scopes each job needs.',
      });
    }
    return findings;
  },
});

export function hasPullRequestTarget(lines) {
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (isCommentLine(line)) continue;
    // Key under `on:` (block style), with or without quotes.
    if (/^[ \t]*(?:-[ \t]+)?['"]?pull_request_target['"]?[ \t]*:/.test(line)) return true;
    // `on: pull_request_target` scalar.
    if (/^[ \t]*on[ \t]*:[ \t]*['"]?pull_request_target['"]?[ \t]*(?:#.*)?$/.test(line)) return true;
    // Flow sequence, inline or on the line after `on:`.
    if (/^[ \t]*on[ \t]*:[ \t]*\[[^\]]*\bpull_request_target\b/.test(line)) return true;
    if (/^[ \t]*\[[^\]]*\bpull_request_target\b[^\]]*\][ \t]*(?:#.*)?$/.test(line)) return true;
    // Flow mapping such as `on: {push: {}, pull_request_target: {}}`.
    const flow = /^[ \t]*on[ \t]*:[ \t]*\{(.*)\}[ \t]*(?:#.*)?$/.exec(line);
    if (flow !== null && /\bpull_request_target\b/.test(flow[1])) return true;
    if (/^[ \t]*\{.*\bpull_request_target\b.*\}[ \t]*(?:#.*)?$/.test(line)) return true;
    // A flow collection that opens on one line and closes on a later one.
    if (/^[ \t]*on[ \t]*:[ \t]*[\[{][^\]}]*$/.test(line)) {
      for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
        if (/\bpull_request_target\b/.test(lines[cursor])) return true;
        if (/[\]}]/.test(lines[cursor])) break;
      }
    }
    // Block sequence entry, with an optional trailing comment.
    if (/^[ \t]*-[ \t]+['"]?pull_request_target['"]?[ \t]*(?:#.*)?$/.test(line)) return true;
  }
  return false;
}

const REF_VALUE_RE = /^([ \t]*)(?:-[ \t]+)?(?:(['"])ref\2|ref)[ \t]*:[ \t]*(.*)$/;
const REPOSITORY_VALUE_RE =
  /^([ \t]*)(?:-[ \t]+)?(?:(['"])repository\2|repository)[ \t]*:[ \t]*(.*)$/;

/**
 * Collect `key: value` entries, joining indented continuation lines so a
 * `${{ ... }}` expression that spans lines is still seen as one value.
 * @returns {{line: number, column: number, value: string}[]}
 */
function collectKeyValues(lines, pattern) {
  const results = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (isCommentLine(lines[index])) continue;
    const match = pattern.exec(lines[index]);
    if (match === null) continue;
    let value = match[3] ?? '';
    let cursor = index;
    const opens = () => (value.match(/\$\{\{/g) ?? []).length;
    const closes = () => (value.match(/\}\}/g) ?? []).length;
    while (opens() > closes() && cursor + 1 < lines.length) {
      cursor += 1;
      value += '\n' + lines[cursor];
    }
    results.push({ line: index + 1, column: match[1].length + 1, value });
    index = cursor;
  }
  return results;
}

/**
 * Flatten every GitHub expression in a value into one whitespace free
 * string so a multiline expression still matches the context patterns.
 */
function expressionText(value) {
  const parts = [];
  const regex = /\$\{\{([\s\S]*?)\}\}/g;
  let match = regex.exec(value);
  while (match !== null) {
    parts.push(match[1].replace(/\s+/g, ''));
    match = regex.exec(value);
  }
  return parts.join(' ');
}

const pullRequestTargetCheckout = defineRule({
  id: 'actions/pull-request-target-checkout',
  title: 'pull_request_target workflow checks out untrusted pull request code',
  category: 'actions',
  severity: 'critical',
  cwe: 'CWE-829',
  docsUrl: DOCS + 'actionspull-request-target-checkout',
  rationale:
    'pull_request_target runs with the base repository secrets and a write scoped token. Checking out the pull request head, or the fork repository, lets outside code run in that privileged context, which is a full compromise path.',
  fix: 'Use the pull_request trigger for code that needs to build the contribution, or split a privileged commenting job from an unprivileged build job that never uses secrets.',
  appliesTo: WORKFLOW_GLOBS,
  check(ctx) {
    const lines = workflowLines(ctx.text);
    if (!hasPullRequestTarget(lines)) return [];

    const findings = [];
    for (const entry of collectKeyValues(lines, REF_VALUE_RE)) {
      const expression = expressionText(entry.value);
      const headRef = /github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)/.test(
        expression,
      );
      const pullNumber = /github\.event\.pull_request\.number/.test(expression);
      const pullRef = /\brefs\/pull\//.test(entry.value) && expression.length > 0;
      if (!headRef && !pullNumber && !pullRef) continue;
      findings.push({
        line: entry.line,
        column: entry.column,
        message:
          'pull_request_target runs with repository secrets, but this checkout uses the pull request head. Replace the trigger with pull_request, or isolate this checkout in an unprivileged workflow.',
      });
    }

    for (const entry of collectKeyValues(lines, REPOSITORY_VALUE_RE)) {
      if (!/github\.event\.pull_request\.head\.repo/.test(expressionText(entry.value))) continue;
      findings.push({
        line: entry.line,
        column: entry.column,
        message:
          'pull_request_target checks out the fork repository, so outside code can run with base repository secrets and a write scoped token.',
      });
    }
    return findings;
  },
});

function mappingKey(line) {
  const match = /^([ \t]*)(?:(['"])(.*?)\2|([A-Za-z0-9_.-]+))[ \t]*:(?:[ \t]*(.*))?$/.exec(line);
  if (match === null) return null;
  return {
    indent: match[1].length,
    key: match[3] ?? match[4],
    column: match[1].length + 1,
  };
}

/**
 * Approximate the workflow and job permission blocks that matter for token
 * scope. This is deliberately structural rather than a text search: an input
 * named permissions under a step must not count as a job permissions block.
 */
export function analyzeWorkflowPermissions(inputLines) {
  const lines = inputLines.map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
  const jobs = [];
  let topLevelPermissions = false;
  let inJobs = false;
  let jobsIndent = -1;
  let jobIndent = null;
  let jobChildIndent = null;
  let currentJob = null;

  function finishJob() {
    if (currentJob !== null) jobs.push(currentJob);
    currentJob = null;
  }

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim() === '' || isCommentLine(line)) continue;
    const parsed = mappingKey(line);
    if (parsed === null) continue;
    const key = parsed.key.toLowerCase();

    if (parsed.indent === 0) {
      finishJob();
      if (key === 'permissions') topLevelPermissions = true;
      inJobs = key === 'jobs';
      jobsIndent = inJobs ? parsed.indent : -1;
      jobIndent = null;
      jobChildIndent = null;
      continue;
    }

    if (!inJobs) continue;
    if (parsed.indent <= jobsIndent) {
      finishJob();
      inJobs = false;
      jobIndent = null;
      jobChildIndent = null;
      continue;
    }

    if (jobIndent === null || parsed.indent === jobIndent) {
      finishJob();
      jobIndent = parsed.indent;
      jobChildIndent = null;
      currentJob = {
        name: parsed.key,
        line: index + 1,
        column: parsed.column,
        hasPermissions: false,
      };
      continue;
    }

    if (parsed.indent > jobIndent) {
      if (jobChildIndent === null) jobChildIndent = parsed.indent;
      if (parsed.indent === jobChildIndent && key === 'permissions' && currentJob !== null) {
        currentJob.hasPermissions = true;
      }
    }
  }

  finishJob();
  return { topLevelPermissions, jobs };
}

function firstContentLine(lines) {
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].trim() === '' || isCommentLine(lines[index])) continue;
    return { line: index + 1, column: (/^[ \t]*/.exec(lines[index]) ?? [''])[0].length + 1 };
  }
  return { line: 1, column: 1 };
}

const missingPermissions = defineRule({
  id: 'actions/missing-permissions',
  title: 'Workflow job has no explicit GITHUB_TOKEN permissions',
  category: 'actions',
  severity: 'warning',
  cwe: 'CWE-272',
  owasp: ['A05:2021-Security Misconfiguration'],
  docsUrl: DOCS + 'actionsmissing-permissions',
  rationale:
    'When neither the workflow nor a job declares permissions, the job inherits repository dependent defaults that may include write scopes. Explicit permissions make the token contract reviewable and prevent silent widening when repository defaults change.',
  fix: 'Add a workflow level permissions block such as contents: read, or give every uncovered job the smallest permissions block it needs.',
  appliesTo: REPOSITORY_WORKFLOW_GLOBS,
  check(ctx) {
    const lines = workflowLines(ctx.text);
    const analysis = analyzeWorkflowPermissions(lines);
    if (analysis.topLevelPermissions) return [];

    if (analysis.jobs.length === 0) {
      const first = firstContentLine(lines);
      return [
        {
          line: first.line,
          column: first.column,
          message:
            'This workflow declares no explicit permissions at workflow or job level. Add a least privilege permissions block instead of inheriting repository defaults.',
        },
      ];
    }

    return analysis.jobs
      .filter((job) => !job.hasPermissions)
      .map((job) => ({
        line: job.line,
        column: job.column,
        message: `Job "${job.name}" has no explicit permissions and no workflow level permissions block covers it. Declare least privilege for this job or the workflow.`,
      }));
  },
});

function continuationEnded(line) {
  return /\\[ \t]*$/.test(line);
}

function hasOpenExpression(text) {
  const opens = (text.match(/\$\{\{/g) ?? []).length;
  const closes = (text.match(/\}\}/g) ?? []).length;
  return opens > closes;
}

function heredocDelimiter(text) {
  const match = /<<-?[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_-]*)\1/.exec(text);
  return match === null ? null : match[2];
}

/**
 * Collect logical shell units inside a run block. Continuation lines and
 * heredoc bodies stay attached to the command that consumes them, which keeps
 * GITHUB_ENV writes precise without treating an entire multi-command run block
 * as one finding.
 */
export function collectShellUnits(lines, block) {
  const contentStart = blockContentStart(lines, block);
  if (contentStart > block.endLine) return [];
  const blockLines = lines.slice(contentStart - 1, block.endLine);
  const units = [];

  let index = 0;
  while (index < blockLines.length) {
    if (blockLines[index].trim() === '' || isCommentLine(blockLines[index])) {
      index += 1;
      continue;
    }

    const start = index;
    let cursor = index;
    const parts = [blockLines[cursor]];
    while (
      (continuationEnded(blockLines[cursor]) || hasOpenExpression(parts.join('\n'))) &&
      cursor + 1 < blockLines.length
    ) {
      cursor += 1;
      parts.push(blockLines[cursor]);
    }

    let text = parts.join('\n');
    const delimiter = heredocDelimiter(text);
    if (delimiter !== null) {
      while (cursor + 1 < blockLines.length) {
        cursor += 1;
        parts.push(blockLines[cursor]);
        if (blockLines[cursor].trim() === delimiter) break;
      }
      text = parts.join('\n');
    }

    units.push({
      startLine: contentStart + start,
      endLine: contentStart + cursor,
      text,
    });
    index = cursor + 1;
  }
  return units;
}

const GITHUB_FILE_TARGET_RE =
  /(?:\$\{GITHUB_ENV\}|\$GITHUB_ENV\b|\$\{GITHUB_PATH\}|\$GITHUB_PATH\b|\$env:GITHUB_ENV\b|\$env:GITHUB_PATH\b)/;

const envFileInjection = defineRule({
  id: 'actions/env-file-injection',
  title: 'Untrusted GitHub context is written to GITHUB_ENV or GITHUB_PATH',
  category: 'actions',
  severity: 'critical',
  cwe: 'CWE-94',
  owasp: ['A03:2021-Injection'],
  docsUrl: DOCS + 'actionsenv-file-injection',
  rationale:
    'GITHUB_ENV and GITHUB_PATH are command files consumed by the runner. Writing pull request or issue controlled text there can poison later steps, alter executable resolution and bypass the shell variable separation that makes direct script interpolation safe.',
  fix: 'Do not write attacker controlled values to runner command files. Validate them against a strict allowlist first, or pass trusted data through ordinary step outputs and env variables.',
  appliesTo: WORKFLOW_GLOBS,
  check(ctx) {
    const lines = workflowLines(ctx.text);
    const blocks = collectRunBlocks(lines);
    const findings = [];

    for (const block of blocks) {
      for (const unit of collectShellUnits(lines, block)) {
        const target = GITHUB_FILE_TARGET_RE.exec(unit.text);
        if (target === null) continue;
        const expressionRegex = /\$\{\{\s*([\s\S]*?)\s*\}\}/g;
        let match = expressionRegex.exec(unit.text);
        while (match !== null) {
          const position = positionIn(unit.text, match.index);
          const unitLines = unit.text.split('\n');
          const lineText = unitLines[position.line - 1] ?? '';
          if (!isCommentLine(lineText) && isUntrustedExpression(match[1])) {
            const targetName = /GITHUB_PATH/.test(target[0]) ? 'GITHUB_PATH' : 'GITHUB_ENV';
            const snippet = match[1].replace(/\s+/g, ' ').trim();
            findings.push({
              line: unit.startLine + position.line - 1,
              column: position.column,
              message: `Untrusted expression "\${{ ${snippet} }}" is written to ${targetName}. Runner command files must never receive pull request or issue controlled text.`,
            });
            break;
          }
          match = expressionRegex.exec(unit.text);
        }
      }
    }
    return findings;
  },
});

export const actionRules = Object.freeze([
  scriptInjection,
  unpinnedAction,
  writeAllPermissions,
  pullRequestTargetCheckout,
  missingPermissions,
  envFileInjection,
]);
