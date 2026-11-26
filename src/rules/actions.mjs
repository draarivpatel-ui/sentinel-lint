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
const DOCS = 'docs/rules.md#';

function leadingIndent(line) {
  const match = /^[ \t]*/.exec(line);
  return match === null ? 0 : match[0].length;
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
    const lines = ctx.text.split('\n');
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

const unpinnedAction = defineRule({
  id: 'actions/unpinned-action',
  title: 'Third-party action is referenced by a mutable tag or branch',
  category: 'actions',
  severity: 'warning',
  cwe: 'CWE-1357',
  docsUrl: DOCS + 'actionsunpinned-action',
  rationale:
    'A tag such as v4 or a branch such as main can be moved by the action owner, and a compromised release then runs in your workflow with your secrets. A full commit SHA freezes the reviewed code. First party actions and local actions are exempt.',
  fix: 'Pin the action to a full 40 character commit SHA and let a dependency bot update it deliberately.',
  appliesTo: WORKFLOW_GLOBS,
  check(ctx) {
    const findings = [];
    const lines = ctx.text.split('\n');
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (isCommentLine(line)) continue;
      const parsed = parseUses(line);
      if (parsed === null) continue;
      const { spec, column } = parsed;
      if (spec.startsWith('./') || spec.startsWith('docker://')) continue;

      const at = spec.lastIndexOf('@');
      const pathPart = at === -1 ? spec : spec.slice(0, at);
      const owner = pathPart.split('/')[0].toLowerCase();
      if (FIRST_PARTY_ACTION_OWNERS.has(owner)) continue;

      const ref = at === -1 ? null : spec.slice(at + 1);
      if (ref !== null && isPinnedActionRef(ref)) continue;

      findings.push({
        line: index + 1,
        column,
        message:
          ref === null
            ? `Third-party action "${spec}" has no version reference; pin it to a full 40 character commit SHA.`
            : `Third-party action "${spec}" uses the mutable ref "${ref}"; pin it to a full 40 character commit SHA.`,
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
    const lines = ctx.text.split('\n');
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
    const lines = ctx.text.split('\n');
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

export const actionRules = Object.freeze([
  scriptInjection,
  unpinnedAction,
  writeAllPermissions,
  pullRequestTargetCheckout,
]);
