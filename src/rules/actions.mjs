/**
 * Adapter: GitHub Actions workflow files.
 *
 * Workflow YAML is intentionally read line by line instead of through a full
 * YAML parser. Every rule here only needs indentation, keys and scalar values,
 * and a line based reader degrades gracefully on the partially malformed
 * workflows that real repositories contain.
 */

import { defineRule } from '../rule-api.mjs';

const WORKFLOW_GLOBS = ['.github/workflows/*.yml', '.github/workflows/*.yaml'];
const DOCS = 'docs/rules.md#';

function leadingIndent(line) {
  const match = /^[ \t]*/.exec(line);
  return match === null ? 0 : match[0].length;
}

function isCommentLine(line) {
  return /^\s*#/.test(line);
}

/**
 * Return the inclusive 1-based line ranges that hold `run:` script content.
 */
export function collectRunBlocks(lines) {
  const blocks = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^([ \t]*)(?:-[ \t]+)?run:[ \t]*(.*)$/.exec(lines[index]);
    if (match === null) continue;
    const baseIndent = match[1].length;
    const rest = match[2].trim();

    if (rest.startsWith('|') || rest.startsWith('>')) {
      let end = index;
      let cursor = index + 1;
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
      blocks.push({ startLine: index + 1, endLine: end + 1 });
      index = end;
      continue;
    }

    if (rest.length > 0 && !rest.startsWith('#')) {
      blocks.push({ startLine: index + 1, endLine: index + 1 });
    }
  }
  return blocks;
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

function expressionAt(line) {
  const results = [];
  const regex = /\$\{\{\s*(.*?)\s*\}\}/g;
  let match = regex.exec(line);
  while (match !== null) {
    results.push({ expression: match[1], index: match.index });
    match = regex.exec(line);
  }
  return results;
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
      for (let lineNumber = block.startLine; lineNumber <= block.endLine; lineNumber += 1) {
        const line = lines[lineNumber - 1] ?? '';
        if (isCommentLine(line)) continue;
        for (const candidate of expressionAt(line)) {
          if (!isUntrustedExpression(candidate.expression)) continue;
          const snippet =
            candidate.expression.length > 70
              ? `${candidate.expression.slice(0, 70)}...`
              : candidate.expression;
          findings.push({
            line: lineNumber,
            column: candidate.index + 1,
            message: `Untrusted expression "\${{ ${snippet} }}" is interpolated directly into a shell script. Assign it to env: and use the shell variable instead.`,
          });
        }
      }
    }
    return findings;
  },
});

export function parseUses(line) {
  const match = /^[ \t]*(?:-[ \t]+)?uses:[ \t]*(['"]?)([^'"\s#]+)\1/.exec(line);
  if (match === null) return null;
  return { spec: match[2], column: match[0].indexOf(match[2]) + 1 };
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
      const match = /permissions[ \t]*:[ \t]*(['"]?)write-all\1/.exec(line);
      if (match === null) continue;
      findings.push({
        line: index + 1,
        column: match.index + 1,
        message:
          'This workflow grants the GITHUB_TOKEN write-all permissions. Declare the smallest read and write scopes each job needs.',
      });
    }
    return findings;
  },
});

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
    const usesPullRequestTarget = lines.some((line) => {
      if (isCommentLine(line)) return false;
      if (/^[ \t]*(?:-[ \t]+)?['"]?pull_request_target['"]?[ \t]*:/.test(line)) return true;
      if (/^[ \t]*on[ \t]*:[ \t]*['"]?pull_request_target['"]?[ \t]*(?:#.*)?$/.test(line)) return true;
      if (/^[ \t]*on[ \t]*:[ \t]*\[[^\]]*\bpull_request_target\b/.test(line)) return true;
      if (/^[ \t]*-[ \t]+pull_request_target[ \t]*$/.test(line)) return true;
      return false;
    });
    if (!usesPullRequestTarget) return [];

    const findings = [];
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (isCommentLine(line)) continue;

      const refMatch = /\bref[ \t]*:[ \t]*\$\{\{[^}]*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)[^}]*\}\}/.exec(
        line,
      );
      if (refMatch !== null) {
        findings.push({
          line: index + 1,
          column: refMatch.index + 1,
          message:
            'pull_request_target runs with repository secrets, but this checkout uses the pull request head. Replace the trigger with pull_request, or isolate this checkout in an unprivileged workflow.',
        });
        continue;
      }

      const repoMatch = /\brepository[ \t]*:[ \t]*\$\{\{[^}]*github\.event\.pull_request\.head\.repo[^}]*\}\}/.exec(line);
      if (repoMatch !== null) {
        findings.push({
          line: index + 1,
          column: repoMatch.index + 1,
          message:
            'pull_request_target checks out the fork repository, so outside code can run with base repository secrets and a write scoped token.',
        });
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
]);
