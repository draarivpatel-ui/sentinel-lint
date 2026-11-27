/**
 * Adapter: repository instructions consumed by AI coding agents.
 *
 * Agent instruction files are security sensitive because they are data for a
 * human reviewer but instructions for a tool using model. These rules look for
 * hidden Unicode that can disguise text and for high confidence instructions
 * that execute remote code, disable review or send credentials elsewhere.
 */

import { defineRule } from '../rule-api.mjs';
import { positionAt } from './helpers.mjs';

const DOCS = 'docs/rules.md#';
const AGENT_BASENAMES = new Set(['.cursorrules', 'claude.md', 'agents.md', 'skill.md']);
const LLM_PROMPT_INJECTION = 'LLM01:2023 Prompt Injection';

/**
 * True for the instruction file names that popular agent tools read
 * automatically. Basenames are matched at any depth; the Copilot file is
 * special because its documented location is inside .github.
 */
export function isAgentInstructionFile(file) {
  if (file === null || typeof file !== 'object') return false;
  const normalized = String(file.path ?? file.name ?? '').replace(/\\/g, '/').toLowerCase();
  const basename = normalized.slice(normalized.lastIndexOf('/') + 1);
  if (normalized === '.github/copilot-instructions.md') return true;
  return AGENT_BASENAMES.has(basename);
}

function isBidiControl(codePoint) {
  return (codePoint >= 0x202a && codePoint <= 0x202e) || (codePoint >= 0x2066 && codePoint <= 0x2069);
}

function isZeroWidthControl(codePoint) {
  return codePoint >= 0x200b && codePoint <= 0x200f;
}

function isTagCharacter(codePoint) {
  return codePoint >= 0xe0000 && codePoint <= 0xe007f;
}

function codePointBefore(text, index) {
  if (index <= 0) return -1;
  const code = text.charCodeAt(index - 1);
  if (code >= 0xdc00 && code <= 0xdfff && index >= 2) {
    const high = text.charCodeAt(index - 2);
    if (high >= 0xd800 && high <= 0xdbff) {
      return (high - 0xd800) * 0x400 + (code - 0xdc00) + 0x10000;
    }
  }
  return code;
}

function isEmojiish(codePoint) {
  return (
    codePoint === 0xfe0f ||
    (codePoint >= 0x2600 && codePoint <= 0x27bf) ||
    (codePoint >= 0x1f000 && codePoint <= 0x1faff)
  );
}

/**
 * A zero width joiner is legitimate in emoji sequences such as a person emoji
 * joined to a profession emoji. Elsewhere in an instruction file it is
 * invisible text and remains reportable.
 */
function isLikelyEmojiJoin(text, index) {
  const before = codePointBefore(text, index);
  const after = text.codePointAt(index + 1) ?? -1;
  return isEmojiish(before) && isEmojiish(after);
}

function unicodeName(codePoint) {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * Find hidden Unicode code points with their UTF-16 indices. The scanner never
 * stores these characters as literals in source; tests construct them
 * dynamically as well.
 */
export function hiddenUnicodeMatches(text) {
  const matches = [];
  for (let index = 0; index < text.length;) {
    const codePoint = text.codePointAt(index);
    const width = codePoint > 0xffff ? 2 : 1;
    if (isBidiControl(codePoint)) {
      matches.push({ index, codePoint, kind: 'bidi' });
    } else if (isTagCharacter(codePoint)) {
      matches.push({ index, codePoint, kind: 'tag' });
    } else if (codePoint === 0xfeff && index > 0) {
      matches.push({ index, codePoint, kind: 'bom' });
    } else if (isZeroWidthControl(codePoint)) {
      if (!(codePoint === 0x200d && isLikelyEmojiJoin(text, index))) {
        matches.push({ index, codePoint, kind: 'zero-width' });
      }
    }
    index += width;
  }
  return matches;
}

function findingsFor(matches, text, limit = 50) {
  return matches.slice(0, limit).map((match) => {
    const position = positionAt(text, match.index);
    return {
      line: position.line,
      column: position.column,
      endColumn: position.column + 1,
      codePoint: match.codePoint,
    };
  });
}

const bidiUnicodeOverride = defineRule({
  id: 'agent/bidi-unicode-override',
  title: 'Agent instructions contain a bidirectional Unicode override',
  category: 'agent',
  severity: 'critical',
  cwe: 'CWE-838',
  owasp: [LLM_PROMPT_INJECTION],
  docsUrl: DOCS + 'agentbidi-unicode-override',
  rationale:
    'Bidirectional override and isolate characters can make source text render in a different order than the order an agent reads. In an instruction file that is a Trojan Source path for hiding or rearranging commands.',
  fix: 'Remove all bidirectional override and isolate characters, then rewrite the surrounding instruction in plain text so the rendered and logical order match.',
  match: isAgentInstructionFile,
  check(ctx) {
    const matches = hiddenUnicodeMatches(ctx.text).filter((match) => match.kind === 'bidi');
    return findingsFor(matches, ctx.text).map((finding) => ({
      line: finding.line,
      column: finding.column,
      endColumn: finding.endColumn,
      message: `Hidden bidirectional control ${unicodeName(finding.codePoint)} can reorder what reviewers see while agents read the original byte order. Remove it and rewrite the instruction plainly.`,
    }));
  },
});

const invisibleZeroWidthUnicode = defineRule({
  id: 'agent/invisible-zero-width-unicode',
  title: 'Agent instructions contain invisible zero width Unicode',
  category: 'agent',
  severity: 'error',
  cwe: 'CWE-838',
  owasp: [LLM_PROMPT_INJECTION],
  docsUrl: DOCS + 'agentinvisible-zero-width-unicode',
  rationale:
    'Zero width characters, mid-file byte order marks and Unicode tag characters are invisible in most editors. They can hide a second instruction stream inside text that appears clean in review.',
  fix: 'Reveal the characters in a hex viewer, remove them, and keep only visible source text. Do not copy hidden characters into replacement text.',
  match: isAgentInstructionFile,
  check(ctx) {
    const matches = hiddenUnicodeMatches(ctx.text).filter((match) => match.kind !== 'bidi');
    return findingsFor(matches, ctx.text).map((finding) => ({
      line: finding.line,
      column: finding.column,
      endColumn: finding.endColumn,
      message: `Invisible Unicode character ${unicodeName(finding.codePoint)} can hide instructions that reviewers cannot see. Remove it from the agent instruction file.`,
    }));
  },
});

/**
 * Join shell style continuation lines in instruction text. The returned text
 * preserves enough ordering for pattern detection while keeping the first
 * line number for a useful finding location.
 */
export function logicalInstructionLines(text) {
  const lines = String(text).split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
  const entries = [];
  let pending = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmedEnd = line.replace(/[ \t]+$/, '');
    const continued = trimmedEnd.endsWith('\\');
    const segment = continued ? trimmedEnd.slice(0, -1) : line;

    if (pending === null) {
      const firstColumn = (line.match(/^[ \t]*/) ?? [''])[0].length + 1;
      pending = { line: index + 1, column: firstColumn, parts: [segment] };
    } else {
      pending.parts.push(segment.trim());
    }

    if (!continued) {
      entries.push({ line: pending.line, column: pending.column, text: pending.parts.join(' ') });
      pending = null;
    }
  }

  if (pending !== null) {
    entries.push({ line: pending.line, column: pending.column, text: pending.parts.join(' ') });
  }
  return entries;
}

/**
 * Blank single and double quoted string contents while preserving length.
 * Backticks are not blanked because Markdown uses them for executable inline
 * examples and shell uses them for command substitution.
 */
export function maskShellQuotes(text) {
  const chars = String(text).split('');
  let quote = null;
  let escaped = false;
  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index];
    if (quote !== null) {
      if (escaped) {
        chars[index] = ' ';
        escaped = false;
        continue;
      }
      if (char === '\\' && quote === '"') {
        chars[index] = ' ';
        escaped = true;
        continue;
      }
      if (char === quote) {
        quote = null;
        continue;
      }
      chars[index] = ' ';
      continue;
    }
    if (char === "'" || char === '"') quote = char;
  }
  return chars.join('');
}

function protectiveNegationBefore(text, index) {
  const prefix = text.slice(0, index).toLowerCase();
  return /\b(?:never|do not|don't|must not|should not|avoid)(?:\s+[a-z0-9_-]+){0,5}\s*$/.test(prefix);
}

const PIPE_TO_SHELL_RE = /\b(?:curl|wget)\b[\s\S]*?\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|fish|ksh)\b/i;
const SHELL_COMMAND_RE = /\b(?:sh|bash|zsh|dash|fish|ksh)\s+-c\b/i;
const DOWNLOADER_RE = /\b(?:curl|wget)\b/i;

function pipeToShellMatch(text) {
  const masked = maskShellQuotes(text);
  const direct = PIPE_TO_SHELL_RE.exec(masked);
  if (direct !== null) return { index: direct.index, kind: 'pipe' };
  const shell = SHELL_COMMAND_RE.exec(masked);
  if (shell !== null && DOWNLOADER_RE.test(text) && text.includes('|')) {
    return { index: shell.index, kind: 'shell-c' };
  }
  return null;
}

const DISABLE_SECURITY_RE =
  /\b(?:disable|turn off|switch off|skip|bypass|ignore|suppress)\s+(?:all\s+|any\s+|the\s+)?(?:security|safety|vulnerability|audit|code scanning|scanning|review)s?\b/i;
const AVOID_SECURITY_RE =
  /\b(?:do not|don't|never)\s+(?:run|perform|use|mention|report)\s+(?:any\s+|all\s+|the\s+)?(?:security\s+|safety\s+|vulnerability\s+)?(?:checks|scans|scanning|audits|review findings)\b/i;

const shellOverrideInstruction = defineRule({
  id: 'agent/shell-override-instruction',
  title: 'Agent instructions override review or execute a remote shell script',
  category: 'agent',
  severity: 'critical',
  cwe: 'CWE-829',
  owasp: [LLM_PROMPT_INJECTION],
  docsUrl: DOCS + 'agentshell-override-instruction',
  rationale:
    'A repository controlled instruction file can influence any agent that opens the project. Instructions that pipe network content into a shell or tell the agent to suppress security review turn that trust into code execution or silent compromise.',
  fix: 'Remove the instruction, review any agent sessions that used the repository, and replace installer pipes with a reviewed, pinned and checksum verified installation step.',
  match: isAgentInstructionFile,
  check(ctx) {
    const findings = [];
    for (const entry of logicalInstructionLines(ctx.text)) {
      const pipe = pipeToShellMatch(entry.text);
      if (pipe !== null && !protectiveNegationBefore(entry.text, pipe.index)) {
        findings.push({
          line: entry.line,
          column: entry.column + pipe.index,
          message:
            'Agent instructions pipe downloaded content into a shell. Pin and inspect an installer instead of executing network content directly.',
        });
        continue;
      }

      const avoid = AVOID_SECURITY_RE.exec(entry.text);
      if (avoid !== null) {
        findings.push({
          line: entry.line,
          column: entry.column + avoid.index,
          message:
            'Agent instructions tell the agent not to run or report security checks. Remove the override and keep independent verification intact.',
        });
        continue;
      }

      const disable = DISABLE_SECURITY_RE.exec(entry.text);
      if (disable !== null && !protectiveNegationBefore(entry.text, disable.index)) {
        findings.push({
          line: entry.line,
          column: entry.column + disable.index,
          message:
            'Agent instructions disable or bypass security review. Remove the override so generated changes remain independently checked.',
        });
      }
    }
    return findings;
  },
});

const TRANSPORT_RE = /\b(?:curl|wget)\b/i;
const DATA_FLAG_RE =
  /(?:^|\s)(?:-d\b|--data(?:-binary|-ascii|-raw|-urlencode)?\b|-F\b|--form\b|-T\b|--upload-file\b|--post-data\b|--post-file\b)/i;
const SENSITIVE_REFERENCE_RE =
  /(?:\$\{?[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY)[A-Za-z0-9_]*\}?|~\/\.ssh(?:\/|\b)|(?:^|[\s"'`=|])\.env(?:\b|$)|\bid_(?:rsa|ed25519|ecdsa)\b)/i;

const exfiltrationInstruction = defineRule({
  id: 'agent/exfiltration-instruction',
  title: 'Agent instructions send credentials or sensitive files to a remote endpoint',
  category: 'agent',
  severity: 'critical',
  cwe: 'CWE-200',
  owasp: [LLM_PROMPT_INJECTION],
  docsUrl: DOCS + 'agentexfiltration-instruction',
  rationale:
    'Instruction files are untrusted input to agents. A command that posts a token, an environment file or an SSH key to a remote endpoint is direct credential exfiltration even when wrapped in otherwise normal prose.',
  fix: 'Remove the command, rotate every credential the agent could access, and audit outbound access from any session that read the file.',
  match: isAgentInstructionFile,
  check(ctx) {
    const findings = [];
    for (const entry of logicalInstructionLines(ctx.text)) {
      const transport = TRANSPORT_RE.exec(entry.text);
      if (transport === null) continue;
      if (!DATA_FLAG_RE.test(entry.text) || !SENSITIVE_REFERENCE_RE.test(entry.text)) continue;
      if (protectiveNegationBefore(entry.text, transport.index)) continue;
      findings.push({
        line: entry.line,
        column: entry.column + transport.index,
        message:
          'Agent instructions upload a credential reference, environment file or SSH key with curl or wget. Remove the command and rotate the exposed credential material.',
      });
    }
    return findings;
  },
});

export const agentRules = Object.freeze([
  bidiUnicodeOverride,
  invisibleZeroWidthUnicode,
  shellOverrideInstruction,
  exfiltrationInstruction,
]);
