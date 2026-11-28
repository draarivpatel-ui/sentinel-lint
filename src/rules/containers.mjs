/**
 * Adapter: Dockerfile and Compose configuration.
 *
 * Container files are read line by line for the same reason as workflow YAML:
 * the dangerous shapes are small, stable and still visible when the rest of a
 * hand written file is only approximately valid.
 */

import { defineRule } from '../rule-api.mjs';
import {
  imageRepositoryMatchesPrefix,
  parseImageReference,
} from '../image-ref.mjs';

const DOCS = 'docs/rules.md#';
const OWASP_MISCONFIGURATION = 'A05:2021-Security Misconfiguration';
const OWASP_INTEGRITY = 'A08:2021-Software and Data Integrity Failures';

function textLines(text) {
  return String(text).split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
}

/** True for Dockerfile, Dockerfile.prod and names ending in .dockerfile. */
export function isDockerfile(file) {
  const name = String(file?.name ?? '').toLowerCase();
  return name === 'dockerfile' || name.startsWith('dockerfile.') || name.endsWith('.dockerfile');
}

/** True for compose YAML files such as compose.yml or docker-compose.yaml. */
export function isComposeFile(file) {
  const name = String(file?.name ?? '').toLowerCase();
  return name.includes('compose') && (name.endsWith('.yml') || name.endsWith('.yaml'));
}

function isDockerWhitespace(char) {
  return /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/u.test(char);
}

function stripLeadingDockerWhitespace(line) {
  const text = String(line);
  let index = 0;
  while (index < text.length && isDockerWhitespace(text[index])) index += 1;
  return text.slice(index);
}

function isDockerCommentLine(line) {
  return stripLeadingDockerWhitespace(line).startsWith('#');
}

function isEmptyDockerContinuationLine(line) {
  return stripLeadingDockerWhitespace(line).length === 0;
}

function trimDockerContinuation(line, escapeToken) {
  let end = line.length;
  while (end > 0 && (line[end - 1] === ' ' || line[end - 1] === '\t')) end -= 1;
  if (end === 0 || line[end - 1] !== escapeToken) return { text: line, endOfLine: true };
  if (end >= 2 && line[end - 2] === escapeToken) return { text: line, endOfLine: true };
  return { text: line.slice(0, end - 1), endOfLine: false };
}

function readDockerParserDirective(line, state) {
  if (state.done) return false;
  if (!line.startsWith('#')) {
    state.done = true;
    return false;
  }

  const body = line.slice(1).replace(/^\s+/u, '');
  const match = /^([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$/u.exec(body);
  if (match === null || !['syntax', 'check', 'escape'].includes(match[1].toLowerCase())) {
    state.done = true;
    return false;
  }

  const name = match[1].toLowerCase();
  if (state.seen.has(name)) {
    state.reliable = false;
    return true;
  }
  state.seen.add(name);

  if (name !== 'escape') return true;
  const value = match[2];
  if (value !== '\\' && value !== '`') {
    state.reliable = false;
    return true;
  }
  state.escapeToken = value;
  return true;
}

function collectDockerInstructionResult(text) {
  const lines = textLines(text);
  if (lines.length > 0 && lines[0].startsWith('\ufeff')) lines[0] = lines[0].slice(1);
  const state = { done: false, seen: new Set(), escapeToken: '\\', reliable: true };
  const instructions = [];
  let index = 0;

  while (index < lines.length) {
    const raw = lines[index];
    const line = stripLeadingDockerWhitespace(raw);
    readDockerParserDirective(line, state);
    index += 1;

    if (line === '' || line.startsWith('#')) continue;

    const startLine = index;
    const column = raw.length - line.length + 1;
    let piece = trimDockerContinuation(line, state.escapeToken);
    if (piece.endOfLine && piece.text.length === 0) continue;

    let logical = piece.text;
    let endOfLine = piece.endOfLine;
    while (!endOfLine && index < lines.length) {
      const continuation = lines[index];
      index += 1;
      if (isDockerCommentLine(continuation)) continue;
      if (isEmptyDockerContinuationLine(continuation)) continue;
      piece = trimDockerContinuation(continuation, state.escapeToken);
      logical += piece.text;
      endOfLine = piece.endOfLine;
    }

    const trimmed = logical.trim();
    const match = /^([A-Za-z]+)(?:\s+([\s\S]*))?$/.exec(trimmed);
    if (match === null) continue;
    instructions.push({
      instruction: match[1].toUpperCase(),
      line: startLine,
      column,
      text: (match[2] ?? '').trim(),
    });
  }

  return { instructions, reliable: state.reliable, escapeToken: state.escapeToken };
}

/**
 * Collect Dockerfile instructions using Docker's continuation rules while
 * retaining each instruction's first line for findings.
 */
export function collectDockerInstructions(text) {
  return collectDockerInstructionResult(text).instructions;
}

function parseFromInstruction(text) {
  const tokens = text.trim().split(/\s+/).filter(Boolean);
  while (tokens.length > 0 && tokens[0].startsWith('--')) tokens.shift();
  if (tokens.length === 0) return { image: null, alias: null };
  let alias = null;
  if (tokens.length === 3 && tokens[1].toLowerCase() === 'as') {
    alias = tokens[2].toLowerCase();
  }
  return { image: tokens[0], alias };
}

function extractDockerBuilderFlags(line, escapeToken) {
  const flags = [];
  let index = 0;
  while (index < line.length) {
    while (index < line.length && isDockerWhitespace(line[index])) index += 1;
    if (index >= line.length) break;
    if (line[index] !== '-' || line[index + 1] !== '-') {
      return { flags, rest: line.slice(index) };
    }

    let word = '';
    let quote = null;
    while (index < line.length) {
      const char = line[index];
      if (quote !== null) {
        if (char === quote) {
          quote = null;
          index += 1;
          continue;
        }
        if (char === escapeToken) {
          if (index + 1 >= line.length) {
            index += 1;
            continue;
          }
          index += 1;
          word += line[index];
          index += 1;
          continue;
        }
        word += char;
        index += 1;
        continue;
      }

      if (isDockerWhitespace(char)) break;
      if (char === '"' || char === "'") {
        quote = char;
        index += 1;
        continue;
      }
      if (char === escapeToken) {
        if (index + 1 >= line.length) {
          index += 1;
          continue;
        }
        index += 1;
        word += line[index];
        index += 1;
        continue;
      }
      word += char;
      index += 1;
    }

    if (word === '--') return { flags, rest: line.slice(index) };
    if (word.length > 0) flags.push(word);
  }
  return { flags, rest: '' };
}

function copyFromValue(text, escapeToken) {
  const { flags } = extractDockerBuilderFlags(text, escapeToken);
  let value = null;
  let seen = false;
  let invalid = false;
  for (const flag of flags) {
    if (!flag.startsWith('--')) {
      invalid = true;
      continue;
    }
    const equal = flag.indexOf('=');
    const name = equal === -1 ? flag.slice(2) : flag.slice(2, equal);
    if (name !== 'from') continue;
    if (seen) invalid = true;
    seen = true;
    if (equal === -1 || equal === flag.length - 1) {
      invalid = true;
    } else {
      value = flag.slice(equal + 1);
    }
  }
  return invalid ? { value: null, invalid: true } : { value, invalid: false };
}

function copySourceIsEarlierStage(source, current) {
  if (!/^[0-9]+$/.test(source)) return false;
  const index = Number(source);
  return Number.isSafeInteger(index) && index >= 0 && index < current.index;
}

function collectStages(instructions, escapeToken = '\\') {
  const stages = [];
  let current = null;
  for (const instruction of instructions) {
    if (instruction.instruction === 'FROM') {
      const parsed = parseFromInstruction(instruction.text);
      current = {
        index: stages.length,
        line: instruction.line,
        column: instruction.column,
        image: parsed.image,
        alias: parsed.alias,
        users: [],
        hasRuntimeCommand: false,
        hasBuildCommand: false,
        hasRuntimeTrigger: false,
        hasShellConfiguration: false,
        hasNonArtifactInstruction: false,
        hasCrossStageCopy: false,
      };
      stages.push(current);
      continue;
    }
    if (current !== null && (instruction.instruction === 'ENTRYPOINT' || instruction.instruction === 'CMD')) {
      current.hasRuntimeCommand = true;
    }
    if (current !== null && instruction.instruction === 'RUN') {
      current.hasBuildCommand = true;
    }
    if (current !== null && (instruction.instruction === 'HEALTHCHECK' || instruction.instruction === 'ONBUILD')) {
      current.hasRuntimeTrigger = true;
    }
    if (current !== null && instruction.instruction === 'SHELL') {
      current.hasShellConfiguration = true;
    }
    if (current !== null && instruction.instruction === 'COPY') {
      const copyFrom = copyFromValue(instruction.text, escapeToken);
      if (copyFrom.value !== null && copySourceIsEarlierStage(copyFrom.value, current)) {
        current.hasCrossStageCopy = true;
      }
    }
    if (
      current !== null &&
      !['COPY', 'ADD', 'ARG', 'LABEL', 'USER'].includes(instruction.instruction)
    ) {
      current.hasNonArtifactInstruction = true;
    }
    if (instruction.instruction === 'USER' && current !== null) {
      current.users.push(instruction);
    }
  }
  return stages;
}

function cleanUserValue(text) {
  let value = String(text).trim();
  if (value.length >= 2) {
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value[value.length - 1] === quote) {
      value = value.slice(1, -1);
    }
  }
  return value.split(/\s+/)[0] ?? '';
}

function effectiveUser(stage) {
  if (stage.users.length === 0) return null;
  const instruction = stage.users[stage.users.length - 1];
  return { value: cleanUserValue(instruction.text), instruction, inherited: false };
}

function isRootUserValue(value) {
  const user = String(value).split(':')[0].trim().toLowerCase();
  return user === 'root' || user === '0';
}

function finalStageContext(text) {
  const collected = collectDockerInstructionResult(text);
  const stages = collectStages(collected.instructions, collected.escapeToken);
  if (stages.length === 0) return null;
  const stage = stages[stages.length - 1];
  return { stage, user: effectiveUser(stage), reliable: collected.reliable };
}

function hasNonRootTagComponent(tag) {
  return typeof tag === 'string' && tag.split(/[-_.]/).includes('nonroot');
}

function configuredNonRootImagePrefixes(config) {
  if (config === null || typeof config !== 'object' || !Array.isArray(config.trustedNonRootImages)) return [];
  return config.trustedNonRootImages.map((entry) => String(entry).trim()).filter((entry) => entry.length > 0);
}

function configuredArtifactOnlyScratchStages(config) {
  if (config === null || typeof config !== 'object' || !Array.isArray(config.trustedArtifactOnlyScratchStages)) return [];
  return config.trustedArtifactOnlyScratchStages.map((entry) => String(entry).toLowerCase());
}

function isKnownNonRootBase(image, configuredPrefixes = []) {
  const parsed = parseImageReference(image);
  if (!parsed.valid || parsed.digest !== null || !hasNonRootTagComponent(parsed.tag)) return false;
  const trusted = ['gcr.io/distroless/', ...configuredPrefixes];
  return trusted.some((prefix) => imageRepositoryMatchesPrefix(parsed.name, prefix));
}

function isArtifactOnlyScratchStage(stage, trustedStages = []) {
  if (stage.image !== 'scratch' || stage.alias === null || !trustedStages.includes(stage.alias)) return false;
  if (stage.hasRuntimeCommand || stage.hasBuildCommand || stage.hasRuntimeTrigger || stage.hasShellConfiguration) return false;
  if (stage.hasNonArtifactInstruction) return false;
  return stage.hasCrossStageCopy;
}

const missingNonRootUser = defineRule({
  id: 'container/missing-non-root-user',
  title: 'Final container image has no non-root USER instruction',
  category: 'container',
  severity: 'warning',
  cwe: 'CWE-250',
  owasp: [OWASP_MISCONFIGURATION],
  docsUrl: DOCS + 'containermissing-non-root-user',
  rationale:
    'Without a USER instruction the container process defaults to root unless the base image has a documented non-root contract. A root process inside the container makes kernel, volume and container breakout weaknesses much more damaging.',
  fix: 'Create or reuse a dedicated unprivileged account and end the final image stage with USER <name or uid>. Verify any inherited user when building FROM another stage.',
  match: isDockerfile,
  check(ctx) {
    const finalStage = finalStageContext(ctx.text);
    if (finalStage === null || finalStage.user !== null) return [];
    if (finalStage.reliable && isArtifactOnlyScratchStage(finalStage.stage, configuredArtifactOnlyScratchStages(ctx.config))) return [];
    if (finalStage.reliable && isKnownNonRootBase(finalStage.stage.image, configuredNonRootImagePrefixes(ctx.config))) return [];
    return [
      {
        line: finalStage.stage.line,
        column: finalStage.stage.column,
        message:
          'The final image stage never establishes a non-root USER. Add a dedicated unprivileged USER before the image entrypoint.',
      },
    ];
  },
});

const explicitRootUser = defineRule({
  id: 'container/explicit-root-user',
  title: 'Final container image explicitly runs as root',
  category: 'container',
  severity: 'error',
  cwe: 'CWE-250',
  owasp: [OWASP_MISCONFIGURATION],
  docsUrl: DOCS + 'containerexplicit-root-user',
  rationale:
    'USER root or uid 0 is an explicit choice to run the final image with full container privileges. That choice removes an important layer of containment for application compromise and mounted file access.',
  fix: 'Use a dedicated non-root account or numeric non-zero uid in the final stage. If a build step needs root, switch back to an unprivileged USER afterward.',
  match: isDockerfile,
  check(ctx) {
    const finalStage = finalStageContext(ctx.text);
    if (finalStage === null || finalStage.user === null || !isRootUserValue(finalStage.user.value)) return [];
    return [
      {
        line: finalStage.user.instruction.line,
        column: finalStage.user.instruction.column,
        message: `The final image effective USER is "${finalStage.user.value}". Use a dedicated non-root account instead.`,
      },
    ];
  },
});

function maskShellQuotes(text) {
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

const PIPE_TO_SHELL_RE = /\b(?:curl|wget)\b[\s\S]*?\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|fish|ksh)\b/i;
const SHELL_COMMAND_RE = /\b(?:sh|bash|zsh|dash|fish|ksh)\s+-c\b/i;
const DOWNLOADER_RE = /\b(?:curl|wget)\b/i;

function pipeToShell(text) {
  const masked = maskShellQuotes(text);
  if (PIPE_TO_SHELL_RE.test(masked)) return true;
  return SHELL_COMMAND_RE.test(masked) && DOWNLOADER_RE.test(text) && text.includes('|');
}

const curlPipeShell = defineRule({
  id: 'container/curl-pipe-shell',
  title: 'Image build pipes downloaded content directly into a shell',
  category: 'container',
  severity: 'critical',
  cwe: 'CWE-494',
  owasp: [OWASP_INTEGRITY],
  docsUrl: DOCS + 'containercurl-pipe-shell',
  rationale:
    'A curl or wget pipe into sh executes whatever the network or a compromised host returns at build time. The result is baked into the image and can reach every runtime secret mounted into the container.',
  fix: 'Download a pinned artifact, verify a cryptographic checksum or signature, then execute a reviewed local file. Prefer a package manager lockfile where possible.',
  match: isDockerfile,
  check(ctx) {
    const findings = [];
    for (const instruction of collectDockerInstructions(ctx.text)) {
      if (instruction.instruction !== 'RUN' || !pipeToShell(instruction.text)) continue;
      findings.push({
        line: instruction.line,
        column: instruction.column,
        message:
          'RUN pipes curl or wget output into a shell. Download a pinned artifact, verify it, and execute a reviewed local installer instead.',
      });
    }
    return findings;
  },
});

const remoteAdd = defineRule({
  id: 'container/remote-add',
  title: 'Dockerfile ADD fetches a remote HTTP URL',
  category: 'container',
  severity: 'warning',
  cwe: 'CWE-494',
  owasp: [OWASP_INTEGRITY],
  docsUrl: DOCS + 'containerremote-add',
  rationale:
    'ADD with a remote URL hides a network fetch inside image build metadata and historically bypassed the review expectations of COPY. Without a checksum the fetched bytes can change between builds.',
  fix: 'Use COPY for local files. For remote artifacts, download a pinned version and verify --checksum or a signature before adding it to the image.',
  match: isDockerfile,
  check(ctx) {
    const findings = [];
    for (const instruction of collectDockerInstructions(ctx.text)) {
      if (instruction.instruction !== 'ADD') continue;
      if (!/https?:\/\//i.test(instruction.text)) continue;
      if (/(?:^|\s)--checksum=/.test(instruction.text)) continue;
      findings.push({
        line: instruction.line,
        column: instruction.column,
        message:
          'ADD fetches a remote URL without a checksum. Pin the artifact and verify it, or copy a reviewed local file instead.',
      });
    }
    return findings;
  },
});

function stripYamlComment(text) {
  let quote = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote !== null) {
      if (char === quote) quote = null;
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

function unquote(value) {
  const trimmed = String(value).trim();
  if (trimmed.length >= 2) {
    const quote = trimmed[0];
    if ((quote === '"' || quote === "'") && trimmed[trimmed.length - 1] === quote) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function stripYamlNodeProperties(value) {
  let rest = String(value).trim();
  for (;;) {
    const match = /^(?:&[A-Za-z0-9_-]+|![^\s]+)\s+/.exec(rest);
    if (match === null) return rest;
    rest = rest.slice(match[0].length);
  }
}

function yamlScalar(raw) {
  let value = stripYamlNodeProperties(stripYamlComment(String(raw)));
  value = unquote(value);
  const token = /^[^\s]+/.exec(value);
  return token === null ? '' : unquote(token[0]);
}

function composeKeyValue(line, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`^([ \\t]*)(?:-[ \\t]+)?(?:(['"])${escaped}\\2|${escaped})[ \\t]*:[ \\t]*(.*)$`, 'i');
  const match = pattern.exec(line);
  if (match === null) return null;
  const rawValue = stripYamlNodeProperties(stripYamlComment(match[3] ?? ''));
  return { indent: match[1].length, column: match[1].length + 1, value: yamlScalar(match[3] ?? ''), rawValue };
}

function composeLines(text) {
  return textLines(text);
}

const privilegedMode = defineRule({
  id: 'container/privileged-mode',
  title: 'Compose service runs in privileged mode',
  category: 'container',
  severity: 'critical',
  cwe: 'CWE-250',
  owasp: [OWASP_MISCONFIGURATION],
  docsUrl: DOCS + 'containerprivileged-mode',
  rationale:
    'privileged: true gives the container nearly all host capabilities, including device access and kernel operations. A compromised service can escape the container boundary instead of being contained by it.',
  fix: 'Remove privileged: true and grant only the specific capability or device the service needs, after confirming no narrower runtime or host integration exists.',
  match: isComposeFile,
  check(ctx) {
    const findings = [];
    const lines = composeLines(ctx.text);
    for (let index = 0; index < lines.length; index += 1) {
      if (/^\s*#/.test(lines[index])) continue;
      const parsed = composeKeyValue(lines[index], 'privileged');
      if (parsed === null || parsed.value.toLowerCase() !== 'true') continue;
      findings.push({
        line: index + 1,
        column: parsed.column,
        message:
          'This Compose service sets privileged: true. Remove it or replace it with the smallest specific capability the workload requires.',
      });
    }
    return findings;
  },
});

const hostNetwork = defineRule({
  id: 'container/host-network',
  title: 'Compose service uses the host network namespace',
  category: 'container',
  severity: 'error',
  cwe: 'CWE-668',
  owasp: [OWASP_MISCONFIGURATION],
  docsUrl: DOCS + 'containerhost-network',
  rationale:
    'network_mode: host removes network isolation. The service can bind or reach host interfaces directly, bypass port mapping review and expose listeners that were never declared in Compose.',
  fix: 'Use an explicit Compose network and publish only required ports. Reserve host networking for a documented host-level agent that cannot work another way.',
  match: isComposeFile,
  check(ctx) {
    const findings = [];
    const lines = composeLines(ctx.text);
    for (let index = 0; index < lines.length; index += 1) {
      if (/^\s*#/.test(lines[index])) continue;
      const parsed = composeKeyValue(lines[index], 'network_mode');
      if (parsed === null || parsed.value.toLowerCase() !== 'host') continue;
      findings.push({
        line: index + 1,
        column: parsed.column,
        message:
          'This Compose service uses network_mode: host. Use an isolated Compose network with explicit published ports instead.',
      });
    }
    return findings;
  },
});

function appendFlowCharacter(state, char, line, column) {
  if (state.itemLine === null) {
    if (/\s/.test(char)) return;
    state.itemLine = line;
    state.itemColumn = column;
  }
  state.current += char;
}

function pushFlowEntry(state, entries) {
  const text = state.current.trim();
  if (text.length > 0) entries.push({ line: state.itemLine ?? 1, column: state.itemColumn ?? 1, text });
  state.current = '';
  state.itemLine = null;
  state.itemColumn = null;
}

function feedFlowVolumeLine(state, entries, line, lineNumber) {
  let index = 0;
  if (!state.started) {
    const start = line.indexOf('[');
    if (start === -1) return;
    state.started = true;
    index = start + 1;
  }

  for (; index < line.length; index += 1) {
    const char = line[index];
    if (state.quote !== null) {
      appendFlowCharacter(state, char, lineNumber, index + 1);
      if (state.escaped) {
        state.escaped = false;
      } else if (state.quote === '"' && char === '\\') {
        state.escaped = true;
      } else if (char === state.quote) {
        if (state.quote === "'" && line[index + 1] === "'") {
          appendFlowCharacter(state, line[index + 1], lineNumber, index + 2);
          index += 1;
        } else {
          state.quote = null;
        }
      }
      continue;
    }

    if (char === '#' && (index === 0 || /\s/.test(line[index - 1]))) break;
    if (char === '"' || char === "'") {
      state.quote = char;
      appendFlowCharacter(state, char, lineNumber, index + 1);
      continue;
    }
    if (char === '[') {
      state.nestedList += 1;
      appendFlowCharacter(state, char, lineNumber, index + 1);
      continue;
    }
    if (char === '{') {
      state.nestedMap += 1;
      appendFlowCharacter(state, char, lineNumber, index + 1);
      continue;
    }
    if (char === ']') {
      if (state.nestedList === 0) {
        pushFlowEntry(state, entries);
        state.done = true;
        return;
      }
      state.nestedList -= 1;
      appendFlowCharacter(state, char, lineNumber, index + 1);
      continue;
    }
    if (char === '}') {
      state.nestedMap = Math.max(0, state.nestedMap - 1);
      appendFlowCharacter(state, char, lineNumber, index + 1);
      continue;
    }
    if (char === ',' && state.nestedList === 0 && state.nestedMap === 0) {
      pushFlowEntry(state, entries);
      continue;
    }
    appendFlowCharacter(state, char, lineNumber, index + 1);
  }

  if (state.current.length > 0) state.current += ' ';
}

function collectFlowVolumeEntries(lines, startIndex, firstLine) {
  const state = {
    started: false,
    done: false,
    quote: null,
    escaped: false,
    nestedList: 0,
    nestedMap: 0,
    current: '',
    itemLine: null,
    itemColumn: null,
  };
  const entries = [];
  feedFlowVolumeLine(state, entries, firstLine, startIndex + 1);
  for (let cursor = startIndex + 1; !state.done && cursor < lines.length; cursor += 1) {
    feedFlowVolumeLine(state, entries, lines[cursor], cursor + 1);
  }
  return entries;
}

function composeVolumeLines(lines) {
  const result = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (/^\s*#/.test(lines[index])) continue;
    const parsed = composeKeyValue(lines[index], 'volumes');
    if (parsed === null) continue;
    if (parsed.rawValue.startsWith('[')) {
      result.push(...collectFlowVolumeEntries(lines, index, lines[index]));
      continue;
    }

    let flowStart = null;
    if (parsed.rawValue === '') {
      for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
        const line = lines[cursor];
        if (line.trim() === '' || /^\s*#/.test(line)) continue;
        const indent = (/^[ \t]*/.exec(line) ?? [''])[0].length;
        if (indent <= parsed.indent) break;
        if (line.trim().startsWith('[')) flowStart = cursor;
        break;
      }
    }
    if (flowStart !== null) {
      result.push(...collectFlowVolumeEntries(lines, flowStart, lines[flowStart]));
      continue;
    }

    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const line = lines[cursor];
      if (line.trim() === '') continue;
      const indent = (/^[ \t]*/.exec(line) ?? [''])[0].length;
      if (indent <= parsed.indent) break;
      result.push({ line: cursor + 1, column: 1, text: line });
    }
  }
  return result;
}

/** True when a compose volume entry uses the host Docker socket as source. */
export function isDockerSocketVolumeLine(line) {
  const cleaned = stripYamlComment(line).trim();
  if (cleaned === '') return false;

  const longSyntax = /(?:^|[\s,{])(?:['"]?(?:source|src)['"]?)\s*:\s*['"]?\/var\/run\/docker\.sock['"]?(?=\s*[,}]|$)/i;
  if (longSyntax.test(cleaned)) return true;

  const listItem = /^-\s+(.+)$/.exec(cleaned);
  const scalar = unquote(listItem === null ? cleaned : listItem[1]);
  if (scalar.startsWith('{')) return longSyntax.test(scalar);
  const source = scalar.split(':')[0];
  return source === '/var/run/docker.sock';
}

const dockerSocketMount = defineRule({
  id: 'container/docker-socket-mount',
  title: 'Compose service mounts the host Docker socket',
  category: 'container',
  severity: 'critical',
  cwe: 'CWE-732',
  owasp: [OWASP_MISCONFIGURATION],
  docsUrl: DOCS + 'containerdocker-socket-mount',
  rationale:
    'The Docker socket controls the host daemon. A container that can write to it can start a privileged container, mount host paths and take over the host, so the socket is effectively root on the machine.',
  fix: 'Remove the socket mount. Use a remote, least privilege API proxy or a tightly scoped external job when container orchestration is truly required.',
  match: isComposeFile,
  check(ctx) {
    const findings = [];
    for (const entry of composeVolumeLines(composeLines(ctx.text))) {
      if (!isDockerSocketVolumeLine(entry.text)) continue;
      const column = Math.max(1, (entry.column ?? 1) + entry.text.indexOf('/var/run/docker.sock'));
      findings.push({
        line: entry.line,
        column,
        message:
          'This service mounts /var/run/docker.sock, which grants control of the host Docker daemon. Remove the mount or use a least privilege proxy.',
      });
    }
    return findings;
  },
});

export const containerRules = Object.freeze([
  missingNonRootUser,
  explicitRootUser,
  curlPipeShell,
  remoteAdd,
  privilegedMode,
  hostNetwork,
  dockerSocketMount,
]);
