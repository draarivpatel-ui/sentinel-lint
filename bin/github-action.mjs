#!/usr/bin/env node

import { promises as fs } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { ConfigError, loadConfig } from '../src/config.mjs';
import { EXIT_CODES, isDirectInvocation, loadRulesForScan } from '../src/cli.mjs';
import { scan } from '../src/engine.mjs';
import { assertValidGlob } from '../src/globs.mjs';
import { PluginError } from '../src/plugins.mjs';
import { formatReport, toSarif } from '../src/reporters/index.mjs';
import { artifactUri } from '../src/reporters/sarif.mjs';
import { meetsThreshold } from '../src/rule-api.mjs';
import { VERSION } from '../src/version.mjs';

export class ActionInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ActionInputError';
  }
}

const FORMATS = Object.freeze({
  sarif: 'sarif',
  text: 'terminal',
  json: 'json',
});

const FAIL_ON = Object.freeze({
  critical: 'critical',
  high: 'error',
  medium: 'warning',
  low: 'info',
  none: 'off',
});

const EXTRA_VALUE_FLAGS = new Set(['include', 'exclude', 'plugin', 'max-findings']);
const EXTRA_BOOLEAN_FLAGS = new Set(['quiet', 'color', 'no-color']);

function write(stream, text) {
  stream.write(text);
}

function hasUnsafeControl(value) {
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}

function inputValue(env, name, fallback = '') {
  const value = env[name];
  if (value === undefined || value === null || value === '') return fallback;
  const text = String(value);
  if (hasUnsafeControl(text) || text.includes('\n') || text.includes('\r')) {
    throw new ActionInputError(`${name} contains a control character or line break`);
  }
  return text;
}

export function isSupportedNodeVersion(version) {
  const [majorText, minorText] = String(version).split('.');
  const major = Number(majorText);
  const minor = Number(minorText);
  return Number.isInteger(major) && Number.isInteger(minor) && (major > 18 || (major === 18 && minor >= 18));
}

export function splitExtraArgs(input) {
  const tokens = [];
  let current = '';
  let quote = null;
  let escaping = false;
  let started = false;

  function finish() {
    if (!started) return;
    tokens.push(current);
    current = '';
    started = false;
  }

  for (const char of input) {
    if (escaping) {
      current += char;
      escaping = false;
      started = true;
      continue;
    }
    if (quote !== null) {
      if (char === quote) quote = null;
      else if (char === '\\' && quote === '"') escaping = true;
      else current += char;
      started = true;
      continue;
    }
    if (char === '\'' || char === '"') {
      quote = char;
      started = true;
      continue;
    }
    if (char === '\\') {
      escaping = true;
      started = true;
      continue;
    }
    if (/\s/.test(char)) {
      finish();
      continue;
    }
    current += char;
    started = true;
  }

  if (escaping) throw new ActionInputError('args ends with an unfinished escape');
  if (quote !== null) throw new ActionInputError('args has an unterminated quote');
  finish();
  return tokens;
}

export function parseExtraArgs(input) {
  const result = {
    include: [],
    exclude: [],
    plugins: [],
    maxFindings: null,
    quiet: false,
    color: null,
  };
  const tokens = splitExtraArgs(input);

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith('--') || token === '--') {
      throw new ActionInputError(`args entry "${token}" is not a supported long option`);
    }

    const equals = token.indexOf('=');
    const name = token.slice(2, equals === -1 ? undefined : equals);
    let value = equals === -1 ? null : token.slice(equals + 1);

    if (EXTRA_BOOLEAN_FLAGS.has(name)) {
      if (value !== null) throw new ActionInputError(`args option "--${name}" does not take a value`);
      if (name === 'quiet') result.quiet = true;
      if (name === 'color') result.color = true;
      if (name === 'no-color') result.color = false;
      continue;
    }

    if (!EXTRA_VALUE_FLAGS.has(name)) {
      throw new ActionInputError(
        `args option "--${name}" is not supported; use include, exclude, plugin, max-findings, quiet, color or no-color`,
      );
    }

    if (value === null) {
      index += 1;
      value = tokens[index];
    }
    if (value === undefined || value === '') {
      throw new ActionInputError(`args option "--${name}" needs a non-empty value`);
    }
    if (hasUnsafeControl(value)) throw new ActionInputError(`args option "--${name}" contains a control character`);

    if (name === 'include' || name === 'exclude') {
      try {
        assertValidGlob(value);
      } catch (error) {
        throw new ActionInputError(`args option "--${name}" has an invalid glob: ${error.message}`);
      }
      result[name].push(value);
    } else if (name === 'plugin') {
      result.plugins.push(value);
    } else if (name === 'max-findings') {
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new ActionInputError('args option "--max-findings" must be a positive integer');
      }
      result.maxFindings = parsed;
    }
  }

  return result;
}

function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function realpathOrResolved(candidate) {
  try {
    return await fs.realpath(candidate);
  } catch {
    return path.resolve(candidate);
  }
}

async function existingRealPath(candidate, label) {
  try {
    return await fs.realpath(candidate);
  } catch {
    throw new ActionInputError(`${label} not found: ${path.basename(candidate)}`);
  }
}

async function resolveOutputPath(candidate, workspace) {
  const missing = [];
  let existing = candidate;
  for (;;) {
    try {
      const real = await fs.realpath(existing);
      const resolved = path.join(real, ...missing);
      if (!inside(workspace, resolved)) {
        throw new ActionInputError('sarif-file must stay inside the GitHub workspace');
      }
      if (missing.length === 0) {
        const stat = await fs.stat(resolved);
        if (stat.isDirectory()) throw new ActionInputError('sarif-file points at a directory');
      }
      return resolved;
    } catch (error) {
      if (error instanceof ActionInputError) throw error;
      const parent = path.dirname(existing);
      if (parent === existing) throw new ActionInputError('sarif-file has no existing parent directory');
      missing.unshift(path.basename(existing));
      existing = parent;
    }
  }
}

async function resolvePathInput(rawValue, cwd, workspace, label) {
  const resolved = path.resolve(cwd, rawValue);
  const real = await existingRealPath(resolved, label);
  if (!inside(workspace, real)) {
    throw new ActionInputError(`${label} must stay inside the GitHub workspace`);
  }
  return real;
}

export async function parseActionInputs(env, cwd = process.cwd()) {
  const workspaceInput = env.GITHUB_WORKSPACE === undefined || env.GITHUB_WORKSPACE === '' ? cwd : env.GITHUB_WORKSPACE;
  const workspace = await realpathOrResolved(path.resolve(cwd, workspaceInput));

  const scanPathInput = inputValue(env, 'SENTINEL_INPUT_PATH', '.') || '.';
  const configInput = inputValue(env, 'SENTINEL_INPUT_CONFIG', '');
  const formatInput = inputValue(env, 'SENTINEL_INPUT_FORMAT', 'sarif').trim().toLowerCase() || 'sarif';
  const sarifFileInput = inputValue(env, 'SENTINEL_INPUT_SARIF_FILE', 'sentinel-lint.sarif') || 'sentinel-lint.sarif';
  const failOnInput = inputValue(env, 'SENTINEL_INPUT_FAIL_ON', 'high').trim().toLowerCase() || 'high';
  const argsInput = inputValue(env, 'SENTINEL_INPUT_ARGS', '');

  if (!Object.hasOwn(FORMATS, formatInput)) {
    throw new ActionInputError(`format must be one of sarif, text or json; got "${formatInput}"`);
  }
  if (!Object.hasOwn(FAIL_ON, failOnInput)) {
    throw new ActionInputError(`fail-on must be one of critical, high, medium, low or none; got "${failOnInput}"`);
  }

  const scanTarget = await resolvePathInput(scanPathInput, cwd, workspace, 'scan path');
  const targetStat = await fs.stat(scanTarget);
  if (!targetStat.isDirectory() && !targetStat.isFile()) {
    throw new ActionInputError('scan path is not a file or directory');
  }

  const configPath = configInput === '' ? null : await resolvePathInput(configInput, cwd, workspace, 'config');
  const sarifFile = await resolveOutputPath(path.resolve(cwd, sarifFileInput), workspace);
  const extra = parseExtraArgs(argsInput);

  for (let index = 0; index < extra.plugins.length; index += 1) {
    extra.plugins[index] = await resolvePathInput(extra.plugins[index], cwd, workspace, 'plugin');
  }

  return {
    workspace,
    scanTarget,
    targetIsFile: targetStat.isFile(),
    configPath,
    format: formatInput,
    reporter: FORMATS[formatInput],
    sarifFile,
    failOn: failOnInput,
    cliFailOn: FAIL_ON[failOnInput],
    extra,
  };
}

export function escapeSummaryCell(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '&#124;')
    .replace(/\[/g, '&#91;')
    .replace(/\]/g, '&#93;')
    .replace(/[\r\n]+/g, ' ');
}

export function buildStepSummary(result, inputs, exitCode) {
  const lines = [
    '## sentinel-lint',
    '',
    `**${result.summary.findings} ${result.summary.findings === 1 ? 'finding' : 'findings'}** in **${result.summary.filesScanned} ${result.summary.filesScanned === 1 ? 'file' : 'files'}**. Threshold \`${inputs.failOn}\`. Exit code \`${exitCode}\`.`,
    '',
  ];

  if (result.findings.length === 0) {
    lines.push('No findings were reported by the active rules.', '');
    return `${lines.join('\n')}\n`;
  }

  lines.push('| Severity | Rule | Location | Message |');
  lines.push('| --- | --- | --- | --- |');
  const shown = result.findings.slice(0, 20);
  for (const finding of shown) {
    const location = finding.file === null ? 'repository' : `${finding.file}:${finding.line}:${finding.column}`;
    lines.push(
      `| ${escapeSummaryCell(finding.severity)} | ${escapeSummaryCell(finding.ruleId)} | ${escapeSummaryCell(location)} | ${escapeSummaryCell(finding.message)} |`,
    );
  }
  if (result.findings.length > shown.length) {
    lines.push('', `${result.findings.length - shown.length} more findings are in the full report.`);
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

function outputLines(name, value) {
  const text = String(value);
  if (!text.includes('\n') && !text.includes('\r')) return `${name}=${text}`;
  let delimiter = 'sentinel-lint-output';
  while (text.includes(delimiter)) delimiter += '-x';
  return `${name}<<${delimiter}\n${text}\n${delimiter}`;
}

async function writeGitHubOutput(outputPath, values) {
  if (outputPath === undefined || outputPath === null || outputPath === '') return;
  const lines = Object.entries(values).map(([name, value]) => outputLines(name, value));
  await fs.appendFile(outputPath, `${lines.join('\n')}\n`, 'utf8');
}

async function performScan(inputs, cwd) {
  const configRoot = inputs.targetIsFile ? path.dirname(inputs.scanTarget) : inputs.scanTarget;
  const configResult = await loadConfig({
    root: configRoot,
    cwd,
    ...(inputs.configPath === null ? {} : { configPath: inputs.configPath }),
  });

  const config = {
    ...configResult.config,
    include: [...configResult.config.include, ...inputs.extra.include],
    exclude: [...configResult.config.exclude, ...inputs.extra.exclude],
    failOn: inputs.cliFailOn,
  };

  const rules = await loadRulesForScan(configResult, inputs.extra.plugins);
  const result = await scan({ root: inputs.scanTarget, config, rules });
  return { configResult, result };
}

function summarize(result) {
  return `sentinel-lint: ${result.summary.findings} ${result.summary.findings === 1 ? 'finding' : 'findings'} in ${result.summary.filesScanned} ${result.summary.filesScanned === 1 ? 'file' : 'files'}`;
}

function sarifReport(result, inputs) {
  const log = toSarif(result, { version: VERSION });
  const relativeRoot = path.relative(inputs.workspace, result.root);
  if (relativeRoot !== '' && !relativeRoot.startsWith('..') && !path.isAbsolute(relativeRoot)) {
    const prefix = artifactUri(relativeRoot);
    if (prefix !== '') {
      for (const run of log.runs) {
        for (const entry of run.results ?? []) {
          const location = entry.locations?.[0]?.physicalLocation?.artifactLocation;
          if (location !== undefined && typeof location.uri === 'string') {
            location.uri = `${prefix}/${location.uri}`;
          }
        }
      }
    }
  }
  return `${JSON.stringify(log, null, 2)}\n`;
}

export async function runGitHubAction(env = process.env, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const cwd = io.cwd ?? process.cwd();

  let exitCode = EXIT_CODES.ok;
  let findingsCount = 0;
  let sarifOutput = '';

  try {
    if (!isSupportedNodeVersion(process.versions.node)) {
      throw new ActionInputError(`sentinel-lint requires Node.js 18.18 or newer; this runner has ${process.versions.node}`);
    }

    const inputs = await parseActionInputs(env, cwd);
    const { configResult, result } = await performScan(inputs, cwd);
    for (const warning of configResult.warnings) {
      write(stderr, `sentinel-lint: warning: ${warning}\n`);
    }

    findingsCount = result.summary.findings;
    const failing = result.findings.some((finding) => meetsThreshold(finding.severity, inputs.cliFailOn));
    exitCode = failing ? EXIT_CODES.findings : EXIT_CODES.ok;

    const report =
      inputs.format === 'sarif'
        ? sarifReport(result, inputs)
        : formatReport(inputs.reporter, result, {
            version: VERSION,
            quiet: inputs.extra.quiet,
            color: inputs.extra.color ?? undefined,
            ...(inputs.extra.maxFindings === null ? {} : { maxFindings: inputs.extra.maxFindings }),
          });

    if (inputs.format === 'sarif') {
      await fs.mkdir(path.dirname(inputs.sarifFile), { recursive: true });
      await fs.writeFile(inputs.sarifFile, report, 'utf8');
      sarifOutput = inputs.sarifFile;
      write(stdout, `${summarize(result)}\nsentinel-lint: wrote SARIF report to ${inputs.sarifFile}\n`);
    } else {
      write(stdout, report);
      if (inputs.format === 'json' && !inputs.extra.quiet) write(stderr, `${summarize(result)}\n`);
    }

    if (env.GITHUB_STEP_SUMMARY !== undefined && env.GITHUB_STEP_SUMMARY !== '') {
      await fs.appendFile(env.GITHUB_STEP_SUMMARY, buildStepSummary(result, inputs, exitCode), 'utf8');
    }
  } catch (error) {
    const usage =
      error instanceof ActionInputError || error instanceof ConfigError || error instanceof PluginError;
    exitCode = usage ? EXIT_CODES.usage : EXIT_CODES.internal;
    const message = error && error.message ? error.message : String(error);
    write(stderr, `sentinel-lint: ${usage ? message : `internal error: ${error && error.stack ? error.stack : message}`}\n`);
  }

  try {
    await writeGitHubOutput(env.GITHUB_OUTPUT, {
      'sarif-file': sarifOutput,
      'findings-count': findingsCount,
      'exit-code': exitCode,
    });
  } catch (error) {
    write(stderr, `sentinel-lint: internal error: could not write GITHUB_OUTPUT: ${error.message}\n`);
    return EXIT_CODES.internal;
  }

  return exitCode;
}

export async function main() {
  process.exitCode = await runGitHubAction();
}

if (isDirectInvocation(import.meta.url, process.argv[1])) {
  await main();
}
