/**
 * Command line front end.
 *
 * Exit codes are part of the contract and are asserted by the tests:
 *   0  scan completed and no finding reached the fail threshold
 *   1  at least one finding reached the fail threshold
 *   2  usage error, missing path or invalid configuration
 *   3  unexpected internal error
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { ConfigError, CONFIG_FILE, DEFAULT_CONFIG, loadConfig } from './config.mjs';
import { resolveRules, scan } from './engine.mjs';
import { formatReport, REPORTER_NAMES } from './reporters/index.mjs';
import { PluginError, loadPluginRules } from './plugins.mjs';
import { loadBuiltinRules, RULE_COUNT } from './rules/index.mjs';
import { meetsThreshold, SEVERITIES } from './rule-api.mjs';
import { VERSION } from './version.mjs';

export const EXIT_CODES = Object.freeze({ ok: 0, findings: 1, usage: 2, internal: 3 });

const COMMANDS = new Set(['scan', 'rules', 'init', 'help', 'version']);

const HELP = `sentinel-lint ${VERSION}

Usage: sentinel-lint <command> [path] [options]

Commands:
  scan [path]      Scan a repository or file (default command)
  rules            List the security rules that are active
  init [path]      Write a starter ${CONFIG_FILE}
  help             Show this text
  version          Print the version

Scan options:
  --format <name>        terminal, json or sarif (default: terminal)
  --json                 Shorthand for --format json
  --sarif                Shorthand for --format sarif
  -o, --output <file>    Write the report to a file, "-" means stdout
  -c, --config <file>    Use an explicit configuration file
  --fail-on <severity>   info, warning, error, critical, off (default: warning)
  --include <glob>       Only scan paths matching this glob, repeatable
  --exclude <glob>       Skip paths matching this glob, repeatable
  --plugin <file>        Load an extra rule module, repeatable
  --max-findings <n>     Cap the findings printed by the terminal reporter
  -q, --quiet            Print only the summary line
  --color / --no-color   Force ANSI colors on or off

Init options:
  --force                Overwrite an existing ${CONFIG_FILE}

General:
  -h, --help             Show this text
  -v, --version          Print the version

Exit codes: 0 clean, 1 findings at or above the threshold, 2 usage or config error, 3 internal error.
`;

export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

const VALUE_FLAGS = new Set([
  'format',
  'output',
  'config',
  'fail-on',
  'max-findings',
  'include',
  'exclude',
  'plugin',
]);

const BOOLEAN_FLAGS = new Set([
  'json',
  'sarif',
  'terminal',
  'quiet',
  'color',
  'no-color',
  'force',
  'help',
  'version',
]);

const SHORT_FLAGS = Object.freeze({
  o: 'output',
  c: 'config',
  q: 'quiet',
  h: 'help',
  v: 'version',
});

function toCamel(flag) {
  return flag.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

/**
 * Parse a raw argv slice into a normalized option object.
 * @param {string[]} argv Arguments after the executable, without node flags.
 * @returns {object}
 */
export function parseArgv(argv) {
  const options = {
    command: null,
    target: null,
    format: null,
    output: null,
    config: null,
    failOn: null,
    quiet: false,
    color: null,
    maxFindings: null,
    include: [],
    exclude: [],
    plugins: [],
    force: false,
    help: false,
    version: false,
  };

  const positionals = [];
  let index = 0;
  let endOfFlags = false;

  while (index < argv.length) {
    const token = argv[index];
    index += 1;

    if (endOfFlags || token === '-' || !token.startsWith('-')) {
      positionals.push(token);
      continue;
    }

    if (token === '--') {
      endOfFlags = true;
      continue;
    }

    let name;
    let inlineValue = null;
    if (token.startsWith('--')) {
      const body = token.slice(2);
      const equals = body.indexOf('=');
      if (equals === -1) {
        name = body;
      } else {
        name = body.slice(0, equals);
        inlineValue = body.slice(equals + 1);
      }
    } else {
      const short = token.slice(1);
      if (short.length !== 1 || !Object.hasOwn(SHORT_FLAGS, short)) {
        throw new UsageError(`unknown option "${token}"`);
      }
      name = SHORT_FLAGS[short];
    }

    if (BOOLEAN_FLAGS.has(name)) {
      if (inlineValue !== null) throw new UsageError(`option "--${name}" does not take a value`);
      const key = toCamel(name);
      options[key] = true;
      if (name === 'json' || name === 'sarif' || name === 'terminal') options.format = name;
      if (name === 'no-color') options.color = false;
      if (name === 'color') options.color = true;
      continue;
    }

    if (!VALUE_FLAGS.has(name)) {
      throw new UsageError(`unknown option "--${name}"`);
    }

    let value = inlineValue;
    if (value === null) {
      value = argv[index];
      index += 1;
    }
    if (value === undefined) throw new UsageError(`option "--${name}" needs a value`);

    if (name === 'format') {
      if (!REPORTER_NAMES.includes(value)) {
        throw new UsageError(`unknown format "${value}"; expected one of ${REPORTER_NAMES.join(', ')}`);
      }
      options.format = value;
    } else if (name === 'output') {
      options.output = value;
    } else if (name === 'config') {
      options.config = value;
    } else if (name === 'fail-on') {
      if (value !== 'off' && value !== 'none' && !SEVERITIES.includes(value)) {
        throw new UsageError(`--fail-on must be one of ${SEVERITIES.join(', ')}, off or none`);
      }
      options.failOn = value;
    } else if (name === 'max-findings') {
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new UsageError('--max-findings must be a positive integer');
      }
      options.maxFindings = parsed;
    } else if (name === 'include') {
      options.include.push(value);
    } else if (name === 'exclude') {
      options.exclude.push(value);
    } else if (name === 'plugin') {
      options.plugins.push(value);
    }
  }

  if (positionals.length > 0 && COMMANDS.has(positionals[0])) {
    options.command = positionals.shift();
  }
  if (positionals.length > 1) {
    throw new UsageError(`unexpected extra argument "${positionals[1]}"`);
  }
  options.target = positionals.length === 1 ? positionals[0] : null;
  options.command = options.command ?? 'scan';

  if (options.command !== 'scan' && (options.include.length > 0 || options.exclude.length > 0)) {
    throw new UsageError(`--include and --exclude are only valid for scan`);
  }
  if (options.command !== 'scan' && options.plugins.length > 0) {
    throw new UsageError('--plugin is only valid for scan');
  }
  if (options.command !== 'init' && options.force) {
    throw new UsageError('--force is only valid for init');
  }

  return options;
}

function write(stream, text) {
  stream.write(text);
}

function summarize(result) {
  const { summary } = result;
  return `sentinel-lint: ${summary.findings} ${summary.findings === 1 ? 'finding' : 'findings'} in ${
    summary.filesScanned
  } ${summary.filesScanned === 1 ? 'file' : 'files'}`;
}

export async function loadRulesForScan(configResult, cliPlugins) {
  const builtin = loadBuiltinRules();
  const configured = Array.isArray(configResult.config.plugins) ? configResult.config.plugins : [];
  const pluginRules = [];
  if (configured.length > 0) {
    // Config sourced paths are untrusted when the config came from a
    // scanned repository, so they must stay inside the config directory.
    pluginRules.push(...(await loadPluginRules(configured, configResult.configDir)));
  }
  if (cliPlugins.length > 0) {
    // The operator named these paths on the command line, so absolute
    // paths and parent directories are allowed.
    pluginRules.push(
      ...(await loadPluginRules(cliPlugins, configResult.configDir, { allowOutsideConfigDir: true })),
    );
  }
  return [...builtin, ...pluginRules];
}

async function commandScan(options, io) {
  const target = path.resolve(io.cwd, options.target ?? '.');
  let stat;
  try {
    stat = await fs.stat(target);
  } catch {
    throw new UsageError(`scan path not found: ${options.target ?? '.'}`);
  }
  if (!stat.isDirectory() && !stat.isFile()) {
    throw new UsageError(`scan path is not a file or directory: ${options.target ?? '.'}`);
  }

  const configResult = await loadConfig({
    root: stat.isDirectory() ? target : path.dirname(target),
    cwd: io.cwd,
    ...(options.config === null ? {} : { configPath: options.config }),
  });
  for (const warning of configResult.warnings) {
    write(io.stderr, `sentinel-lint: warning: ${warning}\n`);
  }

  const config = {
    ...configResult.config,
    include: [...configResult.config.include, ...options.include],
    exclude: [...configResult.config.exclude, ...options.exclude],
    failOn: options.failOn ?? configResult.config.failOn,
  };

  const rules = await loadRulesForScan(configResult, options.plugins);
  const result = await scan({ root: target, config, rules });

  const format = options.format ?? 'terminal';
  const report = formatReport(format, result, {
    version: VERSION,
    quiet: options.quiet,
    color: options.color ?? undefined,
    ...(options.maxFindings === null ? {} : { maxFindings: options.maxFindings }),
  });

  if (options.output !== null) {
    if (options.output === '-') {
      write(io.stdout, report);
    } else {
      const outputPath = path.resolve(io.cwd, options.output);
      await fs.writeFile(outputPath, report, 'utf8');
      if (!options.quiet) {
        write(io.stderr, `sentinel-lint: wrote ${format} report to ${path.relative(io.cwd, outputPath) || outputPath}\n`);
      }
    }
  } else {
    write(io.stdout, report);
    if (format !== 'terminal' && !options.quiet) {
      write(io.stderr, `${summarize(result)}\n`);
    }
  }

  const threshold = config.failOn ?? DEFAULT_CONFIG.failOn;
  const failing = result.findings.some((finding) => meetsThreshold(finding.severity, threshold));
  return failing ? EXIT_CODES.findings : EXIT_CODES.ok;
}

async function commandRules(options, io) {
  const target = path.resolve(io.cwd, options.target ?? '.');
  const configResult = await loadConfig({
    root: target,
    cwd: io.cwd,
    ...(options.config === null ? {} : { configPath: options.config }),
  });

  const rules = await loadRulesForScan(configResult, options.plugins);
  const { rules: active } = resolveRules(rules, configResult.config);

  if (options.format === 'json') {
    write(
      io.stdout,
      `${JSON.stringify(
        active.map((rule) => ({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          cwe: rule.cwe,
          owasp: [...(rule.owasp ?? [])],
          scope: rule.scope,
          docsUrl: rule.docsUrl,
        })),
        null,
        2,
      )}\n`,
    );
    return EXIT_CODES.ok;
  }

  const lines = [];
  let currentCategory = null;
  for (const rule of active) {
    if (rule.category !== currentCategory) {
      if (currentCategory !== null) lines.push('');
      currentCategory = rule.category;
      lines.push(`${currentCategory}:`);
    }
    lines.push(`  ${rule.severity.padEnd(8)} ${rule.id.padEnd(40)} ${rule.title}`);
  }
  lines.push('');
  lines.push(`${active.length} active rules (${RULE_COUNT} built in)`);
  write(io.stdout, `${lines.join('\n')}\n`);
  return EXIT_CODES.ok;
}

const STARTER_CONFIG = {
  $schema: 'https://raw.githubusercontent.com/draarivpatel-ui/sentinel-lint/main/schemas/sentinelrc.schema.json',
  failOn: 'warning',
  include: [],
  exclude: [],
  rules: {},
  plugins: [],
  trustedActions: [],
};

async function commandInit(options, io) {
  const target = path.resolve(io.cwd, options.target ?? '.');
  let stat;
  try {
    stat = await fs.stat(target);
  } catch {
    throw new UsageError(`init path not found: ${options.target ?? '.'}`);
  }
  if (!stat.isDirectory()) throw new UsageError(`init path is not a directory: ${options.target ?? '.'}`);

  const configPath = path.join(target, CONFIG_FILE);
  if (!options.force) {
    try {
      await fs.stat(configPath);
      throw new UsageError(`${CONFIG_FILE} already exists; pass --force to overwrite it`);
    } catch (error) {
      if (error instanceof UsageError) throw error;
    }
  }

  await fs.writeFile(configPath, `${JSON.stringify(STARTER_CONFIG, null, 2)}\n`, 'utf8');
  write(io.stdout, `sentinel-lint: wrote ${path.relative(io.cwd, configPath) || configPath}\n`);
  return EXIT_CODES.ok;
}

/**
 * Run the CLI.
 *
 * @param {string[]} argv Arguments after the executable.
 * @param {object} [io]
 * @param {NodeJS.WritableStream} [io.stdout]
 * @param {NodeJS.WritableStream} [io.stderr]
 * @param {string} [io.cwd]
 * @returns {Promise<number>} Exit code.
 */
export async function run(argv, io = {}) {
  const streams = {
    stdout: io.stdout ?? process.stdout,
    stderr: io.stderr ?? process.stderr,
    cwd: io.cwd ?? process.cwd(),
  };

  let options;
  try {
    options = parseArgv(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      write(streams.stderr, `sentinel-lint: ${error.message}\n\n${HELP}`);
      return EXIT_CODES.usage;
    }
    throw error;
  }

  if (options.version || options.command === 'version') {
    write(streams.stdout, `${VERSION}\n`);
    return EXIT_CODES.ok;
  }
  if (options.help || options.command === 'help') {
    write(streams.stdout, HELP);
    return EXIT_CODES.ok;
  }

  try {
    if (options.command === 'scan') return await commandScan(options, streams);
    if (options.command === 'rules') return await commandRules(options, streams);
    if (options.command === 'init') return await commandInit(options, streams);
    throw new UsageError(`unknown command "${options.command}"`);
  } catch (error) {
    if (error instanceof UsageError || error instanceof ConfigError || error instanceof PluginError) {
      write(streams.stderr, `sentinel-lint: ${error.message}\n`);
      return EXIT_CODES.usage;
    }
    write(
      streams.stderr,
      `sentinel-lint: internal error: ${error && error.stack ? error.stack : String(error)}\n`,
    );
    return EXIT_CODES.internal;
  }
}

/**
 * Entry point used by bin/sentinel-lint.mjs.
 * @returns {Promise<void>}
 */
export async function main() {
  const code = await run(process.argv.slice(2));
  process.exitCode = code;
}

export { HELP };

/**
 * True when this module was executed directly rather than imported.
 * @param {string} moduleUrl
 * @param {string | undefined} entry
 * @returns {boolean}
 */
export function isDirectInvocation(moduleUrl, entry) {
  if (entry === undefined || entry === null) return false;
  try {
    return moduleUrl === pathToFileURL(path.resolve(entry)).href;
  } catch {
    return false;
  }
}
