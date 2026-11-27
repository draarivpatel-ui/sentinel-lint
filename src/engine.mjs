/**
 * The scan engine: load files, run rules, normalize findings, apply
 * suppressions and produce a deterministic result set.
 *
 * Rules are isolated from each other. A rule that throws, returns junk or
 * points outside the repository produces a diagnostic and the scan continues.
 */

import path from 'node:path';
import { DEFAULT_CONFIG } from './config.mjs';
import { matchesAnyGlob } from './globs.mjs';
import { buildIgnoreMap, hasIgnoreMarkers } from './ignore.mjs';
import { loadBuiltinRules } from './rules/index.mjs';
import { walkRepository } from './walk.mjs';

const MAX_DIAGNOSTICS = 100;

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeRepoRelative(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) return null;
  let normalized = filePath.replace(/\\/g, '/');
  if (normalized.startsWith('./')) normalized = normalized.slice(2);
  if (normalized.startsWith('/')) return null;
  if (/^[a-zA-Z]:/.test(normalized)) return null;
  const segments = normalized.split('/');
  if (segments.includes('..') || segments.includes('')) return null;
  return normalized;
}

/**
 * Apply config severity overrides and turn rules off.
 * @param {object[]} rules
 * @param {object} config
 * @returns {{rules: object[], diagnostics: object[]}}
 */
export function resolveRules(rules, config = {}) {
  const overrides = isPlainObject(config.rules) ? config.rules : {};
  const diagnostics = [];
  const resolved = [];

  for (const rule of rules) {
    const override = Object.hasOwn(overrides, rule.id) ? overrides[rule.id] : undefined;
    if (override === 'off') continue;
    resolved.push(
      typeof override === 'string' && override !== rule.severity
        ? Object.freeze({ ...rule, severity: override })
        : rule,
    );
  }

  const known = new Set(rules.map((rule) => rule.id));
  for (const ruleId of Object.keys(overrides)) {
    if (!known.has(ruleId)) {
      diagnostics.push({
        code: 'unknown-rule',
        message: `configuration references unknown rule "${ruleId}"`,
      });
    }
  }

  resolved.sort((left, right) => compareStrings(left.id, right.id));
  return { rules: resolved, diagnostics };
}

function coerceReport(args) {
  if (args.length === 1 && isPlainObject(args[0])) return args[0];
  const [line, column, message, extra] = args;
  return {
    line,
    column,
    message,
    ...(isPlainObject(extra) ? extra : {}),
  };
}

/**
 * Run a scan.
 *
 * @param {object} [options]
 * @param {string} [options.root] Directory to scan, default process.cwd().
 * @param {object} [options.config] Validated config object.
 * @param {object[]} [options.rules] Rule list, defaults to the built in pack.
 * @returns {Promise<object>}
 */
export async function scan(options = {}) {
  const startedAt = Date.now();
  const config = { ...DEFAULT_CONFIG, ...(options.config ?? {}) };
  const rootInput = options.root ?? process.cwd();
  const inputRules = options.rules ?? loadBuiltinRules();

  const walked = await walkRepository(rootInput, {
    include: Array.isArray(config.include) ? config.include : [],
    exclude: Array.isArray(config.exclude) ? config.exclude : [],
    maxFileSize: config.maxFileSize ?? DEFAULT_CONFIG.maxFileSize,
    maxFiles: config.maxFiles ?? DEFAULT_CONFIG.maxFiles,
  });

  const { rules: enabledRules, diagnostics: ruleDiagnostics } = resolveRules(inputRules, config);
  const diagnostics = [...walked.diagnostics, ...ruleDiagnostics];
  const diagnosticKeys = new Set(diagnostics.map((entry) => `${entry.code}|${entry.ruleId ?? ''}|${entry.message}`));
  let truncatedDiagnostics = 0;

  function pushDiagnostic(entry) {
    const key = `${entry.code}|${entry.ruleId ?? ''}|${entry.message}`;
    if (diagnosticKeys.has(key)) return;
    diagnosticKeys.add(key);
    if (diagnostics.length >= MAX_DIAGNOSTICS) {
      truncatedDiagnostics += 1;
      return;
    }
    diagnostics.push(entry);
  }

  const filesByPath = new Map(walked.files.map((file) => [file.path, file]));
  const linesCache = new Map();
  const ignoreCache = new Map();
  const findings = [];
  const findingKeys = new Set();
  const stats = { suppressed: 0, ruleErrors: 0 };

  function linesFor(file) {
    let lines = linesCache.get(file.path);
    if (lines === undefined) {
      lines = file.text.split('\n');
      linesCache.set(file.path, lines);
    }
    return lines;
  }

  function ignoreFor(filePath) {
    if (ignoreCache.has(filePath)) return ignoreCache.get(filePath);
    const file = filesByPath.get(filePath);
    let ignoreMap = null;
    if (file !== undefined && hasIgnoreMarkers(file.text)) {
      ignoreMap = buildIgnoreMap(file.text);
    }
    ignoreCache.set(filePath, ignoreMap);
    return ignoreMap;
  }

  function record(rule, partial, file, lineCount) {
    if (!isPlainObject(partial)) {
      stats.ruleErrors += 1;
      pushDiagnostic({
        code: 'invalid-finding',
        ruleId: rule.id,
        message: `rule "${rule.id}" produced a finding that is not an object`,
      });
      return;
    }

    const message =
      typeof partial.message === 'string' && partial.message.trim().length > 0
        ? partial.message.trim()
        : rule.title;

    let line = Number.isInteger(partial.line) && partial.line > 0 ? partial.line : 1;
    let column = Number.isInteger(partial.column) && partial.column > 0 ? partial.column : 1;

    if (file !== null) {
      const maxLine = Math.max(1, lineCount ?? 1);
      if (line > maxLine) {
        stats.ruleErrors += 1;
        pushDiagnostic({
          code: 'invalid-finding',
          ruleId: rule.id,
          message: `rule "${rule.id}" reported line ${line} in ${file.path}, which only has ${maxLine} lines`,
        });
        return;
      }
      const lineText = (linesFor(file)[line - 1] ?? '');
      if (column > lineText.length + 1) column = lineText.length + 1;
    }

    let findingFile = file === null ? normalizeRepoRelative(partial.file) : file.path;
    if (file === null && partial.file !== undefined && partial.file !== null && findingFile === null) {
      pushDiagnostic({
        code: 'invalid-finding-file',
        ruleId: rule.id,
        message: `rule "${rule.id}" reported an unsafe or absolute file path`,
      });
    }

    const ignoreMap = findingFile === null ? null : ignoreFor(findingFile);
    if (ignoreMap !== null && ignoreMap.isSuppressed(line, rule.id)) {
      stats.suppressed += 1;
      return;
    }

    const key = `${rule.id}|${findingFile ?? ''}|${line}|${column}|${message}`;
    if (findingKeys.has(key)) return;
    findingKeys.add(key);

    const finding = {
      ruleId: rule.id,
      title: rule.title,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      docsUrl: rule.docsUrl,
      fix: rule.fix,
      file: findingFile,
      line,
      column,
      message,
    };

    if (Number.isInteger(partial.endLine) && partial.endLine >= line) {
      finding.endLine = partial.endLine;
    }
    if (Number.isInteger(partial.endColumn) && partial.endColumn > 0) {
      finding.endColumn = partial.endColumn;
    }

    findings.push(finding);
  }

  function runRuleCheck(rule, ctx, targetFile) {
    const collected = [];
    ctx.report = (...args) => {
      collected.push(coerceReport(args));
    };

    let returned;
    try {
      returned = rule.check(ctx);
    } catch (error) {
      stats.ruleErrors += 1;
      pushDiagnostic({
        code: 'rule-error',
        ruleId: rule.id,
        message: `rule "${rule.id}" threw: ${error && error.message ? error.message : String(error)}`,
      });
      return;
    }

    if (Array.isArray(returned)) {
      for (const finding of returned) collected.push(finding);
    } else if (returned !== undefined && returned !== null) {
      stats.ruleErrors += 1;
      pushDiagnostic({
        code: 'invalid-finding',
        ruleId: rule.id,
        message: `rule "${rule.id}" returned a non-array value from check()`,
      });
    }

    for (const partial of collected) {
      record(rule, partial, targetFile, targetFile === null ? undefined : linesFor(targetFile).length);
    }
  }

  for (const rule of enabledRules) {
    if (rule.scope === 'repo') {
      if (walked.rootType === 'file') continue;
      const ctx = {
        path: null,
        file: null,
        text: '',
        lines: [],
        lineCount: 0,
        root: walked.root,
        config,
        files: walked.files,
        paths: walked.files.map((file) => file.path),
        read: (filePath) => {
          const normalized = normalizeRepoRelative(filePath);
          if (normalized === null) return null;
          const file = filesByPath.get(normalized);
          return file === undefined ? null : file.text;
        },
        report: () => {},
      };
      runRuleCheck(rule, ctx, null);
      continue;
    }

    for (const file of walked.files) {
      const hasGlobs = rule.appliesTo.length > 0;
      if (hasGlobs && !matchesAnyGlob(file.path, rule.appliesTo)) continue;

      if (rule.match !== null) {
        let matched = false;
        try {
          matched = Boolean(rule.match(file));
        } catch (error) {
          stats.ruleErrors += 1;
          pushDiagnostic({
            code: 'rule-match-error',
            ruleId: rule.id,
            message: `rule "${rule.id}" match() threw on ${file.path}: ${error && error.message ? error.message : String(error)}`,
          });
          continue;
        }
        if (!matched) continue;
      }

      const ctx = {
        path: file.path,
        file,
        text: file.text,
        lines: linesFor(file),
        lineCount: linesFor(file).length,
        root: walked.root,
        config,
        report: () => {},
      };
      runRuleCheck(rule, ctx, file);
    }
  }

  findings.sort((left, right) => {
    const byFile = compareStrings(left.file ?? '', right.file ?? '');
    if (byFile !== 0) return byFile;
    if (left.line !== right.line) return left.line - right.line;
    if (left.column !== right.column) return left.column - right.column;
    const byRule = compareStrings(left.ruleId, right.ruleId);
    if (byRule !== 0) return byRule;
    return compareStrings(left.message, right.message);
  });

  const bySeverity = { info: 0, warning: 0, error: 0, critical: 0 };
  for (const finding of findings) bySeverity[finding.severity] += 1;

  return {
    root: walked.root,
    files: walked.files,
    findings,
    diagnostics,
    diagnosticsTruncated: truncatedDiagnostics,
    stats: { ...walked.stats, ...stats },
    summary: {
      filesScanned: walked.stats.filesScanned,
      findings: findings.length,
      suppressed: stats.suppressed,
      ruleErrors: stats.ruleErrors,
      diagnostics: diagnostics.length,
      bySeverity,
      durationMs: Date.now() - startedAt,
    },
    rules: enabledRules,
  };
}
