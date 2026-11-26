/**
 * Human readable terminal reporter.
 *
 * Output is grouped by file and ordered the same way as the JSON report. The
 * reporter never truncates findings unless a limit is passed, and it writes to
 * a string so the CLI owns the stream and the tests can assert on the text.
 */

const ANSI = Object.freeze({
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  cyan: '\u001b[36m',
  magenta: '\u001b[35m',
  gray: '\u001b[90m',
});

const SEVERITY_COLOR = Object.freeze({
  info: ANSI.cyan,
  warning: ANSI.yellow,
  error: ANSI.red,
  critical: ANSI.magenta,
});

function paint(enabled, code, text) {
  return enabled ? `${code}${text}${ANSI.reset}` : text;
}

/**
 * Neutralize control characters in text that came from a scanned repository.
 * A file name or manifest key can carry ANSI escapes, carriage returns or
 * other terminal control sequences, and the reporter must not execute them.
 */
function clean(text) {
  return String(text ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ');
}

function plural(count, singular, pluralForm) {
  return count === 1 ? singular : pluralForm ?? `${singular}s`;
}

/**
 * True when the stream looks like an interactive color terminal and NO_COLOR
 * is not set.
 * @param {{isTTY?: boolean}} [stream]
 * @param {object} [env]
 * @returns {boolean}
 */
export function supportsColor(stream = process.stdout, env = process.env) {
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') return false;
  if (env.FORCE_COLOR === '1') return true;
  return Boolean(stream && stream.isTTY);
}

/**
 * Render a scan result as a terminal report.
 *
 * @param {object} result
 * @param {object} [options]
 * @param {boolean} [options.color] Force color on or off.
 * @param {string} [options.version] Tool version string.
 * @param {number} [options.maxFindings] Cap the number of printed findings.
 * @param {boolean} [options.quiet] Print only the summary line.
 * @returns {string}
 */
export function formatTerminal(result, options = {}) {
  const color = options.color === undefined ? false : Boolean(options.color);
  const quiet = options.quiet === true;
  const maxFindings = Number.isInteger(options.maxFindings) && options.maxFindings > 0 ? options.maxFindings : Infinity;
  const version = options.version ?? '0.1.1';
  const out = [];

  if (!quiet) {
    out.push(paint(color, ANSI.bold, `sentinel-lint ${version}`));
    out.push(paint(color, ANSI.gray, `scan root ${clean(result.root)}`));
    out.push('');
  }

  const visible = quiet ? [] : result.findings.slice(0, maxFindings === Infinity ? undefined : maxFindings);
  let currentFile = null;
  let printed = 0;

  for (const finding of visible) {
    if (finding.file !== currentFile) {
      if (currentFile !== null) out.push('');
      currentFile = finding.file;
      out.push(paint(color, ANSI.bold, clean(currentFile ?? '(repository)')));
    }
    const position = `${finding.line}:${finding.column}`.padEnd(9);
    const severity = finding.severity.toUpperCase().padEnd(8);
    const head = [
      paint(color, ANSI.gray, position),
      paint(color, SEVERITY_COLOR[finding.severity] ?? ANSI.yellow, severity),
      paint(color, ANSI.dim, finding.ruleId),
    ].join(' ');
    out.push(`  ${head}  ${clean(finding.message)}`);
    if (finding.fix !== null) {
      out.push(`  ${' '.repeat(9)} ${paint(color, ANSI.gray, `fix: ${clean(finding.fix)}`)}`);
    }
    printed += 1;
  }

  if (!quiet && result.findings.length > printed) {
    out.push('');
    out.push(
      paint(color, ANSI.gray, `${result.findings.length - printed} more ${plural(
        result.findings.length - printed,
        'finding',
      )} not shown (raise --max-findings to see them)`),
    );
  }

  if (out.length > 0) out.push('');

  const { bySeverity } = result.summary;
  const parts = [];
  for (const severity of ['critical', 'error', 'warning', 'info']) {
    if (bySeverity[severity] > 0) parts.push(`${bySeverity[severity]} ${severity}`);
  }

  const findingCount = result.summary.findings;
  const summaryParts = [
    `${result.summary.filesScanned} ${plural(result.summary.filesScanned, 'file')} scanned`,
    findingCount === 0
      ? paint(color, ANSI.cyan, 'no findings')
      : `${findingCount} ${plural(findingCount, 'finding')} (${parts.join(', ')})`,
  ];
  if (result.summary.suppressed > 0) {
    summaryParts.push(`${result.summary.suppressed} suppressed`);
  }
  out.push(summaryParts.join(', '));

  if (result.diagnostics.length > 0) {
    out.push(paint(color, ANSI.gray, `${result.diagnostics.length} ${plural(result.diagnostics.length, 'diagnostic')}`));
    if (!quiet) {
      for (const diagnostic of result.diagnostics.slice(0, 10)) {
        out.push(
          paint(
            color,
            ANSI.gray,
            `  ${clean(diagnostic.code)}: ${clean(diagnostic.message)}`,
          ),
        );
      }
      if (result.diagnostics.length > 10) {
        out.push(paint(color, ANSI.gray, `  ... ${result.diagnostics.length - 10} more`));
      }
    }
  }

  return `${out.join('\n')}\n`;
}
