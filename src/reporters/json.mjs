/**
 * Machine readable JSON reporter.
 *
 * The shape is versioned separately from the package version so downstream
 * consumers can pin to it. Fields are ordered deliberately: a diff between two
 * runs shows the numbers first and the findings second.
 */

export const JSON_REPORT_VERSION = 1;

/**
 * Convert a scan result into a plain serializable object.
 * @param {object} result
 * @param {object} [options]
 * @param {string} [options.version] Tool version string.
 * @returns {object}
 */
export function toJson(result, options = {}) {
  return {
    tool: { name: 'sentinel-lint', version: options.version ?? '0.1.1' },
    reportVersion: JSON_REPORT_VERSION,
    summary: {
      filesScanned: result.summary.filesScanned,
      findings: result.summary.findings,
      suppressed: result.summary.suppressed,
      ruleErrors: result.summary.ruleErrors,
      diagnostics: result.summary.diagnostics,
      bySeverity: { ...result.summary.bySeverity },
    },
    findings: result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      category: finding.category,
      cwe: finding.cwe,
      file: finding.file,
      line: finding.line,
      column: finding.column,
      message: finding.message,
      fix: finding.fix,
      docsUrl: finding.docsUrl,
    })),
    diagnostics: result.diagnostics.map((diagnostic) => ({
      code: diagnostic.code,
      ...(diagnostic.ruleId === undefined ? {} : { ruleId: diagnostic.ruleId }),
      message: diagnostic.message,
    })),
    rules: result.rules.map((rule) => ({
      id: rule.id,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      title: rule.title,
    })),
  };
}

/**
 * Serialize a scan result as JSON text with a trailing newline.
 * @param {object} result
 * @param {object} [options]
 * @returns {string}
 */
export function formatJson(result, options = {}) {
  return `${JSON.stringify(toJson(result, options), null, 2)}\n`;
}
