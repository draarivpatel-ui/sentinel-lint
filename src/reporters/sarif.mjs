/**
 * SARIF 2.1.0 reporter.
 *
 * The output is a single run whose driver is sentinel-lint itself. Every rule
 * that ran appears in driver.rules, and every finding points at a rule index,
 * a repository relative artifact URI and a 1-based region. GitHub code
 * scanning consumes this document directly.
 *
 * Result ordering follows the engine, which sorts by file, line, column and
 * rule id, so two scans of the same tree produce byte identical output.
 */

import { createHash } from 'node:crypto';

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const SARIF_VERSION = '2.1.0';
export const INFORMATION_URI = 'https://github.com/sentinel-lint/sentinel-lint';

const LEVEL_BY_SEVERITY = Object.freeze({
  info: 'note',
  warning: 'warning',
  error: 'error',
  critical: 'error',
});

const SECURITY_SEVERITY = Object.freeze({
  info: '0.0',
  warning: '4.0',
  error: '7.0',
  critical: '9.0',
});

/**
 * Encode a repository relative path as an artifact URI.
 * Spaces become %20 and backslashes become forward slashes.
 * @param {string} filePath
 * @returns {string}
 */
export function artifactUri(filePath) {
  return String(filePath)
    .replace(/\\/g, '/')
    .split('/')
    .map((segment) => encodeURIComponent(segment).replace(/%2F/gi, '/'))
    .join('/');
}

/**
 * Stable fingerprint for a finding. It must not depend on the line number, so
 * a finding that moves down the file is still recognized as the same issue by
 * code scanning alert tracking.
 * @param {object} finding
 * @returns {string}
 */
export function fingerprintFor(finding) {
  const material = [finding.ruleId, finding.file ?? '', finding.message].join('\u0000');
  return createHash('sha256').update(material, 'utf8').digest('hex').slice(0, 32);
}

function sarifRule(rule) {
  const descriptor = {
    id: rule.id,
    name: rule.id.replace(/[^A-Za-z0-9]+/g, '_'),
    shortDescription: { text: rule.title },
    defaultConfiguration: { level: LEVEL_BY_SEVERITY[rule.severity] ?? 'warning' },
    properties: {
      tags: ['security', rule.category],
      precision: 'high',
      'security-severity': SECURITY_SEVERITY[rule.severity] ?? '4.0',
    },
  };

  if (rule.rationale.length > 0) {
    descriptor.fullDescription = { text: rule.rationale };
    descriptor.help = { text: rule.fix === null ? rule.rationale : `${rule.rationale}\n\nRemediation: ${rule.fix}` };
  } else if (rule.fix !== null) {
    descriptor.help = { text: `Remediation: ${rule.fix}` };
  }

  if (rule.docsUrl !== null) descriptor.helpUri = rule.docsUrl;
  if (rule.cwe !== null) descriptor.properties.cwe = rule.cwe;

  return descriptor;
}

function sarifResult(finding, ruleIndex) {
  const location = {
    physicalLocation: {
      artifactLocation: { uri: artifactUri(finding.file ?? '.sentinelrc.json') },
      region: {
        startLine: finding.line,
        startColumn: finding.column,
        ...(finding.endLine === undefined ? {} : { endLine: finding.endLine }),
        ...(finding.endColumn === undefined ? {} : { endColumn: finding.endColumn }),
      },
    },
  };

  return {
    ruleId: finding.ruleId,
    ...(ruleIndex === undefined ? {} : { ruleIndex }),
    level: LEVEL_BY_SEVERITY[finding.severity] ?? 'warning',
    message: { text: finding.message },
    locations: [location],
    partialFingerprints: {
      'sentinelLintFindingHash/v1': fingerprintFor(finding),
    },
    properties: {
      severity: finding.severity,
      category: finding.category,
      ...(finding.cwe === null ? {} : { cwe: finding.cwe }),
    },
  };
}

/**
 * Convert a scan result into a SARIF 2.1.0 log.
 *
 * @param {object} result Result returned by scan().
 * @param {object} [options]
 * @param {string} [options.version] Driver version string.
 * @param {string} [options.informationUri] Driver information URI.
 * @returns {object}
 */
export function toSarif(result, options = {}) {
  const rules = [...result.rules].sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const indexById = new Map(rules.map((rule, index) => [rule.id, index]));

  const notifications = result.diagnostics.map((diagnostic) => ({
    level: 'warning',
    message: { text: diagnostic.message },
    descriptor: { id: diagnostic.code },
    properties: { ...(diagnostic.ruleId === undefined ? {} : { ruleId: diagnostic.ruleId }) },
  }));

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'sentinel-lint',
            version: options.version ?? '0.1.0',
            informationUri: options.informationUri ?? INFORMATION_URI,
            rules: rules.map(sarifRule),
          },
        },
        invocations: [
          {
            executionSuccessful: result.stats.ruleErrors === 0,
            endTimeUtc: new Date(0).toISOString(),
            toolExecutionNotifications: notifications,
            properties: {
              filesScanned: result.summary.filesScanned,
              suppressed: result.summary.suppressed,
            },
          },
        ],
        results: result.findings.map((finding) => sarifResult(finding, indexById.get(finding.ruleId))),
        properties: {
          severityCounts: { ...result.summary.bySeverity },
          suppressed: result.summary.suppressed,
        },
      },
    ],
  };
}

/**
 * Serialize a scan result as SARIF text with a trailing newline.
 * @param {object} result
 * @param {object} [options]
 * @returns {string}
 */
export function formatSarif(result, options = {}) {
  return `${JSON.stringify(toSarif(result, options), null, 2)}\n`;
}
