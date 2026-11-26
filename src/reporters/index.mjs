/**
 * Reporter registry.
 *
 * A reporter is a pure function from (scanResult, options) to a string. The
 * CLI selects one by name, and the public API exposes the same functions so a
 * consumer can render results without spawning a process.
 */

import { formatJson, toJson } from './json.mjs';
import { formatSarif, toSarif } from './sarif.mjs';
import { formatTerminal } from './terminal.mjs';

export { formatJson, toJson, JSON_REPORT_VERSION } from './json.mjs';
export { formatSarif, toSarif, SARIF_SCHEMA, SARIF_VERSION } from './sarif.mjs';
export { formatTerminal, supportsColor } from './terminal.mjs';

/**
 * Supported reporter names.
 */
export const REPORTER_NAMES = Object.freeze(['terminal', 'json', 'sarif']);

const FORMATTERS = Object.freeze({
  terminal: formatTerminal,
  json: formatJson,
  sarif: formatSarif,
});

/**
 * Render a scan result with the named reporter.
 * @param {string} name One of REPORTER_NAMES.
 * @param {object} result
 * @param {object} [options]
 * @returns {string}
 */
export function formatReport(name, result, options = {}) {
  const formatter = FORMATTERS[name];
  if (formatter === undefined) {
    throw new TypeError(`unknown reporter "${name}"; expected one of ${REPORTER_NAMES.join(', ')}`);
  }
  return formatter(result, options);
}
