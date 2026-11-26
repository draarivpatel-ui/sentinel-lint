/**
 * Public API for sentinel-lint.
 *
 * Everything a plugin author, a CI integration or an editor extension needs is
 * exported from here. The CLI is a thin layer over the same functions, so any
 * behavior you can trigger with a flag is also reachable programmatically.
 */

export { VERSION } from './version.mjs';

export { loadConfig, validateConfig, ConfigError, CONFIG_FILE, DEFAULT_CONFIG } from './config.mjs';

export {
  defineRule,
  SEVERITIES,
  RuleDefinitionError,
  meetsThreshold,
  severityRank,
} from './rule-api.mjs';

export { scan, resolveRules } from './engine.mjs';

export { loadBuiltinRules, BUILTIN_RULES, RULE_COUNT } from './rules/index.mjs';

export { loadPluginRules, PluginError } from './plugins.mjs';

export { buildIgnoreMap, hasIgnoreMarkers } from './ignore.mjs';

export { globToRegExp, matchesGlob, matchesAnyGlob, assertValidGlob } from './globs.mjs';

export { walkRepository, DEFAULT_SKIP_DIRS } from './walk.mjs';

export {
  parseJsonDocument,
  jsonToValue,
  JsonDocumentError,
  getMember,
  getEntries,
  stringValue,
  walkJson,
} from './json-pos.mjs';

export {
  REPORTER_NAMES,
  formatReport,
  formatJson,
  formatSarif,
  formatTerminal,
  supportsColor,
  toJson,
  toSarif,
  JSON_REPORT_VERSION,
  SARIF_SCHEMA,
  SARIF_VERSION,
} from './reporters/index.mjs';

export { parseArgv, run, main, UsageError, EXIT_CODES } from './cli.mjs';
