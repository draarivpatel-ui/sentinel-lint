/**
 * The public rule contract.
 *
 * A rule is a plain object with a stable id, a severity, an optional file
 * matcher and a check function. `defineRule` validates the descriptor once at
 * load time so a contributor gets a precise error instead of a runtime crash
 * in the middle of a scan.
 */

export const SEVERITIES = Object.freeze(['info', 'warning', 'error', 'critical']);

const SEVERITY_RANK = Object.freeze({
  info: 0,
  warning: 1,
  error: 2,
  critical: 3,
});

const RULE_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\/[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const CWE_PATTERN = /^CWE-\d{1,5}$/;
const SCOPES = Object.freeze(['file', 'repo']);

/**
 * Rules created by defineRule. Validation runs once per rule at load time;
 * a plugin may export the object it built with defineRule, and the loader
 * must not pay for or risk a second pass over frozen output.
 */
const definedRules = new WeakSet();

export class RuleDefinitionError extends TypeError {
  constructor(message) {
    super(message);
    this.name = 'RuleDefinitionError';
  }
}

/**
 * Return the numeric rank for a severity. Unknown severities rank below info.
 * @param {string} severity
 * @returns {number}
 */
export function severityRank(severity) {
  return Object.hasOwn(SEVERITY_RANK, severity) ? SEVERITY_RANK[severity] : -1;
}

/**
 * True when `severity` is at or above `threshold`.
 * A threshold of "off" never matches.
 * @param {string} severity
 * @param {string} threshold
 * @returns {boolean}
 */
export function meetsThreshold(severity, threshold) {
  if (threshold === 'off' || threshold === 'none') return false;
  const need = severityRank(threshold);
  if (need < 0) return false;
  return severityRank(severity) >= need;
}

/**
 * Validate and freeze a rule descriptor.
 *
 * @param {object} descriptor
 * @param {string} descriptor.id Stable id in the form "category/rule-name".
 * @param {string} descriptor.title One line human title.
 * @param {string} descriptor.severity One of info, warning, error, critical.
 * @param {string} [descriptor.category] Defaults to the id prefix.
 * @param {string} [descriptor.cwe] Optional CWE identifier, for example "CWE-798".
 * @param {string} [descriptor.docsUrl] Absolute or repository relative docs link.
 * @param {string} [descriptor.rationale] Why the rule exists, used in SARIF.
 * @param {string} [descriptor.fix] Actionable remediation text.
 * @param {string[]} [descriptor.appliesTo] Glob patterns for file rules.
 * @param {(file: object) => boolean} [descriptor.match] Custom file matcher.
 * @param {(ctx: object) => (object[] | void)} descriptor.check Rule body.
 * @param {"file" | "repo"} [descriptor.scope] Defaults to "file".
 * @returns {Readonly<object>}
 */
export function defineRule(descriptor) {
  if (descriptor === null || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    throw new RuleDefinitionError('defineRule expects a plain object');
  }
  if (definedRules.has(descriptor)) return descriptor;

  const { id, title, severity, check } = descriptor;

  if (typeof id !== 'string' || !RULE_ID_PATTERN.test(id)) {
    throw new RuleDefinitionError(
      'rule id must look like "category/rule-name" using lowercase letters, digits and hyphens',
    );
  }
  if (typeof title !== 'string' || title.trim().length === 0) {
    throw new RuleDefinitionError(`rule "${id}" needs a non-empty title`);
  }
  if (!SEVERITIES.includes(severity)) {
    throw new RuleDefinitionError(
      `rule "${id}" has severity "${String(severity)}"; expected one of ${SEVERITIES.join(', ')}`,
    );
  }
  if (typeof check !== 'function') {
    throw new RuleDefinitionError(`rule "${id}" needs a check(ctx) function`);
  }

  const category = descriptor.category ?? id.slice(0, id.indexOf('/'));
  if (typeof category !== 'string' || category.length === 0) {
    throw new RuleDefinitionError(`rule "${id}" has an invalid category`);
  }

  if (
    descriptor.cwe !== undefined &&
    descriptor.cwe !== null &&
    (typeof descriptor.cwe !== 'string' || !CWE_PATTERN.test(descriptor.cwe))
  ) {
    throw new RuleDefinitionError(`rule "${id}" has an invalid cwe value; expected the form CWE-798`);
  }

  if (
    descriptor.docsUrl !== undefined &&
    descriptor.docsUrl !== null &&
    (typeof descriptor.docsUrl !== 'string' || descriptor.docsUrl.length === 0)
  ) {
    throw new RuleDefinitionError(`rule "${id}" has an invalid docsUrl`);
  }

  if (
    descriptor.rationale !== undefined &&
    descriptor.rationale !== null &&
    typeof descriptor.rationale !== 'string'
  ) {
    throw new RuleDefinitionError(`rule "${id}" has an invalid rationale; expected a string`);
  }

  if (descriptor.fix !== undefined && descriptor.fix !== null && typeof descriptor.fix !== 'string') {
    throw new RuleDefinitionError(`rule "${id}" has an invalid fix; expected a string`);
  }

  let appliesTo = [];
  if (descriptor.appliesTo !== undefined) {
    if (!Array.isArray(descriptor.appliesTo)) {
      throw new RuleDefinitionError(`rule "${id}" has an invalid appliesTo; expected an array of globs`);
    }
    for (const pattern of descriptor.appliesTo) {
      if (typeof pattern !== 'string' || pattern.length === 0) {
        throw new RuleDefinitionError(`rule "${id}" has a non-string glob in appliesTo`);
      }
    }
    appliesTo = [...descriptor.appliesTo];
  }

  const match = descriptor.match ?? null;
  if (match !== null && typeof match !== 'function') {
    throw new RuleDefinitionError(`rule "${id}" has an invalid match; expected a function`);
  }

  const scope = descriptor.scope ?? 'file';
  if (!SCOPES.includes(scope)) {
    throw new RuleDefinitionError(`rule "${id}" has scope "${String(scope)}"; expected "file" or "repo"`);
  }

  if (scope === 'file' && match === null && appliesTo.length === 0) {
    throw new RuleDefinitionError(
      `file rule "${id}" needs appliesTo globs or a match(file) function`,
    );
  }

  const rule = Object.freeze({
    ...descriptor,
    id,
    title,
    severity,
    category,
    scope,
    cwe: descriptor.cwe ?? null,
    docsUrl: descriptor.docsUrl ?? null,
    rationale: descriptor.rationale ?? '',
    fix: descriptor.fix ?? null,
    appliesTo: Object.freeze(appliesTo),
    match,
    check,
  });
  definedRules.add(rule);
  return rule;
}
