/**
 * Built in rule pack. Every entry is a normal rule that any contributor could
 * have written: one descriptor, one check function, no special casing in the
 * engine.
 */

import { actionRules } from './actions.mjs';
import { mcpRules } from './mcp.mjs';
import { repoRules } from './repo.mjs';

export const BUILTIN_RULES = Object.freeze([...actionRules, ...mcpRules, ...repoRules]);
export const RULE_COUNT = BUILTIN_RULES.length;

/**
 * @returns {readonly object[]}
 */
export function loadBuiltinRules() {
  return BUILTIN_RULES;
}
