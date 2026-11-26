/**
 * Inline suppression comments.
 *
 * Supported forms, in any text file:
 *
 *   // sentinel-ignore-next-line
 *   // sentinel-ignore-next-line actions/write-all-permissions, mcp/secret-in-env
 *   const value = eval(input); // sentinel-ignore-line repo/dangerous-eval
 *   // sentinel-ignore-file -- generated fixture
 *
 * A marker with no rule ids suppresses every rule for its target. Rule ids are
 * validated by shape, so free text in a reason cannot accidentally suppress a
 * rule. Everything after "--" is treated as a human reason and ignored.
 */

const MARKER_PATTERN = /sentinel-ignore-(next-line|line|file)\b([^\r\n]*?)(?=sentinel-ignore-|[\r\n]|$)/g;
const RULE_ID_PATTERN = /[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*/g;

function addSuppression(store, ruleIds) {
  if (ruleIds.length === 0) {
    store.all = true;
    return;
  }
  for (const ruleId of ruleIds) store.rules.add(ruleId);
}

function ruleIdsFrom(rest) {
  const withoutReason = rest.split('--')[0];
  return withoutReason.match(RULE_ID_PATTERN) ?? [];
}

/**
 * Build a suppression index for one file.
 *
 * @param {string} text
 * @returns {{
 *   fileAll: boolean,
 *   fileRules: Set<string>,
 *   lineMap: Map<number, {all: boolean, rules: Set<string>}>,
 *   isFileIgnored(ruleId?: string): boolean,
 *   isSuppressed(line: number, ruleId: string): boolean
 * }}
 */
export function buildIgnoreMap(text) {
  const lines = String(text).split('\n');
  const fileRules = new Set();
  const lineMap = new Map();
  let fileAll = false;

  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const occurrences = lines[index].match(MARKER_PATTERN);
    if (occurrences === null) continue;

    MARKER_PATTERN.lastIndex = 0;
    for (const occurrence of occurrences) {
      MARKER_PATTERN.lastIndex = 0;
      const match = MARKER_PATTERN.exec(occurrence);
      if (match === null) continue;
      const kind = match[1];
      const ruleIds = ruleIdsFrom(match[2] ?? '');

      if (kind === 'file') {
        if (ruleIds.length === 0) fileAll = true;
        for (const ruleId of ruleIds) fileRules.add(ruleId);
        continue;
      }

      const targetLine = kind === 'next-line' ? lineNumber + 1 : lineNumber;
      let store = lineMap.get(targetLine);
      if (store === undefined) {
        store = { all: false, rules: new Set() };
        lineMap.set(targetLine, store);
      }
      addSuppression(store, ruleIds);
    }
  }

  function isFileIgnored(ruleId) {
    if (fileAll) return true;
    return typeof ruleId === 'string' && fileRules.has(ruleId);
  }

  function isSuppressed(line, ruleId) {
    if (fileAll || fileRules.has(ruleId)) return true;
    const store = lineMap.get(line);
    if (store === undefined) return false;
    return store.all || store.rules.has(ruleId);
  }

  return { fileAll, fileRules, lineMap, isFileIgnored, isSuppressed };
}

/**
 * True when text contains any suppression marker. Cheap pre-check.
 * @param {string} text
 */
export function hasIgnoreMarkers(text) {
  MARKER_PATTERN.lastIndex = 0;
  return MARKER_PATTERN.test(String(text));
}
