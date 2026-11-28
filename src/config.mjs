/**
 * Configuration loading and validation.
 *
 * The config file is `.sentinelrc.json` at the scan root or in the current
 * working directory. JSON is accepted with comments and trailing commas to
 * keep hand written configs pleasant.
 */

import { promises as fs, realpathSync } from 'node:fs';
import path from 'node:path';
import { assertValidGlob } from './globs.mjs';
import { isValidImageRepositoryPrefix } from './image-ref.mjs';
import { jsonToValue, parseJsonDocument, JsonDocumentError } from './json-pos.mjs';
import { SEVERITIES } from './rule-api.mjs';

export const CONFIG_FILE = '.sentinelrc.json';

export const DEFAULT_CONFIG = Object.freeze({
  failOn: 'warning',
  include: Object.freeze([]),
  exclude: Object.freeze([]),
  rules: Object.freeze({}),
  plugins: Object.freeze([]),
  trustedActions: Object.freeze([]),
  trustedNonRootImages: Object.freeze([]),
  trustedArtifactOnlyScratchStages: Object.freeze([]),
  trustedActionsLockEnforcement: false,
  maxFileSize: 1024 * 1024,
  maxFiles: 20000,
});

const KNOWN_KEYS = new Set([
  '$schema',
  'failOn',
  'include',
  'exclude',
  'rules',
  'plugins',
  'trustedActions',
  'trustedNonRootImages',
  'trustedArtifactOnlyScratchStages',
  'trustedActionsLockEnforcement',
  'maxFileSize',
  'maxFiles',
]);

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validateGlobArray(value, key) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new ConfigError(`"${key}" must be an array of glob strings`);
  for (const pattern of value) {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      throw new ConfigError(`"${key}" contains a non-string or empty glob`);
    }
    try {
      assertValidGlob(pattern);
    } catch (error) {
      throw new ConfigError(`"${key}" contains an invalid glob: ${error.message}`);
    }
  }
  return [...value];
}

function validateTrustedActions(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ConfigError('"trustedActions" must be an array of action path prefixes');
  }
  const trusted = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.trim().length === 0) {
      throw new ConfigError('"trustedActions" contains a non-string or empty action path prefix');
    }
    const normalized = entry.trim();
    if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+){0,4}$/.test(normalized)) {
      throw new ConfigError(`"trustedActions" entry "${normalized}" must look like owner, owner/repo or owner/repo/path`);
    }
    trusted.push(normalized);
  }
  return trusted;
}

function validateTrustedNonRootImages(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ConfigError('"trustedNonRootImages" must be an array of image repository prefixes');
  }
  const trusted = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.trim().length === 0) {
      throw new ConfigError('"trustedNonRootImages" contains a non-string or empty image repository prefix');
    }
    const normalized = entry.trim();
    if (!isValidImageRepositoryPrefix(normalized)) {
      throw new ConfigError(
        `"trustedNonRootImages" entry "${normalized}" must be a valid lowercase image repository or namespace prefix without whitespace, a tag or a digest`,
      );
    }
    trusted.push(normalized);
  }
  return trusted;
}

function validateTrustedArtifactOnlyScratchStages(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ConfigError('"trustedArtifactOnlyScratchStages" must be an array of Dockerfile stage names');
  }
  const trusted = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || !/^[A-Za-z][A-Za-z0-9_.-]*$/.test(entry)) {
      throw new ConfigError('"trustedArtifactOnlyScratchStages" entries must be valid Dockerfile stage names');
    }
    trusted.push(entry.toLowerCase());
  }
  return trusted;
}

function validateTrustedActionsLockEnforcement(value) {
  if (value === undefined) return false;
  if (typeof value !== 'boolean') {
    throw new ConfigError('"trustedActionsLockEnforcement" must be a boolean');
  }
  return value;
}

function validatePositiveInteger(value, key, fallback) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value <= 0) {
    throw new ConfigError(`"${key}" must be a positive integer`);
  }
  return value;
}

function pathInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function canonicalRealpath(candidate) {
  const realpath = realpathSync.native ?? realpathSync;
  return realpath(candidate);
}

function canonicalLocation(candidate) {
  return path.join(canonicalRealpath(path.dirname(candidate)), path.basename(candidate));
}

function policyProvenance(root, configPath) {
  try {
    return {
      realRoot: canonicalRealpath(root),
      location: canonicalLocation(configPath),
      target: canonicalRealpath(configPath),
    };
  } catch {
    return null;
  }
}

/**
 * Validate a parsed configuration object and merge it with defaults.
 * @param {unknown} raw
 * @returns {{config: object, warnings: string[]}}
 */
export function validateConfig(raw) {
  if (raw === undefined || raw === null) {
    return { config: { ...DEFAULT_CONFIG }, warnings: [] };
  }
  if (!isPlainObject(raw)) throw new ConfigError('configuration must be a JSON object');

  const warnings = [];
  for (const key of Object.keys(raw)) {
    if (!KNOWN_KEYS.has(key)) warnings.push(`unknown configuration key "${key}" ignored`);
  }

  let failOn = DEFAULT_CONFIG.failOn;
  if (raw.failOn !== undefined) {
    if (raw.failOn !== 'off' && raw.failOn !== 'none' && !SEVERITIES.includes(raw.failOn)) {
      throw new ConfigError(`"failOn" must be one of ${SEVERITIES.join(', ')}, off or none`);
    }
    failOn = raw.failOn;
  }

  const include = validateGlobArray(raw.include, 'include');
  const exclude = validateGlobArray(raw.exclude, 'exclude');

  const rules = {};
  if (raw.rules !== undefined) {
    if (!isPlainObject(raw.rules)) throw new ConfigError('"rules" must be an object mapping rule ids to severities');
    for (const [ruleId, value] of Object.entries(raw.rules)) {
      if (typeof value !== 'string') {
        throw new ConfigError(`rules["${ruleId}"] must be a severity string or "off"`);
      }
      if (value !== 'off' && !SEVERITIES.includes(value)) {
        throw new ConfigError(`rules["${ruleId}"] has invalid severity "${value}"`);
      }
      rules[ruleId] = value;
    }
  }

  const plugins = [];
  if (raw.plugins !== undefined) {
    if (!Array.isArray(raw.plugins)) throw new ConfigError('"plugins" must be an array of module paths');
    for (const plugin of raw.plugins) {
      if (typeof plugin !== 'string' || plugin.length === 0) {
        throw new ConfigError('"plugins" contains a non-string or empty path');
      }
      plugins.push(plugin);
    }
  }

  const config = {
    failOn,
    include,
    exclude,
    rules,
    plugins,
    trustedActions: validateTrustedActions(raw.trustedActions),
    trustedNonRootImages: validateTrustedNonRootImages(raw.trustedNonRootImages),
    trustedArtifactOnlyScratchStages: validateTrustedArtifactOnlyScratchStages(raw.trustedArtifactOnlyScratchStages),
    trustedActionsLockEnforcement: validateTrustedActionsLockEnforcement(raw.trustedActionsLockEnforcement),
    maxFileSize: validatePositiveInteger(raw.maxFileSize, 'maxFileSize', DEFAULT_CONFIG.maxFileSize),
    maxFiles: validatePositiveInteger(raw.maxFiles, 'maxFiles', DEFAULT_CONFIG.maxFiles),
  };

  return { config, warnings };
}

/**
 * Load the effective configuration.
 *
 * @param {object} [options]
 * @param {string} [options.root] Scan root, used to discover the config file.
 * @param {string} [options.configPath] Explicit config path, must exist.
 * @param {string} [options.cwd] Base for relative paths, default process.cwd().
 * @returns {Promise<{config: object, path: string|null, configDir: string, warnings: string[]}>}
 */
export async function loadConfig(options = {}) {
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const root = path.resolve(options.root ?? cwd);
  let configPath = null;

  if (options.configPath !== undefined) {
    const candidate = path.resolve(cwd, options.configPath);
    try {
      const stat = await fs.stat(candidate);
      if (!stat.isFile()) throw new ConfigError(`config path is not a file: ${path.basename(candidate)}`);
    } catch (error) {
      if (error instanceof ConfigError) throw error;
      throw new ConfigError(`config file not found: ${path.basename(candidate)}`);
    }
    configPath = candidate;
  } else {
    for (const candidate of [path.join(root, CONFIG_FILE), path.join(cwd, CONFIG_FILE)]) {
      try {
        const stat = await fs.stat(candidate);
        if (stat.isFile()) {
          configPath = candidate;
          break;
        }
      } catch {
        // Not present, keep looking.
      }
    }
  }

  if (configPath === null) {
    return {
      config: {
        ...DEFAULT_CONFIG,
        include: [],
        exclude: [],
        rules: {},
        plugins: [],
        trustedActions: [],
        trustedNonRootImages: [],
        trustedArtifactOnlyScratchStages: [],
        trustedActionsLockEnforcement: false,
      },
      path: null,
      configDir: root,
      warnings: [],
    };
  }

  const provenance = policyProvenance(root, configPath);
  let text;
  try {
    text = await fs.readFile(provenance === null ? configPath : provenance.target, 'utf8');
  } catch (error) {
    throw new ConfigError(`could not read config file ${path.basename(configPath)}: ${error.code ?? error.message}`);
  }

  let raw;
  try {
    raw = jsonToValue(parseJsonDocument(text, { maxDepth: 64 }));
  } catch (error) {
    if (error instanceof JsonDocumentError) {
      throw new ConfigError(`invalid JSON in config file ${path.basename(configPath)}: ${error.message}`);
    }
    throw error;
  }

  const { config, warnings } = validateConfig(raw);
  if (config.trustedActionsLockEnforcement === true) {
    if (provenance === null) {
      config.trustedActionsLockEnforcement = false;
      warnings.push('"trustedActionsLockEnforcement" ignored because the config file location could not be resolved; use a config file outside the scan root or pass the policy through the scan API');
    } else if (
      pathInside(provenance.realRoot, configPath) ||
      pathInside(provenance.realRoot, provenance.location) ||
      pathInside(provenance.realRoot, provenance.target)
    ) {
      config.trustedActionsLockEnforcement = false;
      warnings.push('"trustedActionsLockEnforcement" ignored because the config file is inside the scan root; use a config file outside the scan root or pass the policy through the scan API');
    }
  }

  return {
    config,
    path: configPath,
    configDir: path.dirname(configPath),
    warnings,
  };
}
