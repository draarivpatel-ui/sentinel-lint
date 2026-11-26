/**
 * Plugin loading for local rule modules.
 *
 * A plugin module may export:
 *   export default rule;                 // one object from defineRule
 *   export default [ruleA, ruleB];       // an array
 *   export const rules = [ruleA];        // named export
 *
 * Plugin code runs in the same process as the scanner, so a config file is
 * trusted input in exactly the same way a package.json script is. Never point
 * sentinel-lint at a config from an untrusted repository without reading the
 * plugin paths first.
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { defineRule } from './rule-api.mjs';

export class PluginError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PluginError';
  }
}

function collectExports(moduleNamespace) {
  const candidates = [];
  if (moduleNamespace.default !== undefined) {
    if (Array.isArray(moduleNamespace.default)) candidates.push(...moduleNamespace.default);
    else candidates.push(moduleNamespace.default);
  }
  if (Array.isArray(moduleNamespace.rules)) candidates.push(...moduleNamespace.rules);
  return candidates;
}

/**
 * Import plugin modules and return validated rules.
 *
 * @param {string[]} pluginPaths Paths from the config file, relative to configDir.
 * @param {string} configDir Absolute directory used to resolve relative paths.
 * @param {object} [options]
 * @param {boolean} [options.allowOutsideConfigDir] Permit paths outside the
 *   config directory. Only the CLI sets this, because the operator named the
 *   file directly. Config sourced paths must stay inside the config tree.
 * @returns {Promise<object[]>}
 */
export async function loadPluginRules(pluginPaths, configDir, options = {}) {
  const allowOutside = options.allowOutsideConfigDir === true;
  let realConfigDir;
  try {
    realConfigDir = await fs.realpath(configDir);
  } catch {
    realConfigDir = path.resolve(configDir);
  }

  const rules = [];
  for (const pluginPath of pluginPaths) {
    const absolute = path.resolve(configDir, pluginPath);
    let stat;
    try {
      stat = await fs.stat(absolute);
    } catch {
      throw new PluginError(`plugin not found: ${pluginPath}`);
    }
    if (!stat.isFile()) throw new PluginError(`plugin path is not a file: ${pluginPath}`);

    // realpath defeats a symlink that points outside the config tree.
    let realPlugin;
    try {
      realPlugin = await fs.realpath(absolute);
    } catch {
      throw new PluginError(`plugin not found: ${pluginPath}`);
    }
    if (!allowOutside) {
      const relative = path.relative(realConfigDir, realPlugin);
      if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        throw new PluginError(`plugin path escapes the config directory: ${pluginPath}`);
      }
    }

    const url = pathToFileURL(realPlugin);
    url.searchParams.set('sentinel', String(stat.mtimeMs));

    let namespace;
    try {
      namespace = await import(url.href);
    } catch (error) {
      throw new PluginError(`could not import plugin ${pluginPath}: ${error.message}`);
    }

    const candidates = collectExports(namespace);
    if (candidates.length === 0) {
      throw new PluginError(`plugin ${pluginPath} exported no rules`);
    }

    for (const candidate of candidates) {
      let rule;
      try {
        rule = defineRule(candidate);
      } catch (error) {
        throw new PluginError(`plugin ${pluginPath} has an invalid rule: ${error.message}`);
      }
      rules.push(rule);
    }
  }
  return rules;
}
