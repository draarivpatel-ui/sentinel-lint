/**
 * Type definitions for sentinel-lint 0.1.1.
 *
 * The package ships no JavaScript build step, so these declarations are the
 * contract for editor and TypeScript consumers. They are hand maintained and
 * checked against the runtime exports by tests/types.test.mjs.
 */

export type Severity = 'info' | 'warning' | 'error' | 'critical';
export type FailThreshold = Severity | 'off' | 'none';
export type ReporterName = 'terminal' | 'json' | 'sarif';
export type RuleScope = 'file' | 'repo';

export declare const VERSION: string;
export declare const SEVERITIES: readonly Severity[];
export declare const RULE_COUNT: number;
export declare const CONFIG_FILE: '.sentinelrc.json';
export declare const DEFAULT_CONFIG: Readonly<SentinelConfig>;
export declare const REPORTER_NAMES: readonly ReporterName[];
export declare const SARIF_SCHEMA: string;
export declare const SARIF_VERSION: '2.1.0';
export declare const JSON_REPORT_VERSION: number;

export interface ScannedFile {
  path: string;
  absolutePath: string;
  name: string;
  ext: string;
  size: number;
  text: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: string;
  cwe: string | null;
  docsUrl: string | null;
  fix: string | null;
  file: string | null;
  line: number;
  column: number;
  message: string;
  endLine?: number;
  endColumn?: number;
}

export interface PartialFinding {
  file?: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  message?: string;
}

export type ReportArgument =
  | [partial: PartialFinding]
  | [line: number, column: number, message: string, extra?: Record<string, unknown>];

export interface FileRuleContext {
  path: string;
  file: ScannedFile;
  text: string;
  lines: string[];
  lineCount: number;
  root: string;
  report: (...args: ReportArgument) => void;
}

export interface RepoRuleContext {
  path: null;
  file: null;
  text: '';
  lines: never[];
  lineCount: 0;
  root: string;
  files: ScannedFile[];
  paths: string[];
  read(filePath: string): string | null;
  report: (...args: ReportArgument) => void;
}

export type RuleContext = FileRuleContext | RepoRuleContext;

export interface RuleDescriptor {
  id: string;
  title: string;
  severity: Severity;
  category?: string;
  cwe?: string;
  docsUrl?: string;
  rationale?: string;
  fix?: string;
  appliesTo?: string[];
  match?: (file: ScannedFile) => boolean;
  check: (ctx: RuleContext) => PartialFinding[] | void;
  scope?: RuleScope;
}

export interface Rule {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly category: string;
  readonly scope: RuleScope;
  readonly cwe: string | null;
  readonly docsUrl: string | null;
  readonly rationale: string;
  readonly fix: string | null;
  readonly appliesTo: readonly string[];
  readonly match: ((file: ScannedFile) => boolean) | null;
  readonly check: (ctx: RuleContext) => PartialFinding[] | void;
}

export interface SentinelConfig {
  failOn: FailThreshold;
  include: string[];
  exclude: string[];
  rules: Record<string, Severity | 'off'>;
  plugins: string[];
  maxFileSize: number;
  maxFiles: number;
}

export interface RawConfig {
  $schema?: string;
  failOn?: FailThreshold;
  include?: string[];
  exclude?: string[];
  rules?: Record<string, Severity | 'off'>;
  plugins?: string[];
  maxFileSize?: number;
  maxFiles?: number;
}

export interface ConfigResult {
  config: SentinelConfig;
  path: string | null;
  configDir: string;
  warnings: string[];
}

export interface Diagnostic {
  code: string;
  message: string;
  ruleId?: string;
}

export interface WalkStats {
  directoriesVisited: number;
  filesVisited: number;
  filesScanned: number;
  binarySkipped: number;
  unreadableSkipped: number;
  tooLargeSkipped: number;
  symlinkSkipped: number;
  ignoredSkipped: number;
  limitReached: boolean;
}

export interface WalkResult {
  root: string;
  files: ScannedFile[];
  diagnostics: Diagnostic[];
  stats: WalkStats;
}

export interface ScanStats extends WalkStats {
  suppressed: number;
  ruleErrors: number;
}

export interface ScanSummary {
  filesScanned: number;
  findings: number;
  suppressed: number;
  ruleErrors: number;
  diagnostics: number;
  bySeverity: Record<Severity, number>;
  durationMs: number;
}

export interface ScanResult {
  root: string;
  files: ScannedFile[];
  findings: Finding[];
  diagnostics: Diagnostic[];
  diagnosticsTruncated: number;
  stats: ScanStats;
  summary: ScanSummary;
  rules: Rule[];
}

export interface ScanOptions {
  root?: string;
  config?: Partial<SentinelConfig>;
  rules?: readonly Rule[];
}

export interface LoadConfigOptions {
  root?: string;
  configPath?: string;
  cwd?: string;
}

export interface IgnoreStore {
  all: boolean;
  rules: Set<string>;
}

export interface IgnoreMap {
  fileAll: boolean;
  fileRules: Set<string>;
  lineMap: Map<number, IgnoreStore>;
  isFileIgnored(ruleId?: string): boolean;
  isSuppressed(line: number, ruleId: string): boolean;
}

export interface TerminalOptions {
  color?: boolean;
  version?: string;
  maxFindings?: number;
  quiet?: boolean;
}

export interface JsonOptions {
  version?: string;
}

export interface SarifOptions {
  version?: string;
  informationUri?: string;
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: Record<string, unknown>[];
    };
  };
  invocations: Record<string, unknown>[];
  results: Record<string, unknown>[];
  properties: Record<string, unknown>;
}

export declare class RuleDefinitionError extends TypeError {
  name: 'RuleDefinitionError';
}

export declare class ConfigError extends Error {
  name: 'ConfigError';
}

export declare class PluginError extends Error {
  name: 'PluginError';
}

export declare class JsonDocumentError extends Error {
  name: 'JsonDocumentError';
  line: number;
  column: number;
}

export declare function defineRule(descriptor: RuleDescriptor): Rule;
export declare function severityRank(severity: Severity | string): number;
export declare function meetsThreshold(severity: Severity | string, threshold: FailThreshold): boolean;

export declare function loadConfig(options?: LoadConfigOptions): Promise<ConfigResult>;
export declare function validateConfig(raw: unknown): { config: SentinelConfig; warnings: string[] };

export declare function scan(options?: ScanOptions): Promise<ScanResult>;
export declare function resolveRules(
  rules: readonly Rule[],
  config?: Partial<SentinelConfig>,
): { rules: Rule[]; diagnostics: Diagnostic[] };

export declare function loadBuiltinRules(): readonly Rule[];
export declare const BUILTIN_RULES: readonly Rule[];
export declare function loadPluginRules(pluginPaths: string[], configDir: string): Promise<Rule[]>;

export declare function buildIgnoreMap(text: string): IgnoreMap;
export declare function hasIgnoreMarkers(text: string): boolean;

export declare function globToRegExp(pattern: string): RegExp;
export declare function matchesGlob(filePath: string, pattern: string): boolean;
export declare function matchesAnyGlob(filePath: string, patterns: Iterable<string>): boolean;
export declare function assertValidGlob(pattern: string): void;

export declare function walkRepository(
  root: string,
  options?: {
    maxFileSize?: number;
    maxFiles?: number;
    maxDepth?: number;
    include?: string[];
    exclude?: string[];
    skipDirs?: string[];
  },
): Promise<WalkResult>;

export declare const DEFAULT_SKIP_DIRS: readonly string[];

export interface JsonNode {
  type: 'object' | 'array' | 'string' | 'number' | 'literal';
  line: number;
  column: number;
  value?: unknown;
  entries?: { key: string; keyLine: number; keyColumn: number; value: JsonNode }[];
  items?: JsonNode[];
}

export declare function parseJsonDocument(input: string, options?: { maxDepth?: number }): JsonNode;
export declare function jsonToValue(node: JsonNode): unknown;
export declare function getMember(objectNode: JsonNode | null, key: string): {
  key: string;
  keyLine: number;
  keyColumn: number;
  value: JsonNode;
} | null;
export declare function getEntries(objectNode: JsonNode | null): {
  key: string;
  keyLine: number;
  keyColumn: number;
  value: JsonNode;
}[];
export declare function stringValue(node: JsonNode | null): string | null;
export declare function walkJson(node: JsonNode | null, visit: (node: JsonNode) => void): void;

export declare function formatReport(
  name: ReporterName,
  result: ScanResult,
  options?: TerminalOptions | JsonOptions | SarifOptions,
): string;
export declare function formatTerminal(result: ScanResult, options?: TerminalOptions): string;
export declare function formatJson(result: ScanResult, options?: JsonOptions): string;
export declare function formatSarif(result: ScanResult, options?: SarifOptions): string;
export declare function toJson(result: ScanResult, options?: JsonOptions): Record<string, unknown>;
export declare function toSarif(result: ScanResult, options?: SarifOptions): SarifLog;
export declare function supportsColor(
  stream?: { isTTY?: boolean },
  env?: Record<string, string | undefined>,
): boolean;

export interface CliIo {
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
  cwd?: string;
}

export interface CliOptions {
  command: 'scan' | 'rules' | 'init' | 'help' | 'version';
  target: string | null;
  format: ReporterName | null;
  output: string | null;
  config: string | null;
  failOn: FailThreshold | null;
  quiet: boolean;
  color: boolean | null;
  maxFindings: number | null;
  include: string[];
  exclude: string[];
  plugins: string[];
  force: boolean;
  help: boolean;
  version: boolean;
}

export declare class UsageError extends Error {
  name: 'UsageError';
}

export declare const EXIT_CODES: Readonly<{
  ok: 0;
  findings: 1;
  usage: 2;
  internal: 3;
}>;

export declare function parseArgv(argv: string[]): CliOptions;
export declare function run(argv: string[], io?: CliIo): Promise<number>;
export declare function main(): Promise<void>;
