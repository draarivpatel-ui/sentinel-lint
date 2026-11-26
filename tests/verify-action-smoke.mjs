import { readFile, realpath } from 'node:fs/promises';
import process from 'node:process';

const mode = process.argv[2];
const sarifPath = process.env.SARIF_PATH;
const outputSarif = process.env.OUTPUT_SARIF_FILE;
const findingsCount = Number(process.env.OUTPUT_FINDINGS_COUNT);
const exitCode = process.env.OUTPUT_EXIT_CODE;

function fail(message) {
  console.error(`action smoke verification failed: ${message}`);
  process.exitCode = 1;
}

if (mode !== 'clean' && mode !== 'vulnerable') {
  fail('mode must be clean or vulnerable');
} else if (!sarifPath) {
  fail('SARIF_PATH is missing');
} else if (!outputSarif) {
  fail('sarif-file output is missing');
} else if (!Number.isInteger(findingsCount) || findingsCount < 0) {
  fail('findings-count output is not a non-negative integer');
} else if (exitCode !== '0') {
  fail(`exit-code output was ${exitCode}`);
} else {
  const [expectedPath, emittedPath] = await Promise.all([realpath(sarifPath), realpath(outputSarif)]);
  const samePath =
    process.platform === 'win32'
      ? expectedPath.toLowerCase() === emittedPath.toLowerCase()
      : expectedPath === emittedPath;
  if (!samePath) fail(`sarif-file output ${outputSarif} does not point at ${sarifPath}`);

  const sarif = JSON.parse(await readFile(sarifPath, 'utf8'));
  const results = sarif.runs?.[0]?.results;
  if (sarif.version !== '2.1.0') fail('SARIF version is not 2.1.0');
  if (sarif.$schema !== 'https://json.schemastore.org/sarif-2.1.0.json') fail('SARIF schema is wrong');
  if (!Array.isArray(results)) fail('SARIF results are missing');
  else if (results.length !== findingsCount) fail(`SARIF has ${results.length} results for ${findingsCount} findings`);

  if (mode === 'clean' && findingsCount !== 0) fail(`clean fixture produced ${findingsCount} findings`);
  if (mode === 'vulnerable' && findingsCount === 0) fail('vulnerable fixture produced no findings');

  if (process.exitCode !== 1) {
    console.log(`action smoke ${mode}: ${findingsCount} findings, valid SARIF 2.1.0`);
  }
}
