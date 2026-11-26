#!/usr/bin/env node
/**
 * Executable entry point. All logic lives in src/cli.mjs so the tests can run
 * the CLI in process with fake streams.
 */

import { main } from '../src/cli.mjs';

await main();
