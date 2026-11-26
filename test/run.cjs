'use strict';

// Runs the subpackage tests in their own processes, matching the root suite's
// ELECTRON_RUN_AS_NODE pattern (this repo has no standalone node on PATH).

const { spawnSync } = require('child_process');
const path = require('path');

const TESTS = ['keyring-state.cjs', 'plugin.cjs', 'credential-manager.cjs', 'upstream-integration.cjs'];

const results = [];
for (const testFile of TESTS) {
  const full = path.join(__dirname, testFile);
  console.log(`\n===== zcode-keyring-auth / ${testFile} =====`);
  const env = { ...process.env, ELECTRON_RUN_AS_NODE: '1' };
  const result = spawnSync(process.execPath, [full], {
    stdio: 'inherit',
    env,
    timeout: 120_000,
    windowsHide: true,
  });
  const ok = result.status === 0 && !result.error;
  results.push({ testFile, ok, status: result.status, error: result.error });
  if (!ok) {
    console.error(`${testFile} failed: status=${result.status}${result.error ? ` error=${result.error.message}` : ''}`);
  }
}

console.log('\n===== zcode-keyring-auth summary =====');
for (const result of results) console.log(`${result.ok ? 'PASS' : 'FAIL'}  ${result.testFile}`);
if (results.some((result) => !result.ok)) process.exitCode = 1;
