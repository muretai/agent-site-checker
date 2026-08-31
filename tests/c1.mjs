/**
 * tests/c1.mjs — T123 C1 only.
 *
 * C1: a conformant fixture (real HTTPS, document.modelContext, exposedTo set,
 * Permissions-Policy: tools sent) exits 0 with failed: 0.
 *
 * Obtained the way a user obtains it: the shipped CLI is spawned against a real
 * server over the network. Assertions are exit status and --json only.
 * This file does not import the checker's detection functions.
 *
 * C2–C9 live in tests/t123.mjs.
 */

import { siteWithWebmcp } from './fixtures.mjs';
import { runShippedChecker, checkerEnv } from './spawn-checker.mjs';

let passed = 0;
const failures = [];
function ok(cond, label, detail = '') {
  if (cond) { passed++; console.log(`  ok   ${label}`); }
  else { failures.push(label); console.log(`  FAIL ${label}${detail ? `  (${detail})` : ''}`); }
}

console.log('\n=== T123 C1 — conformant WebMCP fixture over real TLS ===');

{
  const site = await siteWithWebmcp({ tls: true });
  const { code, json } = await runShippedChecker(site.origin, checkerEnv(site));
  ok(code === 0, 'C1: shipped checker exits 0', `exit ${code}`);
  ok(Array.isArray(json?.summary?.failed) && json.summary.failed.length === 0,
     'C1: --json summary.failed is 0',
     json ? JSON.stringify(json.summary.failed) : 'no json');
  await site.close();
}

{
  // Producer mutation of the fixture's TLS: same page, same Permissions-Policy,
  // plain HTTP. If this stays green, C1 is not testing HTTPS.
  const site = await siteWithWebmcp({ tls: false });
  const { code, json } = await runShippedChecker(site.origin);
  ok(code !== 0, 'C1 mutation: neutered TLS exits non-zero', `exit ${code}`);
  ok(Array.isArray(json?.summary?.failed) && json.summary.failed.length > 0,
     'C1 mutation: --json summary.failed is non-empty',
     json ? JSON.stringify(json.summary.failed) : 'no json');
  await site.close();
}

console.log(`\n${'-'.repeat(60)}`);
console.log(`C1: ${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log('failed: ' + failures.join('; '));
  process.exit(1);
}
