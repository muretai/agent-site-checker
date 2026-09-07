#!/usr/bin/env node
/*
 * tests/check-wire.mjs — src/wire.mjs is the wire layer, unedited.
 *
 * The checks this tool makes are the door's own: canonical JSON, did:key, the signed card
 * envelope. They used to come from `@muretai/agent-entry`, which meant this package carried a
 * dependency on a whole door to borrow nine names out of it, pinned four minors behind. They
 * now come from `src/wire.mjs`, a verbatim copy of the wire layer that
 * https://github.com/muretai/agent-wire publishes on its own — the same bytes the door
 * carries, and the same bytes every other implementation of this protocol reproduces.
 *
 * The price of a copy is drift, and a drift here is silent: this checker would go on grading
 * strangers' sites against bytes nobody else uses. So the copy is pinned two ways. When
 * agent-wire is checked out beside this repository the copy must equal it; always, the copy
 * must equal the digest recorded here on the day it was vendored. The second half is what
 * runs on a machine that has only this package.
 *
 * Re-vendor:  cp ../agent-wire/js/wire.mjs src/wire.mjs   (then update EXPECTED, below)
 * Run:        node tests/check-wire.mjs        npm test
 */

import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** sha256 of agent-wire's js/wire.mjs as vendored on 2026-09-07 (agent-wire main 9f0c648). */
const EXPECTED = '21fbf01e6538f49059b88f9c32662c67fae133b7d8ec6cd28ec89d917aab61e1';

const mine = readFileSync(join(ROOT, 'src', 'wire.mjs'));
const got = createHash('sha256').update(mine).digest('hex');
let failed = false;

if (got === EXPECTED) {
  console.log(`ok: src/wire.mjs is the vendored wire layer (${got.slice(0, 12)}…, ${mine.length} bytes)`);
} else {
  failed = true;
  console.log(`FAIL: src/wire.mjs does not match the digest recorded when it was vendored`);
  console.log(`   recorded ${EXPECTED.slice(0, 12)}…  found ${got.slice(0, 12)}…`);
  console.log('   Either it was edited here (it must not be — edit it upstream) or it was');
  console.log('   re-vendored without updating EXPECTED in this file.');
}

const wireRoot = resolve(ROOT, process.env.MURETAI_AGENT_WIRE || '../agent-wire');
const upstream = join(wireRoot, 'js', 'wire.mjs');
if (!existsSync(upstream)) {
  console.log(`skip: no agent-wire checkout at ${wireRoot} — compared against the recorded digest only`);
} else {
  const theirs = readFileSync(upstream);
  const same = createHash('sha256').update(theirs).digest('hex') === got;
  console.log(same ? 'ok: it matches agent-wire\'s copy byte for byte'
                   : `FAIL: agent-wire's js/wire.mjs has moved — re-vendor it and update EXPECTED`);
  if (!same) failed = true;
}
process.exit(failed ? 1 : 0);
