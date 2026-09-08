#!/usr/bin/env node
/*
 * tests/check-seam.mjs — src/seam.mjs is the seam, unedited.
 *
 * The checks this tool makes are the door's own: canonical JSON, did:key, the signed card
 * envelope. They used to come from `@muretai/agent-entry`, which meant this package carried a
 * dependency on a whole door to borrow nine names out of it, pinned four minors behind. They
 * now come from `src/seam.mjs`, a verbatim copy of the seam — the wire/crypto layer whose home
 * is https://github.com/muretai/agent-seam (named agent-wire until 2026-09-07). Those are the
 * bytes the door carries, and the bytes every other implementation of this protocol reproduces.
 *
 * The price of a copy is drift, and a drift here is silent: this checker would go on grading
 * strangers' sites against bytes nobody else uses. So the copy is pinned twice, and the first
 * pin needs NOTHING outside this repository to sound:
 *   digest    always: src/seam.mjs equals EXPECTED, the sha256 recorded the day it was vendored
 *   sibling   only when an agent-seam checkout is beside this one (../agent-seam, or wherever
 *             MURETAI_AGENT_SEAM points): the copy is exactly what
 *             `git show PINNED_COMMIT:js/seam.mjs` produces there — so the pin cannot name a
 *             commit it was not taken from — and this prints how many commits behind that
 *             checkout's HEAD the pin is, and whether its working tree still equals the copy.
 *             Being behind is information, not a failure: this package re-vendors at its own
 *             pace. A missing sibling is one `skip:` line and exit 0 — never a failure.
 *
 * Nothing here writes into agent-seam; nothing there writes into this repository.
 *
 * Re-vendor:  git -C ../agent-seam show <tag>:js/seam.mjs > src/seam.mjs
 *             then update PINNED_* and EXPECTED below:
 *               git -C ../agent-seam rev-parse '<tag>^{commit}'         → PINNED_COMMIT
 *               git -C ../agent-seam show -s --format=%cs <tag>          → PINNED_DATE
 *               git -C ../agent-seam show <tag>:package.json | grep version → PINNED_VERSION
 *               shasum -a 256 src/seam.mjs                               → EXPECTED
 * Run:        node tests/check-seam.mjs        npm test
 *             MURETAI_AGENT_SEAM=/path/to/agent-seam npm test
 */

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** agent-seam v0.2.0 (f93d595): js/seam.mjs as vendored on 2026-09-07. Written by hand from the
 *  commands in the header; tests/check-seam.mjs (this file) holds src/seam.mjs to these. */
const PINNED_REF = 'v0.2.2';
const PINNED_COMMIT = 'c5f5fc505ec3e7961449a5966464d2840efdf2f1';
const PINNED_VERSION = '0.2.2';
const PINNED_DATE = '2026-09-08';
const PINNED_SOURCE = 'js/seam.mjs';
/** sha256 of src/seam.mjs as written at that commit. */
const EXPECTED = '887199c4d4114f1a7ca156da022d6be42c8a31dce46544a1734ef93a42734e56';

const sha = (b) => createHash('sha256').update(b).digest('hex');
let pass = 0;
let failed = false;
function check(ok, okLine, failLines) {
  if (ok) { pass += 1; console.log(`ok: ${okLine}`); return true; }
  failed = true;
  console.log(`FAIL: ${failLines[0]}`);
  for (const l of failLines.slice(1)) console.log(`   ${l}`);
  return false;
}

// ---------------------------------------------------------------- the digest, always
const mine = readFileSync(join(ROOT, 'src', 'seam.mjs'));
const got = sha(mine);
check(got === EXPECTED,
      `src/seam.mjs is the vendored seam (${got.slice(0, 12)}…, ${mine.length} bytes)`,
      ['src/seam.mjs does not match the digest recorded when it was vendored',
       `recorded ${EXPECTED.slice(0, 12)}…  found ${got.slice(0, 12)}…`,
       'Either it was edited here (it must not be — edit it upstream, in agent-seam) or it was',
       're-vendored without updating EXPECTED and PINNED_* in this file.']);

// ---------------------------------------------------------------- the sibling, only when it is there
const siblingRoot = resolve(ROOT, process.env.MURETAI_AGENT_SEAM || '../agent-seam');
const sibling = existsSync(join(siblingRoot, '.git'));
if (!sibling) {
  console.log(`skip: no agent-seam checkout at ${siblingRoot} — compared against the recorded digest only (set MURETAI_AGENT_SEAM to check the recorded commit too)`);
} else {
  const git = (...a) => execFileSync('git', ['-C', siblingRoot, ...a], { stdio: ['ignore', 'pipe', 'pipe'] });
  let known = true;
  try { git('cat-file', '-e', `${PINNED_COMMIT}^{commit}`); } catch { known = false; }
  if (check(known,
            `agent-seam at ${siblingRoot} has the pinned commit ${PINNED_COMMIT.slice(0, 7)} (${PINNED_REF})`,
            [`${siblingRoot} does not have commit ${PINNED_COMMIT.slice(0, 12)} — a stale checkout, or a pin that lies`,
             'Fetch there, or point MURETAI_AGENT_SEAM at a checkout that has it.'])) {
    let theirs = null;
    try { theirs = git('show', `${PINNED_COMMIT}:${PINNED_SOURCE}`); } catch { /* reported below */ }
    check(theirs !== null && theirs.equals(mine),
          `it is exactly what ${PINNED_COMMIT.slice(0, 7)}:${PINNED_SOURCE} produces — the pin is honest`,
          theirs === null
            ? [`${PINNED_COMMIT.slice(0, 7)} has no ${PINNED_SOURCE}`]
            : [`the pin lies: ${PINNED_SOURCE} at ${PINNED_COMMIT.slice(0, 7)} is ${sha(theirs).slice(0, 12)}…, the copy here is ${got.slice(0, 12)}…`,
               'Re-vendor from the commit you record, or record the commit you vendored from.']);
    const behind = git('rev-list', '--count', `${PINNED_COMMIT}..HEAD`).toString().trim();
    const head = git('rev-parse', '--short', 'HEAD').toString().trim();
    console.log(`sibling: pin ${PINNED_REF} (${PINNED_COMMIT.slice(0, 7)}, agent-seam ${PINNED_VERSION}, ${PINNED_DATE}) is ${behind} commit(s) behind ${siblingRoot}'s HEAD ${head}`);
    const tree = join(siblingRoot, PINNED_SOURCE);
    if (!existsSync(tree)) {
      console.log(`note: that checkout has no ${PINNED_SOURCE} in its working tree`);
    } else if (sha(readFileSync(tree)) === got) {
      console.log(`note: its working-tree ${PINNED_SOURCE} still equals the copy byte for byte`);
    } else {
      console.log(`note: its working-tree ${PINNED_SOURCE} differs from the copy — the seam moved on${behind === '0' ? ' (uncommitted edits, or another branch)' : ''}; re-vendor when ready`);
    }
  }
}

// A count nobody asserts is a count that can quietly fall.
const FLOOR = sibling ? 3 : 1;
if (!failed && pass < FLOOR) {
  console.log(`FAIL: only ${pass} check(s) ran, and at least ${FLOOR} were expected — read the rows above`);
  failed = true;
}
if (!failed) console.log(`OK — ${pass} check(s): src/seam.mjs is the seam as vendored at ${PINNED_REF} (${PINNED_COMMIT.slice(0, 7)}, agent-seam ${PINNED_VERSION}).`);
process.exit(failed ? 1 : 0);
