#!/usr/bin/env node
/**
 * bin/agent-site-checker.mjs — the same check, on your own machine.
 *
 * WHY A CLI EXISTS BESIDE THE HOSTED SERVICE. Two reasons, and neither is convenience.
 * First, exit status: this gates a deploy. Second, and more important, the hosted service
 * refuses private addresses — correctly, because it is a public endpoint that fetches URLs
 * strangers choose — which means the one thing a site owner most wants to check, their own
 * deployment before it is public, is exactly what the hosted service cannot do. That check
 * belongs on their machine, run by them, against a server they own.
 *
 *   npx @muretai/agent-site-checker https://your-site.example
 *   npx @muretai/agent-site-checker --json https://your-site.example
 *   npx @muretai/agent-site-checker --allow-private http://127.0.0.1:8788
 *
 * Exit status is 0 unless a hard check FAILED. Advisories never fail a run: a site that
 * publishes no agent card has not done anything wrong, and a checker that says otherwise is
 * grading a whole category against one yardstick.
 */

import { checkSite } from '../src/engine.mjs';

const argv = process.argv.slice(2);
const flag = (f) => argv.includes(f);
const target = argv.find((a) => !a.startsWith('--'));

if (!target || flag('--help') || flag('-h')) {
  console.log(`agent-site-checker <url> [--json] [--allow-private] [--no-probe] [--no-dns]

  Verify what a website offers an AI agent: the agent card's signature, whether that key
  speaks for this origin, how recently it was signed, whether DNS-AID records sit in a
  DNSSEC-signed zone, and whether a knock reaches the door itself or something in front of it.
  Other agent-facing surfaces are listed as facts and are never graded.

  --json           machine-readable result
  --allow-private  permit loopback and private addresses (your own dev server ONLY)
  --no-probe       do not knock on the door the card advertises
  --no-dns         skip the DNS-AID and DNSSEC lookups

  Do not verify a live deployment with curl instead. It sends its own user agent and sails
  through a CDN bot check that would refuse a real agent — a green curl tells you nothing
  about whether agents can reach you.`);
  process.exit(target ? 0 : 2);
}

const result = await checkSite(target, {
  allowPrivate: flag('--allow-private'),
  probeDoor: !flag('--no-probe'),
  dns: !flag('--no-dns'),
});

if (flag('--json')) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(`Agent Site Checker: ${target}`);
  console.log('-'.repeat(66));
  for (const row of result.rows) {
    const mark = { PASS: 'ok  ', FAIL: 'FAIL', WARN: 'warn', INFO: '--  ' }[row.level];
    console.log(`${mark} ${row.label}${row.detail ? `\n       ${row.detail}` : ''}`);
  }
  console.log('-'.repeat(66));
  console.log(result.verdict);
  if (result.refused) console.log(`refused: ${result.refused}`);
}

process.exit(result.summary?.failed?.length ? 1 : 0);
