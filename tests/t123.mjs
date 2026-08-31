/**
 * tests/t123.mjs — T123 C2–C9, obtained the way a user obtains them.
 *
 * Every assertion is exit status and --json from the shipped CLI, pointed at a
 * real server over the network. This file does not import the checker's
 * detection functions.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { siteWithWebmcp } from './fixtures.mjs';
import { runShippedChecker, checkerEnv } from './spawn-checker.mjs';

let passed = 0;
const failures = [];
function ok(cond, label, detail = '') {
  if (cond) { passed++; console.log(`  ok   ${label}`); }
  else { failures.push(label); console.log(`  FAIL ${label}${detail ? `  (${detail})` : ''}`); }
}
const eq = (a, b, label) => ok(a === b, label, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);

async function against(mutate, tls = true) {
  const site = await siteWithWebmcp({ tls, mutate });
  const run = await runShippedChecker(site.origin, checkerEnv(site));
  await site.close();
  return run;
}

console.log('\n=== T123 C2 — producer mutation, six ways ===');
{
  const cases = [
    ['no-header', 'W3', 'drop header'],
    ['no-allow', 'W4', 'drop allow="tools"'],
    ['no-exposedTo', 'W5', 'drop exposedTo'],
    ['http', 'W2', 'serve plain HTTP'],
    ['bad-schema', 'W6', 'corrupt schema'],
    ['flip-autosubmit', 'W7', 'flip autosubmit'],
  ];
  for (const [mutate, id, how] of cases) {
    const { code, json } = await against(mutate);
    const failed = json?.verification?.webmcp?.failed;
    ok(code !== 0, `C2 ${how}: shipped checker exits non-zero`, `exit ${code}`);
    eq(JSON.stringify(failed), JSON.stringify([id]),
       `C2 ${how}: --json failed is only ${id}`);
  }
}

console.log('\n=== T123 C3 — navigator-only is a WARN ===');
{
  const { code, json } = await against('navigator-only');
  ok(code === 0, 'C3: navigator-only page exits 0', `exit ${code}`);
  const warnings = json?.summary?.warnings || [];
  const blob = JSON.stringify(json);
  ok(warnings.length > 0, 'C3: --json carries a WARN');
  ok(/navigator\.modelContext/.test(blob), 'C3: JSON names the navigator.modelContext getter');
  ok(/#184/.test(blob), 'C3: JSON names webmcp#184');
}

console.log('\n=== T123 C4 — provideContext() is REMOVED ===');
{
  const { code, json, stdout } = await against('provide-context');
  ok(code !== 0, 'C4: provideContext() exits non-zero', `exit ${code}`);
  ok(/REMOVED/.test(stdout), 'C4: --json says REMOVED from the spec');
  ok(!/\bdeprecated\b/i.test(JSON.stringify(json?.summary?.failed || [])),
     'C4: the failed labels do not call it merely deprecated');
}

console.log('\n=== T123 C5 — both inputSchema forms ===');
{
  const imp = await against('imperative-only');
  ok(imp.code === 0, 'C5: imperative inputSchema exits 0', `exit ${imp.code}`);
  eq(imp.json?.verification?.webmcp?.inputSchemaForm, 'imperative',
     'C5: --json names the imperative form');

  const dec = await against('declarative-only');
  ok(dec.code === 0, 'C5: declarative inputSchema exits 0', `exit ${dec.code}`);
  eq(dec.json?.verification?.webmcp?.inputSchemaForm, 'declarative',
     'C5: --json names the declarative form');
}

console.log('\n=== T123 C6 — budgets never fail a run ===');
{
  const { code, json } = await against('long-budgets');
  ok(code === 0, 'C6: 40-char name + 900-char description exits 0', `exit ${code}`);
  const warnings = json?.summary?.warnings || [];
  ok(warnings.some((w) => /30-character budget/i.test(w)),
     'C6: --json WARNs on the name budget', JSON.stringify(warnings));
  ok(warnings.some((w) => /500-character budget/i.test(w)),
     'C6: --json WARNs on the description budget', JSON.stringify(warnings));
}

console.log('\n=== T123 C7 — composed verdict, never one number ===');
{
  const { json } = await against('redirect');
  const verdict = json?.verdict || '';
  ok(/not launched/i.test(verdict), 'C7: verdict names the browser build');
  ok(/#enable-webmcp-testing/.test(verdict), 'C7: verdict names the flag');
  ok(/\/landed/.test(verdict), 'C7: verdict names the final URL after redirects', verdict);
  ok(/tools enumerated from/.test(verdict), 'C7: verdict names the origin tools were enumerated from');
  ok(!/\b\d{1,3}\s*\/\s*100\b/.test(verdict), 'C7: verdict is not a /100');

  const dead = await runShippedChecker('http://127.0.0.1:1/');
  const dv = dead.json?.verdict || '';
  ok(/the page never loaded/i.test(dv), 'C7: unreachable host says the page never loaded', dv);
  ok(!/no tools registered/i.test(dv),
     'C7: unreachable host does NOT say no tools registered', dv);
}

console.log('\n=== T123 C8 — no aggregate score ===');
{
  const { stdout } = await against('none');
  const pageJs = fileURLToPath(new URL('../src/page.mjs', import.meta.url));
  const pageHtml = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e',
      `import { renderPage } from ${JSON.stringify(new URL('../src/page.mjs', import.meta.url).href)};`
      + 'process.stdout.write(renderPage("example.com"));',
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { err += c; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(err || `renderPage exited ${code}`));
      else resolve(out);
    });
  });
  const SCORE = [
    [/\b\d{1,3}\s*\/\s*100\b/, '/100'],
    [/\bgrade\s*[:=]\s*["']?[A-F][+-]?\b/i, 'letter grade'],
    [/\b[0-5](\.\d)?\s*(\/|out of)\s*5\b/i, 'stars'],
    [/\bsafe\b/i, 'the word "safe"'],
  ];
  for (const [re, what] of SCORE) {
    ok(!re.test(stdout), `C8: --json has no ${what}`, (stdout.match(re) || [])[0]);
    ok(!re.test(pageHtml), `C8: rendered page has no ${what}`, (pageHtml.match(re) || [])[0]);
  }
  void pageJs;
}

console.log('\n=== T123 C9 — corpus is real; size is the headline ===');
{
  const { json } = await against('none');
  const corpus = json?.webmcpCorpus || json?.verification?.webmcp?.corpus;
  ok(!!corpus, 'C9: --json publishes the corpus');
  const count = corpus?.count;
  const sites = corpus?.sites;
  eq(count, Array.isArray(sites) ? sites.length : -1,
     'C9: published count is the length of the listed sites');
  if (typeof count === 'number' && count <= 2) {
    eq(String(corpus.headline), String(count),
       'C9: when the count is 0–2, that number IS the headline');
  }
  ok(!/corpus of (dozens|hundreds|[3-9]|\d{2,})/i.test(json?.verdict || ''),
     'C9: the verdict does not invent a corpus');
}

console.log(`\n${'-'.repeat(60)}`);
console.log(`T123 C2–C9: ${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log('failed: ' + failures.join('; '));
  process.exit(1);
}
