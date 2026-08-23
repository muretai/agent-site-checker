/**
 * tests/run.mjs — the acceptance suite.
 *
 * TWO RULES THIS SUITE OBEYS, both inherited from muretai core and both about the same failure:
 * a green suite that proves nothing.
 *
 *  1. Every assertion is made on what a USER can observe — the JSON a caller gets back, the
 *     rendered page, the exit status. No test imports a detection function to assert with it.
 *  2. Every verification claim is paired with a PRODUCER MUTATION: neuter exactly one thing in
 *     the fixture and prove the checker goes RED on the intended check, and only that one. A
 *     check that stays green with its producer dead is not testing the producer.
 *
 * Run: npm test
 */

import { checkSite } from '../src/engine.mjs';
import { dispatch, TOOLS } from '../src/mcp.mjs';
import { guardURL, RefusedURL } from '../src/guard.mjs';
import { renderPage } from '../src/page.mjs';
import { assertNoScore } from '../src/report.mjs';
import { siteWithCard, bareSite } from './fixtures.mjs';

let passed = 0;
const failures = [];

function ok(cond, label, detail = '') {
  if (cond) { passed++; console.log(`  ok   ${label}`); }
  else { failures.push(label); console.log(`  FAIL ${label}${detail ? `  (${detail})` : ''}`); }
}
const eq = (a, b, label) => ok(a === b, label, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
const section = (s) => console.log(`\n=== ${s} ===`);

/** Fixtures are on loopback, so the run needs the CLI's own-machine allowance and no DNS. */
const LOCAL = { allowPrivate: true, dns: false };

// ---------------------------------------------------------------- 1. the conformant case
section('1. a conformant door verifies end to end');
{
  const site = await siteWithCard();
  const r = await checkSite(site.origin, LOCAL);
  eq(r.reachable, true, 'the site was reachable');
  eq(r.verification.card.did, site.did, 'the card DID is reported as served');
  eq(r.verification.signature.state, 'verified', 'the signature verifies');
  eq(r.verification.originBinding.state, 'proven', 'the DID is bound to this origin');
  eq(r.verification.freshness.state, 'fresh', 'the envelope is fresh');
  eq(r.verification.door.reached, 'door-answered', 'the knock reached the door itself');
  eq(r.summary.failed.length, 0, 'nothing failed');
  ok(r.interfaces.some((i) => i.kind === 'a2a-agent-entry' && i.identityVerified),
     'the visitor is told the identity is verified');
  await site.close();
}

// ---------------------------------------------------------------- 2. producer mutations
section('2. producer mutation — one lever at a time, one check goes RED');
{
  const cases = [
    ['no-signature',  (r) => r.verification.signature.state === 'absent',
     'signature: absent', (r) => r.summary.failed.length === 0,
     'an unsigned card is NOT a failure — most A2A cards are unsigned, and failing them would '
     + 'be grading the whole category by our own yardstick'],
    ['bad-signature',  (r) => r.verification.signature.state === 'invalid',
     'signature: invalid', (r) => r.summary.failed.some((f) => /verifies under/.test(f)), ''],
    ['copied-card',    (r) => r.verification.originBinding.state === 'mismatch',
     'originBinding: mismatch', (r) => r.summary.failed.some((f) => /bound to this origin/.test(f)), ''],
    ['stale',          (r) => r.verification.freshness.state === 'stale',
     'freshness: stale', (r) => r.summary.failed.some((f) => /fresh/.test(f)), ''],
    ['edge-swallows',  (r) => r.verification.door.reached === 'unknown',
     'door: unknown (not "declined")', (r) => r.summary.failed.length === 0,
     'nothing reached the door, which is an unknown, never a failure of the site'],
  ];

  for (const [mutate, hit, label, statusCheck, why] of cases) {
    const site = await siteWithCard({ mutate });
    const r = await checkSite(site.origin, LOCAL);
    ok(hit(r), `${mutate} -> ${label}`,
       JSON.stringify({ sig: r.verification.signature.state,
                        origin: r.verification.originBinding.state,
                        fresh: r.verification.freshness.state,
                        door: r.verification.door.reached }));
    ok(statusCheck(r), `${mutate} -> the exit status is right${why ? ` (${why})` : ''}`,
       `failed: ${JSON.stringify(r.summary.failed)}`);
    await site.close();
  }

  // The mutation that must NOT bleed: a copied card still carries a VALID signature, so the
  // signature check has to stay green while the binding check goes red. If both flip, the
  // checker is not measuring two things.
  const copied = await siteWithCard({ mutate: 'copied-card' });
  const r = await checkSite(copied.origin, LOCAL);
  eq(r.verification.signature.state, 'verified',
     'a copied card is still correctly reported as SIGNED — only the binding fails');
  ok(/copied here from somewhere else/.test(r.verification.originBinding.detail),
     'the report says the card was copied, in words a person can act on');
  await copied.close();
}

// ------------------------------------------- 3. absent is not the same as never reached
section('3. "nothing loaded" is never reported as "no door"');
{
  const bare = await bareSite();
  const present = await checkSite(bare.origin, LOCAL);
  eq(present.reachable, true, 'a bare site is reachable');
  eq(present.verification.card.present, false, 'a bare site has no card');
  ok(/door: absent/.test(present.verdict), 'a bare site is reported as door absent');
  eq(present.summary.failed.length, 0, 'a bare site fails nothing — absence is not a fault');
  await bare.close();

  // A port nobody is listening on: the connection is refused, so NOTHING was measured.
  const dead = await checkSite('http://127.0.0.1:1/', LOCAL);
  eq(dead.reachable, false, 'an unreachable host is reported unreachable');
  ok(/never loaded/.test(dead.verdict), 'the verdict says the page never loaded');
  ok(!/door: absent/.test(dead.verdict),
     'the verdict does NOT claim the door is absent — that would be a finding we did not make');
}

// ---------------------------------------------------------------- 4. the no-score gate
section('4. no score, no grade, no "safe" — anywhere');
{
  const site = await siteWithCard();
  const r = await checkSite(site.origin, LOCAL);
  for (const [what, text] of [
    ['the JSON result', JSON.stringify(r)],
    ['the verdict sentence', r.verdict],
    ['the rendered page', renderPage('example.com')],
  ]) {
    try { assertNoScore(text, what); ok(true, `${what} contains no score-like string`); }
    catch (e) { ok(false, `${what} contains no score-like string`, e.message); }
  }
  ok(!/\bscore\b/i.test(JSON.stringify(r)), 'the word "score" appears nowhere in a result');
  await site.close();
}

// ---------------------------------------------------------------- 5. the fetch guard
section('5. the guard refuses what a public endpoint must never fetch');
{
  const mustRefuse = [
    'http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/', 'file:///etc/passwd',
    'http://localhost:8080/', 'https://example.com:22/', 'http://[::1]/', 'http://10.1.2.3/',
    'http://192.168.1.1/', 'http://172.16.0.1/', 'http://[::ffff:127.0.0.1]/',
    'http://[::ffff:7f00:1]/', 'gopher://example.com/', 'http://printer.local/',
  ];
  for (const u of mustRefuse) {
    let refused = false;
    try { guardURL(u); } catch (e) { refused = e instanceof RefusedURL; }
    ok(refused, `refuses ${u}`);
  }
  for (const u of ['https://example.com/', 'http://example.com:8080/x', 'https://[2606:4700::1]/']) {
    let allowed = true;
    try { guardURL(u); } catch { allowed = false; }
    ok(allowed, `still allows ${u}`);
  }
  // The one that matters most: the guard is applied to REDIRECT TARGETS, not only to the URL
  // that was typed. A guard on the front door only is not a guard.
  const { serve } = await import('./fixtures.mjs');
  const hop = await serve((req, res) => {
    res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
    res.end();
  });
  const r = await checkSite(hop.origin, LOCAL);
  ok(!r.reachable || /refused/.test(JSON.stringify(r)),
     'a redirect into link-local space is refused rather than followed',
     JSON.stringify(r).slice(0, 200));
  await hop.close();
}

// ---------------------------------------------------------------- 6. MCP, both generations
section('6. MCP answers both generations with the same tools');
{
  const legacy = await dispatch({ jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', clientInfo: { name: 't', version: '1' } } });
  eq(legacy.result.protocolVersion, '2025-06-18', 'a legacy client gets the version it asked for');
  ok(!!legacy.result.serverInfo && !!legacy.result.instructions,
     'the legacy handshake carries serverInfo and instructions');

  const discover = await dispatch({ jsonrpc: '2.0', id: 2, method: 'server/discover' });
  eq(discover.result.resultType, 'result', 'server/discover carries resultType');
  ok(discover.result.protocolVersions.includes('2026-07-28'),
     'server/discover names the modern revision');

  const legacyTools = await dispatch({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  const modernTools = await dispatch({ jsonrpc: '2.0', id: 4, method: 'tools/list',
    params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } } });
  eq(JSON.stringify(legacyTools.result.tools), JSON.stringify(modernTools.result.tools),
     'both generations are offered exactly the same tools');
  eq(legacyTools.result.resultType, undefined,
     'a legacy result is NOT decorated with modern fields');
  eq(modernTools.result.resultType, 'result', 'a modern result carries resultType');

  const badVersion = await dispatch({ jsonrpc: '2.0', id: 5, method: 'tools/list',
    params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '1999-01-01' } } });
  eq(badVersion.error.code, -32022, 'an unknown revision is -32022');
  ok(Array.isArray(badVersion.error.data.supported), '-32022 names the revisions we speak');

  const mismatch = await dispatch({ jsonrpc: '2.0', id: 6, method: 'tools/list' },
    { 'mcp-method': 'tools/call' });
  eq(mismatch.error.code, -32020, 'a header contradicting the body is -32020');

  eq(await dispatch({ jsonrpc: '2.0', method: 'notifications/initialized' }), null,
     'a notification produces no response');

  // No parameter may be mirrored into a header: a URL under check is often unpublished.
  ok(!JSON.stringify(TOOLS).includes('x-mcp-header'),
     'no tool parameter is annotated for header mirroring');
}

// ---------------------------------------------------------------- 7. the tool actually runs
section('7. tools/call returns a real, structured result');
{
  const site = await siteWithCard();
  const res = await dispatch({ jsonrpc: '2.0', id: 7, method: 'tools/call',
    params: { name: 'verify_agent_card', arguments: { url: site.origin } } });
  // The hosted service refuses loopback, which is correct — and that refusal must arrive as a
  // clean tool error, not a crash.
  ok(res.result.isError === true, 'the hosted tool refuses a private address');
  ok(/^refused: /.test(res.result.content[0].text),
     'and the refusal names its reason rather than crashing', res.result.content[0].text);

  const unknown = await dispatch({ jsonrpc: '2.0', id: 8, method: 'tools/call',
    params: { name: 'nope', arguments: {} } });
  eq(unknown.error.code, -32602, 'an unknown tool is -32602');
  await site.close();
}

// ----------------------------------------------------------------
console.log(`\n${'-'.repeat(60)}`);
console.log(`${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log('failed: ' + failures.join('; '));
  process.exit(1);
}
