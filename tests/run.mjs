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
import { siteWithCard, bareSite, serve } from './fixtures.mjs';

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

// ------------------------------------------------- 8. the DNS layer tells the states apart
section('8. DNSSEC states, and a lookup that failed is never an absence');
{
  const { zoneDnssec, dnsAid, TYPE_SVCB } = await import('../src/dns.mjs');
  const answer = (type, data) => ({ status: 0, ad: true, answers: [{ name: 'x', type, data }],
                                    error: null, resolver: 'stub' });
  const empty = { status: 0, ad: false, answers: [], error: null, resolver: 'stub' };

  const states = [
    ['signed',     async (n, ty) => (ty === 'DS' ? answer(43, 'ds data') : empty)],
    // The one found by pointing this at our own zone mid-setup: Cloudflare had signed the zone
    // and the DS had not reached the .com registry, so the apex had a DNSKEY and the parent had
    // nothing. A validator treats that as insecure — but it is a job half done, not a decision
    // not taken, and only one of those has an owner who thinks it is finished.
    ['incomplete', async (n, ty) => (ty === 'DNSKEY' ? answer(48, 'key data') : empty)],
    ['unsigned',   async () => empty],
    ['bogus',      async () => ({ ...empty, status: 2 })],
    ['unknown',    async () => ({ ...empty, status: null, error: 'resolver unreachable' })],
  ];
  for (const [want, query] of states) {
    const r = await zoneDnssec('fixture.example', { query });
    eq(r.state, want, `a zone that looks ${want} is reported ${want}`);
    ok(!!r.detail, `the ${want} verdict says why`);
  }

  // One name errors, the others answer. The error must survive into the report, and the names
  // that failed must NOT be counted as absent.
  const flaky = async (name, type) => {
    if (type !== TYPE_SVCB) return empty;
    if (name.startsWith('_mcp')) return { status: null, ad: null, answers: [],
                                          error: 'AbortError: timed out', resolver: 'stub' };
    return { status: 0, ad: true, resolver: 'stub', error: null,
             answers: [{ name, type: TYPE_SVCB, data: '1 fixture.example. alpn="h2"', TTL: 300 }] };
  };
  const d = await dnsAid('fixture.example', { query: flaky });
  eq(d.records.length, 2, 'the names that answered are reported');
  eq(d.complete, false, 'the run is marked incomplete');
  ok(d.lookupErrors.some((x) => x.name.startsWith('_mcp')),
     'the name whose lookup failed is named in lookupErrors');
  ok(!d.lookupErrors.some((x) => x.name.startsWith('_a2a')),
     'a name that answered is not listed as an error');
}

// ---------------------------------------------- 9. remedies: actionable, sourced, and honest
section('9. every finding is actionable, cites its specification, and refuses to invent surfaces');
{
  const { remediesFor, REMEDIES, NO_REMEDY } = await import('../src/remedies.mjs');

  const bare = await bareSite();
  const r = await checkSite(bare.origin, LOCAL);
  ok(r.remedies.length > 0, 'a site with nothing published still gets an actionable list');
  ok(r.remedies.every((x) => x.kind === 'add'),
     'and every item is an OFFER, not a defect — absence is not a fault');
  ok(r.remedies.every((x) => x.prompt.includes('Publish only what is already true')),
     'EVERY prompt carries the honesty clause');
  ok(r.remedies.every((x) => x.resources.length > 0 && x.resources.every((s) => /^https:\/\//.test(s.url))),
     'every item cites at least one specification, over https');
  ok(!r.remedies.some((x) => NO_REMEDY[x.id]),
     'surfaces we deliberately do not promote produce no prompt',
     Object.keys(NO_REMEDY).join(','));
  await bare.close();

  // A broken card must produce a FIX, ordered ahead of the offers.
  const broken = await siteWithCard({ mutate: 'copied-card' });
  const b = await checkSite(broken.origin, LOCAL);
  const fixes = b.remedies.filter((x) => x.kind === 'fix');
  ok(fixes.some((x) => x.id === 'origin-mismatch'), 'a copied card produces the origin-mismatch fix');
  ok(b.remedies.indexOf(fixes[0]) === 0, 'what is BROKEN is listed before what is merely absent');
  ok(fixes[0].prompt.includes('re-signing') || fixes[0].prompt.includes('re-sign'),
     'the fix prompt warns against editing signed bytes without re-signing');
  await broken.close();

  // The prompts are the most dangerous thing here: a remediation prompt is the most efficient
  // possible way to industrialise self-declaration. This is the guard.
  for (const [id, entry] of Object.entries(REMEDIES)) {
    const text = entry.prompt({ origin: 'https://example.com', host: 'example.com',
                                did: 'did:key:z6MkExample', detail: '' });
    ok(text.includes('Publish only what is already true'), `${id}: honesty clause present`);
  }
}

// -------------------------------------------------- 10. the MCP surface is not one client's
section('10. the install instructions belong to no single client');
{
  const page = renderPage('');
  ok(page.includes('<code>https://check.muretai.com/mcp</code>'),
     'the endpoint URL is offered on its own, as the primary fact');
  ok(page.includes('"mcpServers"'), 'a portable JSON config is shown');
  ok(page.includes('mcp-remote'), 'a path exists for a client with no HTTP transport');
  ok(page.indexOf('claude mcp add') > page.indexOf('"mcpServers"'),
     'a vendor CLI appears only as one example, after the portable forms');
  ok((page.match(/claude/gi) || []).length <= 2,
     'the page does not read as belonging to one vendor',
     `${(page.match(/claude/gi) || []).length} mentions`);
}

// ------------------------------------ 11. what we check is a decision, not an accumulation
section('11. the surface list is pinned: only what is standardised, or credibly heading there');
{
  // Probing for a format IS a statement that it matters — it costs a subrequest, it puts a row
  // in front of every reader, and it tells that format's author a checker now tracks them. So
  // the list is pinned here: adding one has to be a deliberate edit to this test, with the
  // admission rule in engine.mjs read first.
  const EXPECTED = [
    'llms.txt',                  // de facto, broad adoption
    'robots.txt',                // RFC 9309
    'sitemap.xml',               // sitemaps.org, universal
    'agents.md',                 // multi-vendor convention
    'mcp discovery',             // MCP, live ecosystem
    'mcp server card',           // MCP draft
    'agent skills index',        // MCP-adjacent draft, more than one implementer
    'api catalog',               // RFC 9727 (+ RFC 9264)
    'web bot auth directory',    // IETF draft over RFC 9421
    'markdown negotiation',      // RFC 9110 content negotiation
    'Permissions-Policy: tools', // WebMCP, W3C community group
  ];
  const site = await bareSite();
  const r = await checkSite(site.origin, LOCAL);
  const got = r.facts.map((f) => f.surface);
  eq(JSON.stringify(got), JSON.stringify(EXPECTED),
     'the checked surfaces are exactly the pinned list');

  // The two that were removed under the rule, named so they cannot return by reflex: one is a
  // six-week-old single-author draft, the other the superseded 2023 plugin manifest.
  for (const gone of ['ai2w', 'ai-plugin.json']) {
    ok(!got.includes(gone), `${gone} is not checked — it is not standardised, nor heading there`);
  }
  await site.close();
}

// ------------------------------------------ 12. a person who opens a machine address in a browser
section('12. the MCP endpoint answers a browser like a person, and a client like a machine');
{
  const worker = (await import('../src/worker.mjs')).default;
  const call = (path, init = {}) =>
    worker.fetch(new Request('https://check.muretai.com' + path, init), {}, {});

  // The bug this pins, and it has been paid for once already: a short link handed raw JSON to
  // everyone who clicked it, and nothing failed, because no test opens a browser.
  const browser = await call('/mcp', { headers: { Accept: 'text/html,application/xhtml+xml,*/*' } });
  const page = await browser.text();
  eq(browser.status, 405, 'a browser GET is still a 405 — the method really is not allowed');
  ok((browser.headers.get('content-type') || '').startsWith('text/html'),
     'but it is answered in HTML, not as a bare error object');
  ok(page.includes('https://check.muretai.com/mcp'), 'the page names the address they arrived at');
  ok(page.includes('mcpServers'), 'and shows a config they can paste');
  ok(/href="\/"/.test(page), 'and offers the way back to the checker itself');

  const machine = await call('/mcp');
  const j = await machine.json();
  eq(machine.status, 405, 'a non-browser GET is a 405 too');
  ok(!!j.endpoint && !!j.discovery,
     'and its JSON is actionable — the endpoint and the discovery document, not just a complaint');

  const post = await call('/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  eq(post.status, 200, 'and none of this touched the protocol itself');
}

// ------------------------------------------------ 13. the security audit's attacks, executed
section('13. the attacks a red-team found — each one run against the product');
{
  // A1. THE CRITICAL ONE. A signature that verifies, over a card this site does not serve.
  // Before the fix this reported verified + proven + fresh, certifying an identity the
  // attacker does not hold — with a victim's genuine envelope copied verbatim.
  const forged = await siteWithCard({ mutate: 'copied-envelope' });
  const f = await checkSite(forged.origin, LOCAL);
  eq(f.verification.signature.state, 'mismatched-card',
     'a signature over a DIFFERENT card is not "verified"');
  ok(f.verification.originBinding.state !== 'proven',
     'and nothing about the origin is treated as proven',
     f.verification.originBinding.state);
  ok(f.summary.failed.length > 0, 'and the run FAILS');
  ok(!/present, and verified/.test(f.verdict), 'and the verdict does not certify it', f.verdict);
  await forged.close();

  // A2. The confused deputy: the card names a door on somebody else's origin.
  const elsewhere = await siteWithCard({ mutate: 'door-elsewhere' });
  const d = await checkSite(elsewhere.origin, LOCAL);
  eq(d.verification.door.reached, 'not-probed',
     'no POST is sent to a door on another origin');
  ok(/not on this origin/.test(d.verification.door.detail || ''), 'and the report says why');
  await elsewhere.close();

  // A2b. THE SAME DEPUTY, ONE HOP LATER. A2's rule is applied to the FIRST url; a card can
  // advertise a door that is genuinely same-origin and then answer 307 to a third party. The
  // POST carries method AND body across a redirect, so without a same-origin rule INSIDE the
  // redirect loop the victim receives the knock and its status comes back as an oracle.
  // Measured before the fix: the victim logged `POST /private/api` with the full JSON-RPC body.
  const hits = [];
  const victim = await serve((req, res) => {
    let b = ''; req.on('data', (c) => { b += c; });
    req.on('end', () => {
      hits.push({ method: req.method, url: req.url, bytes: b.length });
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}');
    });
  });
  const bouncer = await siteWithCard({ mutate: 'door-redirects-away',
                                       extras: { __redirectDoorTo: victim.origin } });
  const b2 = await checkSite(bouncer.origin, LOCAL);
  eq(hits.length, 0, 'a door that redirects off-origin never receives the POST');
  ok(b2.verification.door.reached !== 'door-answered',
     'and the redirect is not counted as the door answering');
  ok(/another origin/.test(b2.verification.door.detail || ''),
     'and the report names the redirect rather than calling it silence');
  await bouncer.close(); await victim.close();

  // A2c. A CATCH-ALL 200 IS NOT NINE PUBLISHED SURFACES. An SPA answering 200 text/html for
  // every path - the Vercel/Netlify/Next/CRA default - was reported as publishing all nine
  // fact surfaces, and the verdict named them. That is this tool's own thesis ("present is
  // not the same as real") failing at the fact layer, on the line a reader sees first.
  const spa = await serve((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><title>spa</title>');
  });
  const sp = await checkSite(spa.origin, LOCAL);
  eq(sp.facts.filter((f) => f.present === true).length, 0,
     'a catch-all 200 establishes no surface as present');
  ok(sp.facts.some((f) => f.present === null),
     'and the surfaces are reported as not established rather than absent');
  ok(!/Also published[^.]*llms\.txt/.test(sp.verdict || ''),
     'and the verdict does not credit the site with them');
  await spa.close();

  // A3. Indirect prompt injection: newlines let a fetched value impersonate a new section of
  // the very text this tool tells an agent to act on.
  const inject = await siteWithCard({ mutate: 'injection' });
  const i = await checkSite(inject.origin, LOCAL);
  // The defense is that NEWLINES cannot survive out of a fetched value — that is what lets a
  // string impersonate a new section. Assert exactly that, on the text an agent actually reads,
  // rather than the weaker "the marker is absent" (a payload could simply be reworded).
  const quoted = [i.verification.card.did, i.verification.card.name,
                  i.verification.card.protocolVersion, i.verification.door.url]
    .filter((x) => typeof x === 'string');
  ok(quoted.length > 0, 'the fixture did get its values into the report (else this proves nothing)');
  for (const q of quoted) {
    ok(!/[\r\n\u2028\u2029\u0000-\u001f]/.test(q),
       'a value quoted from the checked site carries no line break or control character',
       JSON.stringify(q.slice(0, 40)));
  }
  for (const rem of i.remedies) {
    ok(!/\n\s*SYSTEM:/i.test(rem.prompt),
       `${rem.id}: no injected instruction starts a line in the generated prompt`);
    ok(/PROVENANCE:/.test(rem.prompt),
       `${rem.id}: the prompt tells its reader which parts came from the checked site`);
  }
  ok((i.verification.card.did || '').length <= 220,
     'a fetched field is length-capped before it is quoted back',
     `${(i.verification.card.did || '').length} chars`);
  await inject.close();

  // A4. A future timestamp is not freshness.
  const future = await siteWithCard({ mutate: 'future' });
  const fu = await checkSite(future.origin, LOCAL);
  eq(fu.verification.freshness.state, 'future', 'an envelope dated ahead of now is not "fresh"');
  ok(fu.summary.failed.length > 0, 'and it fails the run');
  await future.close();

  // A5. The guard's denylist holes: a trailing dot, and IPv4 embedded in IPv6 four ways.
  const holes = ['http://localhost./', 'http://foo.local./', 'http://[::169.254.169.254]/',
                 'http://[64:ff9b::169.254.169.254]/', 'http://[2002:a9fe:a9fe::]/',
                 'http://[::127.0.0.1]/'];
  for (const u of holes) {
    let refused = false;
    try { guardURL(u); } catch (e) { refused = e instanceof RefusedURL; }
    ok(refused, `refuses ${u}`);
  }

  // A6. One request may no longer hide thousands of checks.
  const worker = (await import('../src/worker.mjs')).default;
  const batch = await worker.fetch(new Request('https://check.muretai.com/mcp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(Array.from({ length: 200 }, (_, n) =>
      ({ jsonrpc: '2.0', id: n, method: 'tools/list' }))),
  }), {}, {});
  eq(batch.status, 413, 'an oversized batch is refused before any work is done');

  // A7. The time budget is for the whole check, not per hop.
  const slow = await siteWithCard();
  const t0 = Date.now();
  await checkSite(slow.origin, { ...LOCAL, budgetMs: 700 });
  ok(Date.now() - t0 < 4000, 'a check honours its overall budget',
     `${Date.now() - t0}ms`);
  await slow.close();

  // A8. The page carries a policy, so one missed escape is not instantly exploitable.
  const page = await worker.fetch(new Request('https://check.muretai.com/'), {}, {});
  const csp = page.headers.get('content-security-policy') || '';
  ok(csp.includes("default-src 'none'") && csp.includes("frame-ancestors 'none'"),
     'the page ships a Content-Security-Policy', csp.slice(0, 60));
  eq(page.headers.get('x-content-type-options'), 'nosniff', 'and nosniff');
}

// ------------------------------------------------ 14. the version a report prints is the truth
section('14. the reported version cannot drift from the published one');
{
  // Every report, every MCP result and the discovery document carry a version, and the whole
  // point of printing it is that a verdict can be traced to the build that produced it. The
  // number lives in two files, so it can drift, so it is pinned here.
  const { readFile } = await import('node:fs/promises');
  const { VERSION } = await import('../src/engine.mjs');
  const { SERVER_INFO } = await import('../src/mcp.mjs');
  const { wellKnownMcp } = await import('../src/mcp.mjs');
  const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

  eq(VERSION, pkg.version, 'the engine reports the version package.json publishes');
  eq(SERVER_INFO.version, pkg.version, 'and so does the MCP serverInfo');
  eq(wellKnownMcp('https://example.com').version, pkg.version,
     'and so does the discovery document');

  const r = await checkSite('http://127.0.0.1:1/', LOCAL);
  eq(r.checker.version, pkg.version, 'and so does every report, including a failed one');
}

// ----------------------------------------------------------------
console.log(`\n${'-'.repeat(60)}`);
console.log(`${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log('failed: ' + failures.join('; '));
  process.exit(1);
}
