/**
 * tests/verify-live.mjs — probe the DEPLOYED service, over the network, as a stranger.
 *
 * WHY THIS EXISTS SEPARATELY FROM `npm test`. The acceptance suite runs the engine in Node
 * against loopback fixtures, and it was 77/77 green while the deployed service reported
 * muretai.com as having no agent card at all. Nothing in that suite could have seen it: the
 * defect lived in how the Cloudflare runtime ROUTES a subrequest to a hostname on its own
 * zone, which exists only in production and only for one zone.
 *
 * So this asserts the things only the live deployment can be wrong about, and the first
 * assertion is the regression itself.
 *
 *     node tests/verify-live.mjs [https://check.muretai.com]
 */

const BASE = (process.argv[2] || 'https://check.muretai.com').replace(/\/+$/, '');
let passed = 0;
const failures = [];
const ok = (cond, label, detail = '') => {
  if (cond) { passed++; console.log(`  ok   ${label}`); }
  else { failures.push(label); console.log(`  FAIL ${label}${detail ? `  (${detail})` : ''}`); }
};

const rpc = async (body, headers = {}) => {
  const r = await fetch(`${BASE}/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json() };
};

console.log(`live verification of ${BASE}\n`);

// 1. THE REGRESSION. A checker that cannot see the site it is hosted beside is worse than no
//    checker: it reports a verified door as absent, on the one site its owners will demo.
console.log('1. the service sees the public edge of its own zone, not the origin behind it');
{
  const r = await fetch(`${BASE}/api/check?url=muretai.com`);
  const j = await r.json();
  ok(j.reachable === true, 'muretai.com is reachable');
  ok(j.verification?.card?.present === true,
     'the agent card is FOUND (absent here means the subrequest reached the origin, not the edge '
     + '— check global_fetch_strictly_public in wrangler.toml)',
     `card status ${j.verification?.card?.status}`);
  ok(j.verification?.signature?.state === 'verified', 'the card signature verifies',
     j.verification?.signature?.state);
  ok(j.verification?.originBinding?.state === 'proven', 'the DID is bound to the origin',
     j.verification?.originBinding?.state);
  const present = (j.facts || []).filter((f) => f.present).map((f) => f.surface);
  ok(present.includes('llms.txt') && present.includes('robots.txt'),
     'llms.txt and robots.txt are seen', `present: ${present.join(',') || 'none'}`);
  ok(j.dnsAid?.dnssec?.state === 'signed' && j.dnsAid?.records?.length === 3,
     'all three DNS-AID records resolve in a signed zone',
     `${j.dnsAid?.dnssec?.state}, ${j.dnsAid?.records?.length} records`);
}

// 2. An external zone must keep working — the flag changes routing for every fetch, not just
//    the same-zone one, so this is the control.
console.log('\n2. an external site still checks correctly (the control for the flag)');
{
  const j = await (await fetch(`${BASE}/api/check?url=cloudflare.com`)).json();
  const present = (j.facts || []).filter((f) => f.present).map((f) => f.surface);
  ok(j.reachable === true, 'cloudflare.com is reachable');
  ok(present.includes('llms.txt'), 'its llms.txt is seen', present.join(',') || 'none');
}

// 3. MCP, both generations, live.
console.log('\n3. the MCP endpoint answers both generations');
{
  const legacy = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', clientInfo: { name: 'verify-live', version: '1' } } });
  ok(legacy.json.result?.protocolVersion === '2025-06-18', 'the legacy handshake answers');
  const disc = await rpc({ jsonrpc: '2.0', id: 2, method: 'server/discover' });
  ok(disc.json.result?.protocolVersions?.includes('2026-07-28'), 'server/discover answers');
  const tools = await rpc({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  ok((tools.json.result?.tools || []).length === 2, 'both tools are listed');
  const bad = await rpc({ jsonrpc: '2.0', id: 4, method: 'tools/list' }, { 'Mcp-Method': 'tools/call' });
  ok(bad.json.error?.code === -32020, 'a contradicting header is -32020');
}

// 4. The two things no unit test can see: is the door open to a client that is not a browser,
//    and does the page still refuse to grow a score.
console.log('\n4. the checks a green suite cannot make');
{
  // An MCP client is not a browser. Browser Integrity Check 403s exactly this shape of request,
  // and it once left muretai's own Agent Entry dark for three days.
  const bare = await fetch(`${BASE}/.well-known/mcp.json`, { headers: { 'User-Agent': 'probe/1' } });
  ok(bare.status === 200, 'a bare, non-browser user agent is not blocked (Browser Integrity Check)',
     `got ${bare.status}`);
  const page = await (await fetch(`${BASE}/`)).text();
  const { assertNoScore } = await import('../src/report.mjs');
  try { assertNoScore(page, 'the live page'); ok(true, 'the live page carries no score'); }
  catch (e) { ok(false, 'the live page carries no score', e.message); }
  const wk = await (await fetch(`${BASE}/.well-known/mcp.json`)).json();
  ok(wk.url === `${BASE}/mcp`, 'the discovery document names this endpoint', wk.url);

  // Somebody will paste the endpoint into a browser. What they get back is a product surface.
  const inBrowser = await fetch(`${BASE}/mcp`, { headers: { Accept: 'text/html,*/*' } });
  const html = await inBrowser.text();
  ok((inBrowser.headers.get('content-type') || '').startsWith('text/html')
     && html.includes('mcpServers'),
     'opening the MCP endpoint in a browser explains itself instead of printing a raw error',
     `${inBrowser.status} ${inBrowser.headers.get('content-type')}`);
}

console.log(`\n${'-'.repeat(60)}`);
console.log(`${passed} passed, ${failures.length} failed`);
if (failures.length) { console.log('failed: ' + failures.join('; ')); process.exit(1); }
