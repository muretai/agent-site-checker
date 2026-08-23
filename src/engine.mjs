/**
 * src/engine.mjs — follow the signposts, then check whether what is at the end is real.
 *
 * THE DIVISION OF LABOUR THIS FILE ASSUMES. There is already a category of tools that answer
 * "does this site PUBLISH agent-facing surfaces" — Cloudflare's isitagentready.com is the
 * largest, and it scores 22 criteria. This file does not re-answer that question. It answers
 * the one none of them ask: **is any of it real?** A JSON file at a well-known path is a
 * claim. A signature that verifies under the DID the file names, from a key that provably
 * speaks for this origin, re-signed within the last six hours, is a fact.
 *
 * The three layers, and why each needs the one before it:
 *
 *   L1  DNS      — the record exists AND the zone is DNSSEC-signed (`dns.mjs`). An unsigned
 *                  discovery record is a hint from whoever answered the query.
 *   L2  HTTP     — the card is signed, the signature verifies, the DID is bound to THIS
 *                  origin (not copied from another site), and the envelope is FRESH.
 *   L3  behaviour— when we speak to the door, does the DOOR answer, or does something in
 *                  front of it answer for it? Those two are not the same, and telling them
 *                  apart is the difference between a verdict and a guess.
 *
 * EVERYTHING ELSE IS A FACT, NOT A GRADE. llms.txt, robots rules, an MCP server card, a
 * skills index — each is reported with the URL fetched and the status returned, and none is
 * scored. Grading a foreign format against our own yardstick is exactly the failure that made
 * a competitor's scanner report muretai.com as not agent-ready while it served an A2A card at
 * both well-known paths.
 */

import {
  AGENT_CARD_PATH, AGENT_CARD_PATH_LEGACY, AGENT_CARD_SIG_PATH, AGENT_ENTRY_REL,
  verifyCardEnvelope,
} from '@muretai/agent-entry';
import { boundedFetch, normaliseInput, RefusedURL } from './guard.mjs';
import { Report } from './report.mjs';
import { dnsAid } from './dns.mjs';

export const VERSION = '0.1.0';

/** What a visitor enforces before it will speak to a door: a signed card older than this is
 *  refused. Mirrors muretai's `Outbox.CARD_SIG_MAX_AGE`. It is the only check that can tell a
 *  live re-signing process from a JSON file somebody pasted and forgot. */
export const CARD_SIG_MAX_AGE_S = 6 * 3600;

/** Read-only surfaces worth REPORTING, never scoring. Each is one GET. */
const FACT_SURFACES = [
  ['llms.txt', '/llms.txt', 'the plain-language brief written for language models'],
  ['robots.txt', '/robots.txt', 'crawler policy, AI-bot rules and Content-Signal'],
  ['sitemap.xml', '/sitemap.xml', 'the URL list a scanner samples'],
  ['agents.md', '/agents.md', 'instructions addressed to coding agents'],
  ['mcp discovery', '/.well-known/mcp.json', 'a pointer to an MCP endpoint'],
  ['mcp server card', '/.well-known/mcp/server-card.json', 'the MCP server description (draft)'],
  ['agent skills index', '/.well-known/agent-skills/index.json', 'skills an agent may load'],
  ['api catalog', '/.well-known/api-catalog', 'RFC 9727 linkset of APIs'],
  ['web bot auth directory', '/.well-known/http-message-signatures-directory',
   'the keys this site\'s own outbound agents sign with'],
  ['ai-plugin.json', '/.well-known/ai-plugin.json', 'the 2023-era plugin manifest'],
  ['ai2w', '/.well-known/ai2w', 'the AI2Web manifest'],
];

const j = (s) => { try { return JSON.parse(s); } catch { return null; } };

function originOf(u) { try { return new URL(u).origin; } catch { return null; } }

/** Collapse a repeated header field the way RFC 9110 §5.3 says to. A WordPress page emits its
 *  own `Link:` beside the door signpost, and last-one-wins reports the signpost missing while
 *  it is present and first — a bug this project has already paid for once. */
function linkRels(headerValue) {
  const rels = [];
  for (const part of String(headerValue || '').split(/,(?=\s*<)/)) {
    const m = /<([^>]*)>/.exec(part);
    const rel = /rel\s*=\s*"?([^";]+)"?/i.exec(part);
    if (m) rels.push({ href: m[1], rel: rel ? rel[1].trim() : null });
  }
  return rels;
}

/**
 * The whole check.
 *
 * `input` is whatever a person or an agent typed: `muretai.com`, `https://muretai.com/`, or a
 * path-mounted entry like `https://shop.example/support`.
 */
export async function checkSite(input, { resolver = 'cloudflare', probeDoor = true,
                                        allowPrivate = false, dns = true } = {}) {
  const startedAt = new Date().toISOString();
  const rep = new Report();

  let target;
  try {
    target = normaliseInput(input, { allowPrivate });
  } catch (e) {
    return {
      checker: { name: 'agent-site-checker', version: VERSION, checkedAt: startedAt },
      target: { input: String(input), url: null },
      refused: e instanceof RefusedURL ? e.reason : String(e),
      reachable: false,
      rows: [], summary: { passed: 0, failed: [], warnings: [] },
    };
  }

  const base = target.origin + target.pathname.replace(/\/+$/, '');
  const result = {
    checker: { name: 'agent-site-checker', version: VERSION, checkedAt: startedAt },
    target: { input: String(input), url: target.href, base, finalUrl: null, redirects: [] },
    reachable: false,
    interfaces: [],
    verification: {},
    dnsAid: null,
    facts: [],
    rows: [],
    summary: null,
    verdict: null,
  };

  // ---------------------------------------------------------------- 0. does the page load?
  //
  // This runs first and its failure is terminal, because of the single most misleading thing a
  // checker can print. "No agent card found" and "we never reached the server" look identical
  // in a report that does not separate them, and one of them is a statement about the site
  // while the other is a statement about the network. If the page never loaded, this run has
  // measured nothing and says so.
  const home = await boundedFetch(base + '/', { allowPrivate, headers: { Accept: 'text/html,*/*' } });
  result.target.finalUrl = home.finalUrl;
  result.target.redirects = home.redirects;
  if (home.status === null) {
    rep.check(false, 'the site answered at all', home.error || 'no response');
    result.rows = rep.rows;
    result.summary = rep.summary();
    result.verdict = 'The page never loaded, so nothing about this site was measured. '
                   + 'This is not a finding about the site.';
    return result;
  }
  result.reachable = true;
  rep.info('the site answered', `HTTP ${home.status} at ${home.finalUrl}`
    + (home.redirects.length ? ` after ${home.redirects.length} redirect(s)` : ''));

  const originBase = originOf(home.finalUrl) || base;

  // ---------------------------------------------------------------- 1. the card, and the alias
  const cardRes = await boundedFetch(base + AGENT_CARD_PATH, { allowPrivate, headers: { Accept: 'application/json' } });
  const card = cardRes.status === 200 ? j(cardRes.body) : null;
  const did = card && typeof card.did === 'string' ? card.did : null;

  const v = result.verification;
  v.card = {
    present: !!card,
    url: base + AGENT_CARD_PATH,
    status: cardRes.status,
    did,
    name: card?.name ?? null,
    protocolVersion: card?.protocolVersion ?? null,
  };

  if (!card) {
    rep.info('no A2A agent card at the well-known path',
      `GET ${AGENT_CARD_PATH} -> ${cardRes.status ?? cardRes.error}`);
  } else {
    rep.check(!!did && did.startsWith('did:key:'),
      'the card names a did:key', `got ${JSON.stringify(did)}`);

    const legacy = await boundedFetch(base + AGENT_CARD_PATH_LEGACY, { allowPrivate, headers: { Accept: 'application/json' } });
    rep.warn(legacy.status === 200 && legacy.body === cardRes.body,
      `the ${AGENT_CARD_PATH_LEGACY} alias is byte-identical`,
      legacy.status === 200 ? 'the alias is served but its bytes differ from the card'
                            : `the alias answered ${legacy.status ?? legacy.error}`);
  }

  // ------------------------------------------------- 2. the signature: the check nobody runs
  //
  // Three separate questions, reported separately because they fail separately and a reader
  // who is deciding whether to TRANSACT needs to know which one failed:
  //   signature     — do these bytes carry a valid Ed25519 signature under the DID they name?
  //   originBinding — does that DID speak for THIS origin, or was a valid card copied here
  //                   from somewhere else? A mirrored card verifies perfectly and proves
  //                   nothing about the site serving it.
  //   freshness     — is something alive re-signing it?
  v.signature = { state: 'absent', detail: 'no signed envelope was fetched' };
  v.originBinding = { state: 'unproven', detail: 'no verified card' };
  v.freshness = { state: 'unknown', ageSeconds: null, maxAgeSeconds: CARD_SIG_MAX_AGE_S };

  if (card) {
    const sigRes = await boundedFetch(base + AGENT_CARD_SIG_PATH, { allowPrivate, headers: { Accept: 'application/json' } });
    const env = sigRes.status === 200 ? j(sigRes.body) : null;
    v.signature.url = base + AGENT_CARD_SIG_PATH;
    v.signature.status = sigRes.status;

    if (!env) {
      v.signature = { ...v.signature, state: 'absent',
        detail: `GET ${AGENT_CARD_SIG_PATH} -> ${sigRes.status ?? sigRes.error}. The card is an `
              + 'unsigned claim: anyone can serve this file, and nothing here shows the DID '
              + 'in it consented to being named.' };
      rep.warn(false, 'the card is accompanied by a signed envelope', v.signature.detail);
    } else {
      const verified = verifyCardEnvelope(env, did);
      const ts = env.ts;
      const tsOk = typeof ts === 'number' && Number.isInteger(ts);

      if (verified) {
        v.signature = { ...v.signature, state: 'verified',
          detail: `the envelope signature verifies under ${did}` };
        rep.check(true, 'the signed card envelope verifies under the card\'s DID');
      } else {
        v.signature = { ...v.signature, state: 'invalid',
          detail: 'a signed envelope is served but it does NOT verify under the DID the card '
                + 'names — the bytes were altered, the DID was swapped, or the signer is not '
                + 'who the card says it is' };
        rep.check(false, 'the signed card envelope verifies under the card\'s DID',
          v.signature.detail);
      }

      rep.warn(tsOk, 'the envelope `ts` is an integer a non-JavaScript verifier can read',
        `got ${typeof ts}`);
      if (tsOk) {
        const age = Math.round(Date.now() / 1000 - ts);
        v.freshness = {
          state: Math.abs(age) <= CARD_SIG_MAX_AGE_S ? 'fresh' : 'stale',
          ageSeconds: age, maxAgeSeconds: CARD_SIG_MAX_AGE_S,
          detail: Math.abs(age) <= CARD_SIG_MAX_AGE_S
            ? `signed ${Math.max(0, Math.round(age / 60))} minute(s) ago`
            : `signed ${(age / 3600).toFixed(1)} hours ago, past the ${CARD_SIG_MAX_AGE_S / 3600}h `
              + 'window a visitor enforces — a live door re-signs on a timer, so this reads as a '
              + 'static file that stopped being maintained',
        };
        rep.check(v.freshness.state === 'fresh', 'the signed card is fresh', v.freshness.detail);
      }

      // Origin binding. The card's own declared endpoints are the test: a card lifted from
      // another site still verifies, and still names that other site.
      if (verified) {
        const claimed = [];
        if (typeof card.url === 'string') claimed.push(card.url);
        for (const si of Array.isArray(card.supportedInterfaces) ? card.supportedInterfaces : []) {
          if (si && typeof si.url === 'string') claimed.push(si.url);
        }
        const origins = [...new Set(claimed.map(originOf).filter(Boolean))];
        if (!origins.length) {
          v.originBinding = { state: 'unproven', claimedOrigins: [],
            detail: 'the verified card names no endpoint, so it cannot be tied to this origin' };
          rep.warn(false, 'the verified card names an endpoint on this origin',
            v.originBinding.detail);
        } else if (origins.includes(originBase)) {
          v.originBinding = { state: 'proven', claimedOrigins: origins,
            detail: `${did} signed a card whose endpoint is on ${originBase}, and that card is `
                  + 'served from that same origin' };
          rep.check(true, 'the DID is bound to this origin (the signed card names it)');
        } else {
          v.originBinding = { state: 'mismatch', claimedOrigins: origins,
            detail: `the signature is valid, but the card it signs points at ${origins.join(', ')} `
                  + `— not ${originBase}. This card was copied here from somewhere else; it says `
                  + 'nothing about who runs THIS site.' };
          rep.check(false, 'the DID is bound to this origin', v.originBinding.detail);
        }
      }
    }
  }

  // ------------------------------------------- 3. the door, and WHO ANSWERED when we knocked
  //
  // The trap this exists for, measured on our own production site: a POST to a door behind a
  // CDN can be answered by the EDGE with a body byte-identical to the door's own refusal. The
  // response alone cannot tell you which component spoke, so a checker that reports "the door
  // declined" has certified a door it never reached. The disambiguator is positive evidence:
  // a JSON-RPC envelope can only have come from something speaking JSON-RPC. Absent that, this
  // reports "unknown" and says why, rather than inventing the reassuring reading.
  const openDoor = !!(card && ((card.agentEntry && card.agentEntry.open_door)
                            || (card.muretai && card.muretai.open_door)));
  v.door = { advertised: openDoor, url: null, reached: 'not-probed' };

  if (card && openDoor && probeDoor) {
    // The URL comes from the SIGNED CARD, never from user input: the one POST this tool makes
    // goes to an address the site itself published as a door for exactly this purpose.
    const doorUrl = (Array.isArray(card.supportedInterfaces) && card.supportedInterfaces[0]?.url)
                  || card.url || (base + '/');
    v.door.url = doorUrl;
    let doorOk = false;
    try {
      const probe = await boundedFetch(doorUrl, { allowPrivate,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 'agent-site-checker', method: 'message/send',
          params: { message: { kind: 'message', role: 'user', parts: [{ kind: 'text', text: 'hello' }] } },
        }),
      });
      const parsed = j(probe.body);
      const isRpc = !!parsed && parsed.jsonrpc === '2.0';
      v.door.status = probe.status;
      if (isRpc) {
        doorOk = true;
        const code = parsed.error?.code ?? null;
        v.door.reached = 'door-answered';
        v.door.detail = `a JSON-RPC ${code === null ? 'result' : `error ${code}`} came back, so the `
                      + 'door itself answered — an unsigned knock is refused, which is correct';
      } else {
        v.door.reached = 'unknown';
        v.door.detail = `HTTP ${probe.status ?? probe.error} with no JSON-RPC envelope. This does `
                      + 'NOT mean the door refused: it means nothing that speaks JSON-RPC replied. '
                      + 'A CDN, a proxy or a framework route in front of the door produces the same '
                      + 'bytes, and from outside the two are indistinguishable.';
      }
    } catch (e) {
      v.door.reached = 'unknown';
      v.door.detail = `the probe could not complete: ${e.message}`;
    }
    rep.warn(doorOk, 'a knock reached the door itself (not something in front of it)',
      v.door.detail);
  }

  // ---------------------------------------------------------------- 4. the door signpost
  const rels = linkRels(home.headers.link);
  const hasSignpost = rels.some((r) => r.rel === AGENT_ENTRY_REL);
  const hasServiceDesc = rels.some((r) => r.rel === 'service-desc');
  rep.warn(hasSignpost || hasServiceDesc,
    'the front page points at a machine-readable description (Link: service-desc)',
    home.headers.link ? `Link: ${home.headers.link}` : 'no Link header on the front page');
  v.signpost = { link: home.headers.link || null, rels, agentEntry: hasSignpost, serviceDesc: hasServiceDesc };

  // ---------------------------------------------------------------- 5. facts, never graded
  const factFetches = FACT_SURFACES.map(async ([name, path, why]) => {
    const r = await boundedFetch(base + path, { allowPrivate, maxBytes: 128 * 1024 });
    return { surface: name, url: base + path, status: r.status, present: r.status === 200,
             bytes: r.bytes, why };
  });

  const mdProbe = boundedFetch(base + '/', { allowPrivate, headers: { Accept: 'text/markdown' } });
  const [factRows, md] = await Promise.all([Promise.all(factFetches), mdProbe]);

  for (const f of factRows) {
    result.facts.push(f);
    rep.info(`${f.surface}: ${f.present ? 'present' : 'absent'}`,
      `${f.url} -> ${f.status ?? 'no response'}`);
  }

  const mdType = String(md.headers['content-type'] || '');
  result.facts.push({
    surface: 'markdown negotiation', url: base + '/', status: md.status,
    present: mdType.includes('text/markdown'),
    detail: `Accept: text/markdown -> ${mdType || 'no content-type'}`
          + (md.headers.vary ? `, Vary: ${md.headers.vary}` : ', no Vary header'),
    why: 'whether a page can be read without parsing HTML',
  });
  rep.info(`markdown negotiation: ${mdType.includes('text/markdown') ? 'served' : 'not served'}`,
    `on ${base}/ — a scanner samples the sitemap, so this holding on the front page does not `
    + 'mean it holds on the others');

  const pp = home.headers['permissions-policy'];
  result.facts.push({
    surface: 'Permissions-Policy: tools', url: base + '/', status: home.status,
    present: !!pp && /(^|[^a-z])tools\s*=/.test(pp),
    detail: pp ? `Permissions-Policy: ${pp}` : 'no Permissions-Policy header',
    why: 'whether WebMCP tools on the page may be reached from another origin at all',
  });

  // ---------------------------------------------------------------- 6. DNS-AID + DNSSEC
  result.dnsAid = dns
    ? await dnsAid(new URL(home.finalUrl).hostname, { resolver })
    : { domain: new URL(home.finalUrl).hostname, queried: [], found: false, records: [],
        authenticated: false, dnssec: { state: 'unknown', detail: 'DNS lookups disabled for this run' },
        resolver: null };
  const d = result.dnsAid;
  if (d.found) {
    rep.info(`DNS-AID: ${d.records.length} record(s) under _agents.${d.domain}`,
      d.records.map((r) => `${r.label} -> ${r.target}`).join('; '));
    rep.check(d.dnssec.state === 'signed',
      'the DNS-AID zone is DNSSEC-signed (the draft makes this a MUST)',
      `${d.dnssec.state}: ${d.dnssec.detail}`);
  } else {
    rep.info('DNS-AID: no records', `nothing under _agents.${d.domain} (resolver: ${d.resolver})`);
    rep.info(`the zone ${d.domain} is ${d.dnssec.state}`, d.dnssec.detail);
  }

  // ---------------------------------------------------------------- 7. what a visitor can use
  if (card && openDoor) {
    result.interfaces.push({
      kind: 'a2a-agent-entry',
      endpoint: v.door.url,
      did,
      protocol: 'A2A JSON-RPC 2.0 (message/send), Ed25519-signed envelopes',
      identityVerified: v.signature.state === 'verified' && v.originBinding.state === 'proven',
      nextCall: 'POST a signed message/send. Every message must carry a signature from your own '
              + 'did:key, or the door will refuse it (-32001).',
    });
  }
  for (const r of d.records) {
    const alpn = r.params?.alpn;
    result.interfaces.push({
      kind: `dns-aid:${r.label}`, endpoint: r.target, alpn: alpn || null,
      identityVerified: d.dnssec.state === 'signed',
      nextCall: d.dnssec.state === 'signed'
        ? 'the record is in a signed zone and may be followed'
        : 'the zone is unsigned — the draft says a visitor MUST NOT act on this record',
    });
  }
  const mcpFact = result.facts.find((f) => f.surface === 'mcp discovery' && f.present);
  if (mcpFact) {
    result.interfaces.push({ kind: 'mcp', endpoint: mcpFact.url, identityVerified: false,
      nextCall: 'fetch this document for the MCP endpoint it names' });
  }

  result.rows = rep.rows;
  result.summary = rep.summary();
  result.verdict = verdictSentence(result);
  return result;
}

/**
 * One or two sentences a person can read, in the vocabulary the parent ISSUE fixed: the door is
 * "present / absent / broken", never "this site is (not) agent-ready". A checker that hands
 * down a category judgement about a whole site is making a claim it did not measure — which is
 * how the owner of a site that publishes llms.txt, an A2A card and a signed envelope was told
 * his site was not AI-ready, and correctly concluded the checker was blind.
 */
export function verdictSentence(r) {
  if (!r.reachable) return 'The page never loaded, so nothing was measured.';
  const v = r.verification;
  const parts = [];

  if (!v.card?.present) {
    parts.push('Agent Entry door: absent — no A2A agent card is served at the well-known path.');
  } else if (v.signature?.state === 'verified' && v.originBinding?.state === 'proven') {
    parts.push(`Agent Entry door: present, and verified. The card is signed by ${v.card.did}, `
      + `that key names this origin, and the envelope was ${v.freshness?.detail || 'signed'}.`);
  } else if (v.signature?.state === 'verified' && v.originBinding?.state === 'mismatch') {
    parts.push('Agent Entry door: broken — the card carries a valid signature, but it was signed '
      + 'for a different origin. It was copied here.');
  } else if (v.signature?.state === 'invalid') {
    parts.push('Agent Entry door: broken — a signed envelope is served and it does not verify.');
  } else {
    parts.push('Agent Entry door: present but unverified — a card is served with no valid '
      + 'signature, so nothing here shows who actually runs it.');
  }

  if (v.door?.reached === 'unknown') {
    parts.push('When we knocked, nothing speaking JSON-RPC replied — we cannot tell whether the '
      + 'door declined or nothing reached it.');
  }
  if (r.dnsAid?.found && r.dnsAid.dnssec?.state !== 'signed') {
    parts.push(`DNS-AID records exist under _agents.${r.dnsAid.domain}, but the zone is `
      + `${r.dnsAid.dnssec.state}, so a conforming visitor must not act on them.`);
  }
  const present = r.facts.filter((f) => f.present).map((f) => f.surface);
  parts.push(present.length
    ? `Also published, reported as facts and not graded: ${present.join(', ')}.`
    : 'No other agent-facing surface was found at the usual paths.');
  return parts.join(' ');
}
