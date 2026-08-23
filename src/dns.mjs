/**
 * src/dns.mjs — DNS-AID lookups, and the DNSSEC state that decides whether they mean anything.
 *
 * WHAT DNS-AID IS. `draft-mozleywilliams-dnsop-dnsaid` (DNS for AI Discovery; the coalition
 * sits under the Linux Foundation) is a naming convention over records that already exist —
 * no new record type, no new server. An agent is published as an SVCB record (RFC 9460) at
 *
 *     [agent-id]._[protocol]._agents.[domain]
 *
 * with `_index`, `_a2a` and `_mcp` as the entry labels and `alpn` declaring what the endpoint
 * at the other end speaks. It sits one layer BELOW MCP and A2A: it is how an address is found
 * before any connection exists.
 *
 * WHY THIS MODULE REPORTS DNSSEC AND NOT JUST PRESENCE — the whole reason it exists. The
 * draft is not soft about it: *"A public authoritative zone used for the purposes of agent
 * discovery MUST use DNSSEC"*, and a validator *"MUST NOT act on unsigned or invalidly signed
 * discovery data."* Unsigned DNS is a hint from whoever happens to be answering. So a checker
 * that finds the records and says "present" has told you nothing about whether you may follow
 * them, and every checker in this category today stops exactly there. `authenticated` below is
 * the AD bit from a validating resolver, and it is reported separately from `found` on purpose:
 * "records exist, and a conforming visitor is required to ignore them" is a real outcome and
 * needs a way to be said.
 *
 * WHICH RESOLVER, AND WHY IT IS NAMED IN THE OUTPUT. A DNSSEC verdict is a claim about a
 * conversation with a specific resolver; a report that does not name it is not reproducible.
 */

import { boundedFetch, USER_AGENT } from './guard.mjs';

/** RFC 9460. The DoH JSON APIs take the number for types they do not name. */
export const TYPE_SVCB = 64;

export const RESOLVERS = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/resolve',
};

/** The protocol labels the draft reserves. `_index` is the capability entry point. */
export const DNSAID_LABELS = ['_index', '_a2a', '_mcp'];

/**
 * One DoH query. Returns `{name, type, status, ad, answers, error, resolver}`.
 *
 * `do=1` asks for DNSSEC data; `ad` is the resolver's statement that it VALIDATED the answer.
 * A SERVFAIL (`status === 2`) from a validating resolver is the bogus case — a zone that is
 * signed and whose signatures do not check out — which is strictly worse than unsigned and is
 * reported as such rather than being flattened into "not found".
 */
export async function dohQuery(name, type, { resolver = 'cloudflare' } = {}) {
  const base = RESOLVERS[resolver] || resolver;
  const url = `${base}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&do=1`;
  const res = await boundedFetch(url, {
    headers: { Accept: 'application/dns-json', 'User-Agent': USER_AGENT },
    maxBytes: 64 * 1024,
    timeoutMs: 6000,
  });
  if (res.error || res.status !== 200) {
    return { name, type, status: null, ad: null, answers: [], resolver,
             error: res.error || `resolver answered HTTP ${res.status}` };
  }
  let j;
  try {
    j = JSON.parse(res.body);
  } catch (e) {
    return { name, type, status: null, ad: null, answers: [], resolver,
             error: `resolver answer was not JSON: ${e.message}` };
  }
  return {
    name, type, resolver,
    status: typeof j.Status === 'number' ? j.Status : null,
    ad: j.AD === true,
    answers: Array.isArray(j.Answer) ? j.Answer.map((a) => ({
      name: a.name, type: a.type, ttl: a.TTL, data: a.data,
    })) : [],
    error: null,
  };
}

/**
 * Is this zone signed, and does a validating resolver say so?
 *
 * Asked as a DS query at the apex rather than as "did some answer carry AD": a NOERROR with a
 * DS record is the delegation actually carrying a signed link from the parent, which is the
 * thing the draft requires. An unsigned zone answers NOERROR with no DS, which is why `found`
 * and `status` are both reported — "no DS" and "the query failed" are different facts.
 */
export async function zoneDnssec(domain, opts = {}) {
  const q = await dohQuery(domain, 'DS', opts);
  if (q.error) return { state: 'unknown', detail: q.error, resolver: q.resolver };
  if (q.status === 2) {
    return { state: 'bogus', resolver: q.resolver,
             detail: 'the resolver returned SERVFAIL — a signed zone whose signatures do not validate' };
  }
  const ds = q.answers.filter((a) => a.type === 43);
  if (ds.length) {
    return { state: 'signed', resolver: q.resolver, records: ds.length,
             detail: `${ds.length} DS record(s) at ${domain}, answer ${q.ad ? 'authenticated (AD)' : 'not marked AD'}` };
  }
  return { state: 'unsigned', resolver: q.resolver,
           detail: `no DS record at ${domain} — the zone is not signed, so a conforming DNS-AID `
                 + `visitor is required NOT to act on any discovery record found in it` };
}

/**
 * Pull apart an SVCB record in presentation form far enough to say something useful.
 * Deliberately shallow: the point is to report what is published, not to re-specify RFC 9460.
 * An unparseable record is returned as `raw` rather than dropped — silently discarding a
 * record we did not understand is how a checker reports "absent" for something present.
 */
export function parseSvcb(data) {
  const out = { raw: data, priority: null, target: null, params: {} };
  if (typeof data !== 'string') return out;
  const parts = data.trim().split(/\s+/);
  if (parts.length >= 2) {
    out.priority = Number.isNaN(Number(parts[0])) ? null : Number(parts[0]);
    out.target = parts[1].replace(/\.$/, '');
  }
  for (const tok of parts.slice(2)) {
    const eq = tok.indexOf('=');
    if (eq === -1) out.params[tok] = true;
    else out.params[tok.slice(0, eq)] = tok.slice(eq + 1).replace(/^"|"$/g, '');
  }
  return out;
}

/**
 * The full DNS-AID probe for one hostname.
 *
 * Queries `_index`, `_a2a` and `_mcp` under `_agents.<host>`, and — only if none of them
 * answered — retries one label up. A site is commonly `www.example.com` while its discovery
 * zone is `example.com`, and reporting "absent" because we asked the wrong name would be the
 * format-blindness this whole product exists to avoid. Whichever name was asked is returned,
 * so the report can say it.
 */
export async function dnsAid(hostname, opts = {}) {
  const candidates = [hostname];
  const labels = hostname.split('.');
  if (labels.length > 2) candidates.push(labels.slice(1).join('.'));

  for (const domain of candidates) {
    const queries = [];
    for (const label of DNSAID_LABELS) {
      queries.push(dohQuery(`${label}._agents.${domain}`, TYPE_SVCB, opts));
    }
    const results = await Promise.all(queries);
    const records = [];
    for (const r of results) {
      for (const a of r.answers) {
        if (a.type === TYPE_SVCB) {
          records.push({ name: r.name, label: r.name.split('.')[0], ...parseSvcb(a.data), ttl: a.ttl });
        }
      }
    }
    const authenticated = results.some((r) => r.ad === true);
    if (records.length || domain === candidates[candidates.length - 1]) {
      const dnssec = await zoneDnssec(domain, opts);
      return {
        domain,
        queried: results.map((r) => ({ name: r.name, status: r.status, ad: r.ad, error: r.error })),
        found: records.length > 0,
        records,
        authenticated,
        dnssec,
        resolver: results[0]?.resolver ?? null,
      };
    }
  }
  return { domain: hostname, queried: [], found: false, records: [], authenticated: false,
           dnssec: { state: 'unknown', detail: 'not queried' }, resolver: null };
}
