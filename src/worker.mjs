/**
 * src/worker.mjs — the edge entry point: a page, a JSON API, and an MCP endpoint.
 *
 * FOUR SURFACES, ONE ENGINE. The page and the MCP tool must never be able to disagree about
 * what a site publishes, so they call the same `checkSite`. The moment a "web version" and an
 * "agent version" of a checker diverge is the moment one of them starts lying.
 *
 * WHY THE MCP ENDPOINT IS ON ITS OWN HOST. muretai.com's `/` IS an A2A door. An A2A door and
 * an MCP endpoint must never share a path — two protocols answering the same POST is how a
 * refusal from one gets read as a result from the other. `check.muretai.com` keeps them apart
 * with a hostname rather than with a convention nobody can see.
 *
 * ABUSE POSTURE. Anonymous by design (see mcp.mjs), so the limits do the work the login would
 * have done: a per-IP rate limit if the binding is configured, a short result cache so a
 * popular URL is fetched once, and `guard.mjs` on every outbound request. Nothing here ever
 * returns a fetched body to the caller.
 */

import { checkSite } from './engine.mjs';
import { dispatch, wellKnownMcp } from './mcp.mjs';
import { renderPage } from './page.mjs';

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name',
};

/** How long a result is reused. Long enough that a link doing the rounds costs one fetch;
 *  short enough that a site owner who just deployed a fix sees it change. */
const CACHE_TTL_S = 600;

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj, null, 2), { status, headers: { ...JSON_HEADERS, ...extra } });

/**
 * Rate limit, when the binding exists. Deliberately fail-OPEN: a misconfigured binding must
 * degrade this into a slower service, not a broken one. The fetch guard is the control that
 * must never fail open; this one is a cost control.
 */
async function rateLimited(env, request) {
  if (!env?.RATE_LIMITER?.limit) return false;
  const ip = request.headers.get('cf-connecting-ip') || 'anon';
  try {
    const { success } = await env.RATE_LIMITER.limit({ key: ip });
    return !success;
  } catch {
    return false;
  }
}

/**
 * Origin validation for the MCP endpoint. A page in someone's browser must not be able to
 * drive this endpoint on their behalf — the DNS-rebinding case the spec calls out. Requests
 * carrying no Origin are the normal case for a real MCP client and are allowed; a request
 * carrying one has to be from us.
 */
function originAllowed(request, url) {
  const origin = request.headers.get('origin');
  if (!origin) return true;
  try {
    return new URL(origin).origin === url.origin;
  } catch {
    return false;
  }
}

async function cachedCheck(target, opts, ctx) {
  const key = new Request(`https://cache.invalid/check?u=${encodeURIComponent(target)}`
    + `&p=${opts.probeDoor ? 1 : 0}`);
  const cache = globalThis.caches?.default;
  if (cache) {
    const hit = await cache.match(key);
    if (hit) return { result: await hit.json(), cached: true };
  }
  const result = await checkSite(target, opts);
  if (cache && result.reachable) {
    const store = new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': `max-age=${CACHE_TTL_S}` },
    });
    ctx?.waitUntil ? ctx.waitUntil(cache.put(key, store)) : await cache.put(key, store);
  }
  return { result, cached: false };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...JSON_HEADERS, Allow: 'GET, POST, OPTIONS' } });
    }

    // ------------------------------------------------------------------ the discovery document
    if (path === '/.well-known/mcp.json') {
      return json(wellKnownMcp(url.origin), 200, { 'Cache-Control': 'public, max-age=3600' });
    }

    // ------------------------------------------------------------------ the MCP endpoint
    if (path === '/mcp') {
      if (request.method !== 'POST') {
        return json({ error: 'this endpoint speaks MCP over HTTP POST' }, 405, { Allow: 'POST, OPTIONS' });
      }
      if (!originAllowed(request, url)) {
        return json({ error: 'origin not allowed' }, 403);
      }
      if (await rateLimited(env, request)) {
        return json({ jsonrpc: '2.0', id: null,
                      error: { code: -32000, message: 'rate limited — try again shortly' } }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }, 400);
      }
      const headers = {};
      for (const [k, val] of request.headers) headers[k.toLowerCase()] = val;

      // A batch is a JSON array. Notifications produce no response, so an all-notification
      // batch answers 202 with no body rather than an empty array.
      const messages = Array.isArray(body) ? body : [body];
      const out = [];
      for (const m of messages) {
        const r = await dispatch(m, headers);
        if (r) out.push(r);
      }
      if (!out.length) return new Response(null, { status: 202, headers: JSON_HEADERS });
      return json(Array.isArray(body) ? out : out[0]);
    }

    // ------------------------------------------------------------------ the JSON API
    if (path === '/api/check') {
      const target = url.searchParams.get('url');
      if (!target) return json({ error: 'pass ?url=' }, 400);
      if (await rateLimited(env, request)) {
        return json({ error: 'rate limited — try again shortly' }, 429);
      }
      const probeDoor = url.searchParams.get('probe') !== '0';
      const { result, cached } = await cachedCheck(target, { probeDoor }, ctx);
      return json(result, 200, {
        'Cache-Control': `public, max-age=${CACHE_TTL_S}`,
        'X-Result-Cached': cached ? '1' : '0',
      });
    }

    // ------------------------------------------------------------------ the page
    if (path === '/' || path === '/check') {
      return new Response(renderPage(url.searchParams.get('url') || ''), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          // The page names the endpoint an agent should use instead of scraping it. Same
          // courtesy this tool checks other sites for.
          Link: `<${url.origin}/.well-known/mcp.json>; rel="service-desc"`,
        },
      });
    }

    if (path === '/robots.txt') {
      return new Response('User-agent: *\nAllow: /\n', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }

    return json({ error: 'not found' }, 404);
  },
};
