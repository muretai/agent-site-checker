/**
 * src/guard.mjs — the URL guard and the bounded fetch.
 *
 * WHY THIS FILE IS LOAD-BEARING. Everything else here is a read-only report. This module is
 * the only part that takes a string an anonymous stranger typed and makes OUR infrastructure
 * open a connection with it. That is an SSRF surface by construction, and a public,
 * unauthenticated MCP tool is the most convenient possible front end for one. So the rules
 * are here, in one file, and every outbound request in this package goes through `boundedFetch`.
 *
 * WHAT IT REFUSES, AND WHY EACH ONE:
 *   * a non-http(s) scheme          — `file:`, `gopher:`, `data:` are not websites
 *   * a private / reserved IP literal — 127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16
 *     (the cloud metadata address lives there), ::1, fc00::/7, fe80::/10
 *   * `localhost` and `.local`      — the same targets spelled as names
 *   * a non-standard port           — a checker has no business speaking to :22 or :6379
 *   * more than MAX_REDIRECTS hops, and every hop is re-validated. A guard applied only to
 *     the URL the user typed is not a guard: `https://evil.example/go` answering
 *     `302 -> http://169.254.169.254/` walks straight through it.
 *
 * WHAT IT NEVER DOES: return a fetched body to the caller unbounded. `boundedFetch` reads at
 * most `maxBytes` and reports the size; the engine parses named fields out of known schemas
 * and reports those. A checker that echoes a stranger's bytes back to another stranger is a
 * proxy wearing a lab coat.
 *
 * DNS is deliberately NOT resolved here. On the Workers runtime we cannot, and a
 * resolve-then-connect check is a TOCTOU race anyway. Literal addresses are refused outright;
 * for hostnames the platform's own egress policy is the second line, and the redirect
 * re-validation is the third.
 */

const PRIVATE_V4 = [
  [/^0\./, 'this network'], [/^10\./, 'RFC 1918 private'], [/^127\./, 'loopback'],
  [/^169\.254\./, 'link-local (cloud metadata lives here)'],
  [/^172\.(1[6-9]|2\d|3[01])\./, 'RFC 1918 private'], [/^192\.168\./, 'RFC 1918 private'],
  [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, 'CGNAT'],
  [/^(22[4-9]|23\d)\./, 'multicast'], [/^(24\d|25[0-5])\./, 'reserved'],
];

const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

export const MAX_REDIRECTS = 3;
export const DEFAULT_MAX_BYTES = 512 * 1024;
export const DEFAULT_TIMEOUT_MS = 8000;

/** The user agent every request in this package sends. Named, honest, and traceable — a
 *  checker that hides behind a browser string cannot complain when it is treated as one. */
export const USER_AGENT =
  'MuretaiAgentSiteChecker/0.1 (+https://check.muretai.com; verification, read-only)';

export class RefusedURL extends Error {
  constructor(url, reason) {
    super(`refusing ${url}: ${reason}`);
    this.name = 'RefusedURL';
    this.url = url;
    this.reason = reason;
  }
}

function isIPv4Literal(host) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(host); }

/**
 * Validate one URL. Returns a URL object or throws RefusedURL. Exported so the redirect
 * loop and the tests can call the SAME function the entry point calls — a second copy of
 * this logic is how the two drift apart.
 */
export function guardURL(input, { allowPrivate = false } = {}) {
  let u;
  try {
    u = new URL(input);
  } catch {
    throw new RefusedURL(String(input), 'not a URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new RefusedURL(u.href, `scheme ${u.protocol} is not http(s)`);
  }
  // `allowPrivate` exists for ONE caller: a site owner running the CLI against their own
  // dev server or a fixture on 127.0.0.1. The Worker never passes it, and there is no query
  // parameter or tool argument that can reach it — the hosted service has no way to be talked
  // into scanning a private address. Keeping the escape hatch in the same function as the rule
  // is deliberate: a second, laxer copy of this logic for tests is how the two drift apart and
  // the tests stop testing the thing that ships.
  if (allowPrivate) return u;
  if (!ALLOWED_PORTS.has(u.port)) {
    throw new RefusedURL(u.href, `port ${u.port} is not a web port`);
  }
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new RefusedURL(u.href, `${host} names this machine or its LAN`);
  }
  if (isIPv4Literal(host)) {
    for (const [re, why] of PRIVATE_V4) {
      if (re.test(host)) throw new RefusedURL(u.href, `${host} is ${why}`);
    }
  }
  if (host.includes(':')) {                        // an IPv6 literal
    const h = host.toLowerCase();
    if (h === '::1' || h === '::' || /^f[cd]/.test(h) || /^fe[89ab]/.test(h)) {
      throw new RefusedURL(u.href, `${host} is a loopback, unique-local or link-local address`);
    }
    // IPv4-mapped addresses, in BOTH spellings. This is the hole that a naive check leaves:
    // the WHATWG URL parser normalises `::ffff:127.0.0.1` to `::ffff:7f00:1`, so a guard that
    // only looks for the dotted form lets loopback through in hexadecimal. Measured, not
    // theorised — the first run of this file's own test refused seven addresses and passed
    // `http://[::ffff:127.0.0.1]/` straight to fetch.
    const mapped = /^::ffff:(.+)$/.exec(h);
    if (mapped) {
      const tail = mapped[1];
      let v4 = null;
      if (isIPv4Literal(tail)) {
        v4 = tail;
      } else {
        const hex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail);
        if (hex) {
          const n = (parseInt(hex[1], 16) << 16) | parseInt(hex[2], 16);
          v4 = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
        }
      }
      if (v4) {
        for (const [re, why] of PRIVATE_V4) {
          if (re.test(v4)) throw new RefusedURL(u.href, `${host} maps to ${v4}, which is ${why}`);
        }
      }
    }
  }
  return u;
}

/**
 * Normalise what a person typed into something fetchable. `muretai.com` and
 * `https://muretai.com/` must reach the same place, because the first is what everyone types.
 */
export function normaliseInput(input, opts = {}) {
  const s = String(input || '').trim();
  if (!s) throw new RefusedURL('', 'no URL given');
  return guardURL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`, opts);
}

/**
 * One bounded HTTP round trip, redirects followed by hand so every hop is re-validated.
 *
 * Returns `{status, headers, body, bytes, finalUrl, redirects, error}`. A transport failure
 * is `{status: null, error}` rather than a throw: one dead route must not abort a run, and
 * "we could not connect" is itself a finding a report has to be able to state.
 */
export async function boundedFetch(url, {
  method = 'GET', body = null, headers = {},
  maxBytes = DEFAULT_MAX_BYTES, timeoutMs = DEFAULT_TIMEOUT_MS, maxRedirects = MAX_REDIRECTS,
  allowPrivate = false,
} = {}) {
  const redirects = [];
  let current = guardURL(url instanceof URL ? url.href : url, { allowPrivate });

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(current.href, {
        method,
        body,
        redirect: 'manual',
        signal: ac.signal,
        headers: { 'User-Agent': USER_AGENT, ...headers },
      });
    } catch (e) {
      clearTimeout(timer);
      return {
        status: null, headers: {}, body: '', bytes: 0,
        finalUrl: current.href, redirects,
        error: `${e.name}: ${e.message}`,
      };
    }
    clearTimeout(timer);

    const h = {};
    for (const [k, v] of res.headers) h[k.toLowerCase()] = v;

    if (res.status >= 300 && res.status < 400 && h.location) {
      let next;
      try {
        next = guardURL(new URL(h.location, current).href, { allowPrivate });
      } catch (e) {
        return {
          status: res.status, headers: h, body: '', bytes: 0,
          finalUrl: current.href, redirects,
          error: `redirect refused — ${e.reason}`,
        };
      }
      redirects.push({ from: current.href, to: next.href, status: res.status });
      current = next;
      continue;
    }

    // Read at most maxBytes. `slice` on the decoded text is not enough — the point is to
    // never PULL an unbounded body, so the reader is stopped at the byte budget.
    let bytes = 0;
    const chunks = [];
    if (res.body) {
      const reader = res.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          if (bytes <= maxBytes) chunks.push(value);
          else { await reader.cancel(); break; }
        }
      } catch { /* a truncated body is still a result: report what arrived */ }
    }
    const merged = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
    let off = 0;
    for (const c of chunks) { merged.set(c, off); off += c.byteLength; }

    return {
      status: res.status, headers: h,
      body: new TextDecoder('utf-8').decode(merged),
      bytes, finalUrl: current.href, redirects, error: null,
      truncated: bytes > maxBytes,
    };
  }

  return {
    status: null, headers: {}, body: '', bytes: 0,
    finalUrl: current.href, redirects,
    error: `more than ${maxRedirects} redirects`,
  };
}
