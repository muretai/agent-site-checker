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

/** The low 32 bits of an IPv6 address, written as two hex groups, read back as a dotted quad. */
function hexPairToV4(hi, lo) {
  const n = ((parseInt(hi, 16) << 16) | parseInt(lo, 16)) >>> 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

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
  // The trailing dot is the root label and it is legal in a URL: `localhost.` resolves to
  // loopback and `foo.local.` to the LAN, while neither matches a check written against the
  // dotless spelling. Strip it before any name comparison — an audit found both slipping past.
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new RefusedURL(u.href, `${host} names this machine or its LAN`);
  }
  if (isIPv4Literal(host)) {
    for (const [re, why] of PRIVATE_V4) {
      if (re.test(host)) throw new RefusedURL(u.href, `${host} is ${why}`);
    }
  }
  if (host.includes(':')) {                        // an IPv6 literal
    const h = host;
    if (h === '::1' || h === '::' || /^f[cd]/.test(h) || /^fe[89ab]/.test(h)) {
      throw new RefusedURL(u.href, `${host} is a loopback, unique-local or link-local address`);
    }
    // EVERY IPv6 FORM THAT EMBEDS AN IPv4 ADDRESS, not just `::ffff:`.
    //
    // This was a denylist with named holes, and an audit walked through three of them. The URL
    // parser rewrites `::169.254.169.254` to `::a9fe:a9fe`, `64:ff9b::169.254.169.254` (NAT64)
    // to `64:ff9b::a9fe:a9fe`, and `2002:a9fe:a9fe::` (6to4) keeps the address in its first two
    // groups — so a guard that only decoded `::ffff:` let link-local through in three
    // notations. The families below all carry a v4 address in the low 32 bits (or, for 6to4,
    // the high ones), so each is decoded and run through the SAME v4 rules. Deprecated and
    // non-routable is not the same as unreachable, and on Node — where this same file ships in
    // the CLI — there is no runtime backstop underneath it at all.
    const embedded = [];
    const low32 = /^(?:::ffff:|::|64:ff9b(?:::|:[0-9a-f:]*:))([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
    if (low32) embedded.push(hexPairToV4(low32[1], low32[2]));
    const dotted = /(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/.exec(h);
    if (dotted) embedded.push(dotted[1]);
    const sixToFour = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4}):/.exec(h);
    if (sixToFour) embedded.push(hexPairToV4(sixToFour[1], sixToFour[2]));
    for (const v4 of embedded.filter(Boolean)) {
      for (const [re, why] of PRIVATE_V4) {
        if (re.test(v4)) {
          throw new RefusedURL(u.href, `${host} embeds ${v4}, which is ${why}`);
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
  allowPrivate = false, deadline = null, sameOriginOnly = null,
} = {}) {
  const redirects = [];
  let method_ = method, body_ = body;
  let current = guardURL(url instanceof URL ? url.href : url, { allowPrivate });
  // WHAT `allowPrivate` VOUCHES FOR IS ONE MACHINE: the one the caller named, and no other.
  //
  // The flag's whole stated purpose (see guardURL) is "a site owner running the CLI against
  // their own dev server". That is a statement about an address the operator typed and can see.
  // It is NOT a statement about wherever that server later points — a redirect is the REMOTE
  // end choosing the next address, and nobody vouched for its judgment. Carrying the allowance
  // into the hop turned `--allow-private` into "follow this stranger anywhere", and a dev box
  // in CI answering `302 -> http://169.254.169.254/` handed over cloud credentials on a flag
  // whose documented meaning was "my laptop".
  //
  // So the allowance is scoped to the vouched HOST: a hop that stays on that machine keeps it
  // (the ordinary `/` -> `/en/` and trailing-slash redirects a dev server makes), and a hop
  // that leaves it is re-validated under the full guard like any other stranger's URL.
  // Scoped by host and not by origin on purpose: `allowPrivate` already grants every port on
  // that machine, so a hop to another port there is no new capability. The known cost is that
  // `localhost` -> `127.0.0.1` is two hosts to this rule and the second is refused; spelling
  // the entry URL the way the server redirects is the workaround, and narrowing the vouch is
  // the right way to be wrong.
  const vouchedHost = current.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');

  for (let hop = 0; hop <= maxRedirects; hop++) {
    // THE TIMEOUT USED TO BE PER HOP, WHICH IS NOT A CEILING.
    //
    // This timer lives inside the redirect loop, so four hops cost four full timeouts, and the
    // engine runs six such stages in sequence — an attacker who redirect-chains and then stalls
    // every path made one check take minutes, on a service anyone may call for free. `deadline`
    // is an absolute wall for the WHOLE check, passed down from the caller: each hop gets the
    // smaller of its own timeout and whatever is left.
    const remaining = deadline == null ? timeoutMs : deadline - Date.now();
    if (deadline != null && remaining <= 0) {
      return { status: null, headers: {}, body: '', bytes: 0,
               finalUrl: current.href, redirects,
               error: 'the overall time budget for this check ran out' };
    }
    const ac = new AbortController();
    // WHICH CLOCK THIS ABORT BELONGS TO IS DECIDED HERE, not re-derived after it fires.
    //
    // Asking `deadline - Date.now() <= 0` inside the catch to mean "the wall is why" is a race,
    // and it was observed losing: the timer is armed for EXACTLY the time left, so when it
    // fires the budget is zero give or take a millisecond, and a timer that lands a hair early
    // reads as "not past the deadline" — and a stalled body gets reported as a successful
    // empty one. Which timer won is known at arming time, so record it then.
    const wallIsCloser = deadline != null && Math.max(1, remaining) <= timeoutMs;
    let abortedByTimer = false;
    const timer = setTimeout(() => { abortedByTimer = true; ac.abort(); },
                             Math.min(timeoutMs, Math.max(1, remaining)));
    let res;
    try {
      res = await fetch(current.href, {
        method: method_,
        body: body_,
        redirect: 'manual',
        signal: ac.signal,
        headers: { 'User-Agent': USER_AGENT, ...headers },
      });
    } catch (e) {
      clearTimeout(timer);
      return {
        status: null, headers: {}, body: '', bytes: 0,
        finalUrl: current.href, redirects,
        // A server that stalls before its HEADERS hit the same wall as one that stalls in the
        // body, and it should say the same thing rather than "AbortError".
        error: abortedByTimer && wallIsCloser
          ? 'the overall time budget for this check ran out'
          : `${e.name}: ${e.message}`,
      };
    }
    // THE TIMER IS DELIBERATELY STILL ARMED HERE.
    //
    // It used to be cleared on this line, which disarmed the AbortController for the whole body
    // read below — so a server that answered its headers in 4 ms and then trickled one byte
    // every 400 ms was bounded by nothing at all. Measured: a 700 ms budget still running after
    // 25 s, and 512 KiB at that rate is about 58 hours. Headers were bounded; the body was not,
    // and the body is the part an attacker controls the pace of. It is cleared after the read
    // instead, so `timeoutMs` and `deadline` cover the round trip they claim to cover.

    const h = {};
    for (const [k, v] of res.headers) h[k.toLowerCase()] = v;

    if (res.status >= 300 && res.status < 400 && h.location) {
      clearTimeout(timer);   // this hop is over; the next pass through the loop arms its own
      let next;
      // The vouch travels only as far as the machine it was made about (see `vouchedHost`).
      let hopHost = null;
      try {
        hopHost = new URL(h.location, current).hostname
          .toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
      } catch { /* an unparseable Location falls through to guardURL, which refuses it */ }
      const hopAllowPrivate = allowPrivate && hopHost !== null && hopHost === vouchedHost;
      try {
        next = guardURL(new URL(h.location, current).href, { allowPrivate: hopAllowPrivate });
      } catch (e) {
        return {
          status: res.status, headers: h, body: '', bytes: 0,
          finalUrl: current.href, redirects,
          error: `redirect refused — ${e.reason}`,
        };
      }
      // A SAME-ORIGIN RULE ENFORCED ONCE IS NOT ENFORCED.
      //
      // The door POST is restricted to the origin under check (see engine.mjs, "WHERE THE ONE
      // POST THIS TOOL MAKES IS ALLOWED TO GO") because the target comes out of a stranger's
      // JSON. That restriction was applied to the FIRST url and then discarded here: a card
      // advertising a same-origin door that answers `307 Location: https://victim.example/x`
      // had the POST — method, body and all — delivered to the victim, with the victim's
      // status handed back as an oracle. It is the confused deputy the engine's comment says
      // it closed, one hop later.
      if (sameOriginOnly && next.origin !== sameOriginOnly) {
        return {
          status: res.status, headers: h, body: '', bytes: 0,
          finalUrl: current.href, redirects,
          error: `redirect refused - it leaves the origin under check (${next.origin})`,
        };
      }
      // RFC 9110 SS15.4: 301/302/303 are rewritten to GET by every real client; only 307/308
      // preserve the method. Carrying a POST body through a 302 sends it somewhere the sender
      // never addressed it.
      if (res.status === 301 || res.status === 302 || res.status === 303) {
        method_ = 'GET';
        body_ = null;
      }
      redirects.push({ from: current.href, to: next.href, status: res.status });
      current = next;
      continue;
    }

    // Read at most maxBytes. `slice` on the decoded text is not enough — the point is to
    // never PULL an unbounded body, so the reader is stopped at the byte budget.
    let bytes = 0;
    const chunks = [];
    // THE BUDGET HAS TO BE CHECKED WHERE THE TIME IS ACTUALLY SPENT.
    //
    // The armed AbortController above is what makes the wall hold, and it is the half that
    // covers the hard case: its timer is set to min(timeoutMs, what is left of the deadline),
    // so it fires on time even for a body that sends NOTHING after its headers and therefore
    // never resolves a read for any in-loop check to run between.
    //
    // WHAT THE SUITE CAN AND CANNOT PROVE ABOUT THE LINE BELOW, stated here so nobody later
    // mistakes it for a tested guard. On Node it is unreachable: the abort is armed to exactly
    // min(timeoutMs, time left), so it always fires first, and deleting this line changes no
    // observable behaviour — measured, not assumed. It is kept because it does not rest on a
    // runtime interrupting a read already IN FLIGHT, which is a guarantee this file cannot
    // make across both places it ships (the Node CLI and Workers), and because it names the
    // verdict directly instead of inferring it from a clock reading in an exception handler.
    // If it is ever removed, the `catch` below is the only thing holding the wall up.
    //
    // Either way the caller gets the verdict and not a silently truncated body reported as a
    // success: "we ran out of time" is a finding, and a short card is a different one.
    let ranOut = false;
    if (res.body) {
      const reader = res.body.getReader();
      try {
        for (;;) {
          if (deadline != null && deadline - Date.now() <= 0) { ranOut = true; break; }
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          if (bytes <= maxBytes) chunks.push(value);
          else { await reader.cancel(); break; }
        }
      } catch {
        // The abort lands here. If the wall is what fired it, say so; otherwise a truncated
        // body is still a result and we report what arrived.
        if (abortedByTimer && wallIsCloser) ranOut = true;
      } finally {
        clearTimeout(timer);
        if (ranOut) await reader.cancel().catch(() => {});
      }
    } else {
      clearTimeout(timer);
    }
    if (ranOut) {
      return { status: null, headers: {}, body: '', bytes: 0,
               finalUrl: current.href, redirects,
               error: 'the overall time budget for this check ran out' };
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
