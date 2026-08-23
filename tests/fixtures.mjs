/**
 * tests/fixtures.mjs — sites to point the checker at.
 *
 * Every fixture is a REAL HTTP server on loopback, and the checker reaches it the way it
 * reaches anything else: over the network, through `checkSite`. No test calls a detection
 * function directly, because a test that imports the checker's internals only proves the
 * checker agrees with itself — which is exactly the discipline that would have caught a
 * feature shipping green with nothing in the product producing it.
 */

import { createServer } from 'node:http';
import { makeCardEnvelope, newSeedHex, didFromSeedHex } from '@muretai/agent-entry';

/** Start a server on an arbitrary free port; returns {origin, close}. */
export function serve(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        origin: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

/**
 * A site that serves an agent card, its signed envelope, and a door.
 *
 * `mutate` is the whole point: one named lever per producer, so a test can neuter exactly one
 * thing and prove the checker goes RED on the intended check and no other.
 *   'none'          — conformant
 *   'no-signature'  — the card is served, the envelope is not
 *   'bad-signature' — an envelope is served whose signature does not check out
 *   'copied-card'   — a VALID signature over a card that names a different origin
 *   'stale'         — a valid signature over a card signed long ago
 *   'edge-swallows' — the door path answers with a plain 404 body, as a CDN would
 */
export async function siteWithCard({ mutate = 'none', extras = {} } = {}) {
  const seed = newSeedHex();
  const did = didFromSeedHex(seed);
  let ref;

  const handler = (req, res) => {
    const url = new URL(req.url, ref.origin);
    const path = url.pathname;
    const origin = mutate === 'copied-card' ? 'https://elsewhere.example' : ref.origin;

    const card = {
      protocolVersion: '0.2',
      name: 'Fixture Desk',
      description: 'a fixture',
      url: `${origin}/`,
      did,
      agentEntry: { open_door: true },
      supportedInterfaces: [{ url: `${origin}/`, protocolBinding: 'JSONRPC', protocolVersion: '0.2' }],
    };

    const send = (status, body, type = 'application/json; charset=utf-8', headers = {}) => {
      res.writeHead(status, { 'Content-Type': type, ...headers });
      res.end(body);
    };

    if (path === '/.well-known/agent-card.json' || path === '/.well-known/agent.json') {
      return send(200, JSON.stringify(card));
    }
    if (path === '/.well-known/agent-card.sig.json') {
      if (mutate === 'no-signature') return send(404, JSON.stringify({ error: 'not found' }));
      const ts = mutate === 'stale'
        ? Math.floor(Date.now() / 1000) - 48 * 3600
        : Math.floor(Date.now() / 1000);
      const env = makeCardEnvelope(seed, card, ts);
      if (mutate === 'bad-signature') {
        // Flip one base64 character. The envelope stays well-formed and the DID stays right,
        // so only an actual verification can tell the difference — which is the point.
        const s = env.sig;
        env.sig = (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
      }
      return send(200, JSON.stringify(env));
    }
    if (path === '/' && req.method === 'POST') {
      if (mutate === 'edge-swallows') {
        // Byte-identical to what an entry's own decline looks like — which is the trap.
        return send(404, JSON.stringify({ error: 'not found' }));
      }
      return send(200, JSON.stringify({
        jsonrpc: '2.0', id: 'agent-site-checker',
        error: { code: -32001, message: 'signature verification failed' },
      }));
    }
    if (path === '/' && req.method === 'GET') {
      return send(200, '<!doctype html><title>fixture</title>', 'text/html; charset=utf-8', {
        Link: '</.well-known/agent-card.json>; rel="service-desc"',
      });
    }
    if (extras[path]) {
      const [body, type] = extras[path];
      return send(200, body, type);
    }
    return send(404, JSON.stringify({ error: 'not found' }));
  };

  ref = await serve(handler);
  return { ...ref, did, seed, mutate };
}

/** A site with no agent-facing surface at all. */
export async function bareSite() {
  return serve((req, res) => {
    if (req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!doctype html><title>just a website</title>');
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });
}
