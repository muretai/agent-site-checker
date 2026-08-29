/**
 * src/mcp.mjs — one stateless endpoint, two generations of MCP client.
 *
 * WHY BOTH. The `2026-07-28` revision removed the `initialize` handshake and `Mcp-Session-Id`:
 * every request now carries its own `_meta.io.modelcontextprotocol/*` and servers MUST answer
 * `server/discover`. The spec's own compatibility matrix says a modern-only client against a
 * legacy-only server FAILS with no fall-forward — and the reverse is just as fatal for a tool
 * that wants to be reached: nearly every client deployed today still opens with `initialize`.
 * A server that picks one generation is invisible to half the clients on the internet, and the
 * owner of that server sees nothing but "no tools". So the era is decided PER REQUEST, and the
 * legacy answers stay field-for-field what a legacy client expects.
 *
 * WHY THERE IS NO AUTH. This is meant to be the tool an agent reaches for when it is handed a
 * URL mid-task. An API key is a step a visiting agent cannot take on its own, and one that
 * needs a human is one that does not happen. The abuse budget is spent on rate limits and the
 * fetch guard instead — see `guard.mjs`, which is the only thing standing between this endpoint
 * and an SSRF proxy.
 *
 * WHAT IS DELIBERATELY NOT HERE: no parameter is annotated with `x-mcp-header`. Mirroring a
 * tool argument into `Mcp-Param-*` puts it in every intermediary's logs, and a URL somebody is
 * checking is often one they have not published yet.
 */

import { checkSite, VERSION } from './engine.mjs';

export const SERVER_INFO = { name: 'agent-site-checker', version: VERSION,
                             title: 'Agent Site Checker' };

/** Newest first. `-32022` hands this list back so a client can pick. */
export const SUPPORTED_VERSIONS = ['2026-07-28', '2025-06-18', '2025-03-26', '2024-11-05'];
export const LEGACY_DEFAULT = '2024-11-05';
export const MODERN = '2026-07-28';

const META_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_SERVER_INFO = 'io.modelcontextprotocol/serverInfo';

/** MCP reserves -32020..-32099. These three are the ones this server can raise. */
export const MCP_ERRORS = {
  HEADER_MISMATCH: -32020,
  UNSUPPORTED_PROTOCOL_VERSION: -32022,
};

const CHECK_INPUT = {
  type: 'object',
  properties: {
    url: { type: 'string',
      description: 'The site to check. A bare domain is fine: "example.com".' },
    probe_door: { type: 'boolean', default: true,
      description: 'Send one unsigned JSON-RPC knock to the door the card itself advertises, to '
        + 'establish whether the door answered or something in front of it did. The knock is '
        + 'refused by design and writes nothing.' },
  },
  required: ['url'],
  additionalProperties: false,
};

export const TOOLS = [
  {
    name: 'check_site',
    title: 'Check what a site offers an AI agent, and whether any of it is verified',
    description:
      'You have been handed a URL. This answers whether you can TALK to that site as an agent '
      + 'rather than scrape its HTML: which interfaces it exposes (A2A agent-entry door, MCP, '
      + 'DNS-AID records), the endpoint for each, and — the part other readiness checkers do not '
      + 'do — whether the identity behind them is VERIFIED: does the agent card carry an Ed25519 '
      + 'signature that checks out under the did:key it names, does that key provably speak for '
      + 'this origin (rather than the card having been copied from another site), was it re-signed '
      + 'recently enough to be a live service, and is the DNS-AID zone DNSSEC-signed. Other '
      + 'surfaces (llms.txt, robots rules, sitemap, MCP server card, skills index, markdown '
      + 'negotiation) are reported as plain facts. There is no score and no grade: the report '
      + 'names every URL it fetched and what came back, so you can judge it yourself. Each '
      + 'finding comes with links to the specification it was measured against and a ready '
      + 'prompt for fixing or publishing it.',
    inputSchema: CHECK_INPUT,
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: 'verify_agent_card',
    title: 'Verify one site\'s agent card signature and its claim on the origin',
    description:
      'The narrow, fast check: fetch the A2A agent card and its signed envelope, and report '
      + 'whether the signature verifies under the DID the card names, whether that DID is bound '
      + 'to this origin or the card was copied here from elsewhere, and how long ago it was '
      + 'signed. Use this before trusting an identity a site claims — a card that parses is a '
      + 'claim, a card that verifies is evidence.',
    inputSchema: { type: 'object', properties: { url: CHECK_INPUT.properties.url },
                   required: ['url'], additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
];

const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });
const rpcError = (id, code, message, data) => ({
  jsonrpc: '2.0', id, error: data === undefined ? { code, message } : { code, message, data },
});

/** Wrap a result for the modern generation: `resultType` on every result, serverInfo in `_meta`. */
function modernise(result, isModern) {
  if (!isModern) return result;
  return { ...result, resultType: 'result', _meta: { [META_SERVER_INFO]: SERVER_INFO } };
}

function summaryText(r) {
  const lines = [r.verdict, ''];
  lines.push(`checked ${r.target.finalUrl || r.target.url} at ${r.checker.checkedAt} `
           + `(${r.checker.name} ${r.checker.version})`);
  if (r.interfaces?.length) {
    lines.push('', 'interfaces a visiting agent can use:');
    for (const i of r.interfaces) {
      lines.push(`  - ${i.kind} at ${i.endpoint}`
        + ` — identity ${i.identityVerified ? 'VERIFIED' : 'not verified'}`);
      if (i.nextCall) lines.push(`    next: ${i.nextCall}`);
      if (i.kind === 'a2a-agent-entry' && r.verification?.terms) {
        lines.push(`    guardrails observed: terms on the card ${r.verification.terms.state}; refusal ${r.verification.refusal?.state}; `
                 + `rate ceiling ${r.verification.limits?.state} (only the operator can measure that)`);
      }
    }
  }
  const failed = r.summary?.failed ?? [];
  if (failed.length) lines.push('', `failed checks: ${failed.join('; ')}`);

  // The caller of this tool is very often the agent that would do the fixing, so the remedies
  // are named here rather than left to be discovered in the structured payload.
  const rem = r.remedies || [];
  const broken = rem.filter((x) => x.kind === 'fix');
  const absent = rem.filter((x) => x.kind === 'add');
  if (rem.length) {
    lines.push('');
    if (broken.length) lines.push(`to fix (${broken.length}): ${broken.map((x) => x.id).join(', ')}`);
    if (absent.length) lines.push(`not published (${absent.length}, none of it a fault): `
      + absent.map((x) => x.id).join(', '));
    lines.push('structuredContent.remedies carries, for each of these, links to the normative '
      + 'specification and a prompt written to be handed to whoever works on that site. Every '
      + 'prompt says to publish only what is already true — do not create a discovery document '
      + 'for something that does not exist.');
  }
  return lines.join('\n');
}

async function callTool(name, args) {
  const url = args?.url;
  if (typeof url !== 'string' || !url.trim()) {
    return { isError: true, content: [{ type: 'text', text: 'url is required' }] };
  }
  const full = await checkSite(url, { probeDoor: args?.probe_door !== false });

  if (full.refused) {
    return { isError: true, content: [{ type: 'text', text: `refused: ${full.refused}` }],
             structuredContent: full };
  }
  if (name === 'verify_agent_card') {
    const slim = {
      checker: full.checker, target: full.target,
      reachable: full.reachable, verification: full.verification, verdict: full.verdict,
    };
    return { content: [{ type: 'text', text: summaryText(full) }], structuredContent: slim };
  }
  return { content: [{ type: 'text', text: summaryText(full) }], structuredContent: full };
}

/**
 * Dispatch one JSON-RPC message. `headers` is a plain lower-cased object; it is inspected only
 * to enforce the 2026-07-28 header/body agreement.
 *
 * On the header rules: the revision makes `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name`
 * REQUIRED and says they must match the body. This server raises `-32020` when a header is
 * present and CONTRADICTS the body — the case the rule exists to catch, where an intermediary
 * routed or rate-limited on a header that lied. It does not reject a request for omitting them:
 * refusing a client that is otherwise speaking the protocol correctly makes this tool
 * unreachable for the sake of a header no intermediary here consumes.
 */
export async function dispatch(message, headers = {}) {
  const id = message?.id ?? null;
  const method = message?.method;
  const meta = message?.params?._meta || message?._meta || {};
  const declared = meta[META_VERSION];
  const isModern = declared === MODERN || method === 'server/discover';

  if (declared && !SUPPORTED_VERSIONS.includes(declared)) {
    return rpcError(id, MCP_ERRORS.UNSUPPORTED_PROTOCOL_VERSION,
      `unsupported protocol version ${declared}`, { supported: SUPPORTED_VERSIONS });
  }
  const hMethod = headers['mcp-method'];
  if (hMethod && method && hMethod !== method) {
    return rpcError(id, MCP_ERRORS.HEADER_MISMATCH,
      `Mcp-Method header ${JSON.stringify(hMethod)} does not match the body method `
      + `${JSON.stringify(method)}`);
  }
  const hVersion = headers['mcp-protocol-version'];
  if (hVersion && declared && hVersion !== declared) {
    return rpcError(id, MCP_ERRORS.HEADER_MISMATCH,
      `MCP-Protocol-Version header ${JSON.stringify(hVersion)} does not match the body`);
  }

  switch (method) {
    case 'initialize': {
      const asked = message?.params?.protocolVersion;
      const version = SUPPORTED_VERSIONS.includes(asked) ? asked : LEGACY_DEFAULT;
      return rpcResult(id, {
        protocolVersion: version,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
        instructions:
          'Call check_site with any URL you have been handed to find out whether you can speak '
          + 'to that site as an agent, and whether the identity it claims is cryptographically '
          + 'verified. Nothing here is scored: every check names the URL it fetched and what '
          + 'came back. This server is read-only and needs no credentials.',
      });
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null;                                  // a notification: no response at all
    case 'ping':
      return rpcResult(id, modernise({}, isModern));

    case 'server/discover':
      return rpcResult(id, {
        resultType: 'result',
        protocolVersions: SUPPORTED_VERSIONS,
        serverInfo: SERVER_INFO,
        capabilities: { tools: { listChanged: false } },
        instructions: 'Read-only site verification. No credentials, no session.',
        _meta: { [META_SERVER_INFO]: SERVER_INFO },
      });

    case 'tools/list':
      return rpcResult(id, modernise({ tools: TOOLS }, isModern));

    case 'tools/call': {
      const name = message?.params?.name;
      if (!TOOLS.some((t) => t.name === name)) {
        return rpcError(id, -32602, `unknown tool ${JSON.stringify(name)}`);
      }
      try {
        const out = await callTool(name, message?.params?.arguments || {});
        return rpcResult(id, modernise(out, isModern));
      } catch (e) {
        return rpcResult(id, modernise(
          { isError: true, content: [{ type: 'text', text: `check failed: ${e.message}` }] },
          isModern));
      }
    }
    default:
      return rpcError(id, -32601, `method ${JSON.stringify(method)} not found`);
  }
}

/** The discovery document, at the path Cloudflare's scanner taught agents to look at. */
export function wellKnownMcp(origin) {
  return {
    name: SERVER_INFO.title,
    version: SERVER_INFO.version,
    description: 'Verify what a website offers AI agents: signatures, origin binding, freshness, '
               + 'DNSSEC — not a score.',
    url: `${origin}/mcp`,
    transport: { type: 'streamable-http' },
    capabilities: { tools: true },
    protocolVersions: SUPPORTED_VERSIONS,
  };
}
