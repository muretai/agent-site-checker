/**
 * src/remedies.mjs — what to do about a finding, and where the rule is written down.
 *
 * TWO THINGS THIS PROVIDES, and one thing it refuses to.
 *
 * RESOURCES. Every check here measures something somebody else specified. A verdict that does
 * not say WHOSE rule it applied is an opinion, so each entry carries links to the normative
 * text — the RFC, the draft, the spec page. This is also the honest way to be disagreed with:
 * a reader who thinks we are wrong can go and read the same document.
 *
 * PROMPTS. A finding a reader cannot act on is trivia. Each entry generates text that can be
 * handed straight to a coding agent working on that site.
 *
 * WHAT IT REFUSES: any prompt that would have a site publish something untrue. Every generated
 * prompt carries HONESTY, below, and several entries say in as many words which file must NOT
 * be created if the underlying thing does not exist. This is not decoration. The whole category
 * this tool sits in scores sites on self-declaration, which rewards exactly one behaviour —
 * writing a manifest that claims a capability nobody implemented — and a remediation prompt is
 * the most efficient possible way to industrialise that. A checker that hands out "add this
 * file" prompts without that constraint is a machine for manufacturing lies about the web.
 *
 * `kind` separates two situations that must never be worded the same way:
 *   'fix'  something is BROKEN — it is published and it does not hold up.
 *   'add'  something is ABSENT — publishing no agent card is not a fault, and the prompt is
 *          offered as "if you want this, here is how", never as a defect to be closed.
 */

const HONESTY =
  'Publish only what is already true. If the thing described here does not exist on this site, '
  + 'do not create a file that says it does — a discovery document pointing at nothing is worse '
  + 'than no document, because an agent will follow it and fail. If you cannot make the '
  + 'underlying thing real, say so and stop.';

const R = {
  rfc: (n, label) => ({ label: `RFC ${n} — ${label}`, url: `https://www.rfc-editor.org/rfc/rfc${n}.html` }),
  dnsaid: { label: 'DNS-AID draft (dnsop)', url: 'https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/' },
  a2a: { label: 'A2A specification', url: 'https://a2a-protocol.org/latest/specification/' },
  mcp: { label: 'Model Context Protocol', url: 'https://modelcontextprotocol.io/' },
  llms: { label: 'llms.txt', url: 'https://llmstxt.org/' },
  agentsmd: { label: 'AGENTS.md', url: 'https://agents.md/' },
  sitemaps: { label: 'sitemaps.org protocol', url: 'https://www.sitemaps.org/protocol.html' },
  agentEntry: { label: 'Agent Entry — muretai docs', url: 'https://docs.muretai.com/guides/agent-entry/' },
  didkey: { label: 'did:key method', url: 'https://w3c-ccg.github.io/did-method-key/' },
};

/**
 * One entry per finding this tool can report. `prompt(ctx)` receives
 * `{ origin, host, did, detail }` and returns text a coding agent can act on directly.
 */
export const REMEDIES = {
  // ------------------------------------------------------------------ things that are BROKEN
  'signature-invalid': {
    kind: 'fix',
    title: 'The signed card envelope does not verify',
    resources: [R.agentEntry, R.didkey, R.rfc(8032, 'Ed25519')],
    prompt: (c) => [
      `The agent card at ${c.origin}/.well-known/agent-card.json names ${c.did || 'a did:key'},`,
      'and the signed envelope beside it at /.well-known/agent-card.sig.json does NOT verify',
      'under that key. Find out which of these is true and fix that one:',
      '',
      '  1. the envelope signs a DIFFERENT byte sequence than the card now served — something',
      '     edits or re-serialises the card after signing (a CDN minifier, a JSON re-encode, a',
      '     template that reorders keys). The signature covers exact bytes.',
      '  2. the signing key is not the key the card names — a rotation that updated one and not',
      '     the other.',
      '  3. the envelope is stale output from an older card.',
      '',
      'Do not "fix" this by removing the signed envelope. An unsigned card is an honest claim;',
      'a signature that does not verify is a broken one, and a visitor is right to refuse both',
      'the card and the door behind it.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'origin-mismatch': {
    kind: 'fix',
    title: 'The card carries a valid signature for a different origin',
    resources: [R.agentEntry, R.a2a],
    prompt: (c) => [
      `The agent card served from ${c.origin} verifies, but the endpoint inside it points`,
      `elsewhere (${c.detail || 'another origin'}). A card copied from another deployment keeps`,
      'its valid signature and keeps naming the site it was signed for, so this proves nothing',
      'about who runs this one.',
      '',
      'Either (a) this site should have its OWN key and its own signed card — generate a key,',
      'sign a card whose endpoint is this origin, and serve both; or (b) this host is a mirror',
      'and should not be serving an agent card at all.',
      '',
      'Do not edit the endpoint inside the card without re-signing: the signature covers it, and',
      'the result would be case (1) of a broken signature.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'freshness-stale': {
    kind: 'fix',
    title: 'The signed card is older than a visitor will accept',
    resources: [R.agentEntry],
    prompt: (c) => [
      `The signed card envelope at ${c.origin}/.well-known/agent-card.sig.json verifies, but it`,
      `was signed too long ago (${c.detail || 'past the freshness window'}). A visitor enforces a`,
      'six-hour window, so this card is refused even though the signature is good.',
      '',
      'A live door re-signs on a timer — hourly is the convention. A card that stopped being',
      're-signed is the signature of a static file somebody generated once and left behind, and',
      'the window exists exactly to tell those apart.',
      '',
      'Fix the re-signing job: whatever process holds the key should re-issue the envelope well',
      'inside the window and keep serving it at the same path. If nothing holds the key any',
      'more, that is the real finding — say so rather than back-dating a timestamp.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'dnssec-unsigned-with-records': {
    kind: 'fix',
    title: 'DNS-AID records are published in an unsigned zone',
    resources: [R.dnsaid, R.rfc(9460, 'SVCB and HTTPS records'), R.rfc(4033, 'DNSSEC introduction')],
    prompt: (c) => [
      `The zone ${c.host} publishes DNS-AID records under _agents.${c.host}, and the zone is not`,
      'DNSSEC-signed. The draft is explicit that a validator MUST NOT act on unsigned or',
      'invalidly signed discovery data, so a conforming agent is required to ignore every record',
      'you just published.',
      '',
      'Enable DNSSEC on the zone and make sure the DS record reaches the parent. Then confirm',
      'from OUTSIDE:',
      '',
      `    dig DS ${c.host} +short          # a DS record must come back`,
      `    dig +dnssec ${c.host} | grep ad  # the answer must carry the ad flag`,
      '',
      'Watch for the half-finished state: a zone can publish a DNSKEY at its apex while the',
      'parent delegation carries no DS. Every validator still treats that as insecure, and it',
      'looks finished from the inside.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'dnssec-incomplete': {
    kind: 'fix',
    title: 'DNSSEC was started and the chain never closed',
    resources: [R.rfc(4033, 'DNSSEC introduction'), R.dnsaid],
    prompt: (c) => [
      `The zone ${c.host} publishes a DNSKEY, so it signs its own answers — but the parent`,
      'delegation carries no DS record, so the chain of trust does not reach it and every',
      'validating resolver treats the zone as insecure. From inside the DNS provider this looks',
      'switched on; from the outside it does nothing.',
      '',
      'Get the DS record to the registrar for this domain and confirm it published:',
      '',
      `    dig DS ${c.host} +short`,
      '',
      'If the registrar is the same company as the DNS provider this is usually one toggle. If',
      'they are different companies, the DS has to be copied by hand and that is the step that',
      'gets skipped.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'door-unknown': {
    kind: 'fix',
    title: 'Nothing speaking the protocol answered the door',
    resources: [R.agentEntry, R.a2a],
    prompt: (c) => [
      `A well-formed JSON-RPC request was sent to the door this site advertises (${c.detail || c.origin}),`,
      'and what came back was not a JSON-RPC envelope. That does not mean the door refused — it',
      'means nothing that speaks the protocol replied, and from outside those look identical.',
      '',
      'The usual cause is something in front of the door: a CDN rule, a WAF, a proxy that drops',
      'or rewrites POST, an edge route that does not match the path, or a bot check that refuses',
      'clients without a browser fingerprint. An agent is not a browser and will be refused by',
      'any of them.',
      '',
      'Diagnose from the OUTSIDE, and against the origin as well as the public address — if the',
      'two answer differently, whatever sits between them is the finding. Do not test with curl',
      'alone: it sends its own user agent and sails through bot checks that would refuse a real',
      'agent.',
      '',
      HONESTY,
    ].join('\n'),
  },

  // ------------------------------------------------------------------ things that are ABSENT
  'agent-card': {
    kind: 'add',
    title: 'An A2A agent card, so an agent knows who answers here',
    resources: [R.a2a, R.agentEntry, R.didkey],
    prompt: (c) => [
      `Give ${c.host} an A2A agent card so an arriving AI agent can find out what this site`,
      'answers and address it, instead of scraping the HTML.',
      '',
      `  1. Serve the card at ${c.origin}/.well-known/agent-card.json, and the same bytes at the`,
      '     legacy path /.well-known/agent.json.',
      '  2. Include supportedInterfaces naming the endpoint that actually answers, with its',
      '     protocol binding and version.',
      '  3. If the site can hold a key, sign the card: publish the signed envelope at',
      '     /.well-known/agent-card.sig.json and re-sign it on a timer. That is what turns the',
      '     card from a claim anyone could serve into something a visitor can check.',
      '',
      'An unsigned card is still worth publishing. A card describing an endpoint that does not',
      'answer is not.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'llms.txt': {
    kind: 'add',
    title: 'llms.txt — the plain-language brief for a language model',
    resources: [R.llms],
    prompt: (c) => [
      `Write ${c.origin}/llms.txt: a short markdown brief telling a language model what this`,
      'site is, what it offers, and which URLs matter, so it does not have to infer that from',
      'navigation and marketing copy.',
      '',
      'Serve it as text/markdown with an explicit charset — plain text has no in-band way to',
      'declare its encoding, and a missing charset is how a file reaches readers as mojibake.',
      '',
      'Keep it factual and current. It is read by something that cannot tell an aspiration from',
      'a fact.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'robots.txt': {
    kind: 'add',
    title: 'robots.txt — say what crawlers and AI agents may do',
    resources: [R.rfc(9309, 'Robots Exclusion Protocol'),
                { label: 'Content Signals', url: 'https://contentsignals.org/' }],
    prompt: (c) => [
      `Add ${c.origin}/robots.txt. Beyond the usual crawl rules, state a position on AI use with`,
      'Content-Signals (search, ai-input, ai-train), and point at the sitemap.',
      '',
      'Decide each signal deliberately rather than copying a template: they are a published',
      'statement about what may be done with this content, and a default someone pasted is still',
      'a statement.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'sitemap.xml': {
    kind: 'add',
    title: 'sitemap.xml — the URL list a scanner samples',
    resources: [R.sitemaps],
    prompt: (c) => [
      `Add ${c.origin}/sitemap.xml listing the public URLs, and reference it from robots.txt.`,
      '',
      'This matters more than it used to: agent-facing scanners sample the sitemap to decide',
      'which pages to test. A capability offered on only some pages will be measured on the',
      'pages the sitemap advertises — so if you add an agent-facing feature, cover the pages',
      'listed here, not just the front page.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'agents.md': {
    kind: 'add',
    title: 'AGENTS.md — instructions for a coding agent working on this site',
    resources: [R.agentsmd],
    prompt: (c) => [
      `Add ${c.origin}/agents.md with the conventions a coding agent needs to work on this`,
      'project: how to build and test, what must not be touched, and the house rules that are',
      'not visible from the code.',
      '',
      'Write what is actually true of this repository. An AGENTS.md describing a workflow nobody',
      'follows sends every agent down the wrong path with confidence.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'api catalog': {
    kind: 'add',
    title: 'api-catalog — one place that lists the APIs this site offers',
    resources: [R.rfc(9727, 'api-catalog well-known URI'), R.rfc(9264, 'Linkset'),
                R.rfc(8288, 'Web Linking')],
    prompt: (c) => [
      `Publish an API catalog at ${c.origin}/.well-known/api-catalog, per RFC 9727.`,
      '',
      'The document is a linkset (RFC 9264): serve application/linkset+json, with one entry per',
      'API, each carrying a service-desc link to its machine-readable description (OpenAPI, an',
      'agent card, an MCP endpoint document) and a service-doc link to its human documentation.',
      '',
      'List only APIs that already exist and answer. RFC 9727 makes this the one address an',
      'agent is meant to be able to trust for "what can I call here" — an entry pointing at',
      'nothing costs a caller a failed request and costs you the address.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'mcp discovery': {
    kind: 'add',
    title: 'An MCP discovery document, if this site runs an MCP server',
    resources: [R.mcp],
    prompt: (c) => [
      `If — and only if — this site actually runs an MCP server, publish a discovery document at`,
      `${c.origin}/.well-known/mcp.json naming it: the server name and version, the endpoint URL,`,
      'the transport, and the capabilities it offers.',
      '',
      'If there is no MCP server on this origin, do not add this file. It is a pointer, and a',
      'pointer to nothing is the single most common defect in this whole category of metadata.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'mcp server card': {
    kind: 'add',
    title: 'An MCP server card, describing the server before a client connects',
    resources: [R.mcp],
    prompt: (c) => [
      `If this site runs an MCP server, describe it at ${c.origin}/.well-known/mcp/server-card.json`,
      '— what tools it exposes, how to reach it, and how (or whether) to authenticate — so a',
      'client can decide before opening a connection.',
      '',
      'This is a draft proposal, not a settled standard: adopt it because the description is',
      'useful to a client, and expect the shape to move. If there is no MCP server here, do not',
      'create the file.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'agent skills index': {
    kind: 'add',
    title: 'An agent-skills index, if this site publishes skills',
    resources: [R.mcp],
    prompt: (c) => [
      `If this site publishes agent skills — packaged instructions an agent can load — index them`,
      `at ${c.origin}/.well-known/agent-skills/index.json: what each skill is for and where to`,
      'fetch it.',
      '',
      'List skills that exist and load. An index of aspirational skills teaches agents to',
      'distrust the index.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'web bot auth directory': {
    kind: 'add',
    title: 'A signing directory, if agents leave this site signing their requests',
    resources: [R.rfc(9421, 'HTTP Message Signatures'),
                { label: 'Web Bot Auth (IETF draft)',
                  url: 'https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/' }],
    prompt: (c) => [
      `If agents act on behalf of this site and sign their outbound HTTP requests, publish the`,
      `public keys at ${c.origin}/.well-known/http-message-signatures-directory so the sites they`,
      'visit can verify them (RFC 9421 message signatures, Web Bot Auth directory).',
      '',
      'This is about requests LEAVING this site, not arriving at it — it is the outbound half of',
      'agent identity, and it is only worth publishing if something here actually signs. An',
      'empty or stale key directory is worse than none: it invites verification that then fails.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'markdown negotiation': {
    kind: 'add',
    title: 'Markdown for agents — return markdown when an agent asks for it',
    resources: [R.rfc(9110, 'HTTP semantics: content negotiation')],
    prompt: (c) => [
      `Make ${c.host} answer Accept: text/markdown with a markdown rendering of the page, while`,
      'HTML stays the default for browsers. Return Content-Type: text/markdown; charset=utf-8',
      'and set Vary: Accept so caches keep the two representations apart — without Vary, one',
      'cached HTML response is served to every markdown asker from then on.',
      '',
      'Cover every page the sitemap lists, not just the front page. Partial coverage is the',
      'common failure here and it is invisible from the page you tested: a scanner samples the',
      'sitemap, so two pages out of five reads as absent.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'dns-aid': {
    kind: 'add',
    title: 'DNS-AID — publish this site\'s agent endpoints in DNS',
    resources: [R.dnsaid, R.rfc(9460, 'SVCB and HTTPS records'), R.rfc(4033, 'DNSSEC introduction')],
    prompt: (c) => [
      `Publish DNS-AID records for ${c.host} so an agent can find its endpoints before making any`,
      'HTTP request. The convention is SVCB records (RFC 9460) at',
      '_<protocol>._agents.<domain>, with alpn declaring what the endpoint speaks:',
      '',
      `    _index._agents.${c.host}   SVCB  1 ${c.host}. alpn="h2,h3"`,
      `    _a2a._agents.${c.host}     SVCB  1 ${c.host}. alpn="h2,h3"`,
      `    _mcp._agents.${c.host}     SVCB  1 <the host serving MCP>. alpn="h2,h3"`,
      '',
      'Two things that are easy to get wrong:',
      '',
      '  * ENABLE DNSSEC FIRST. The draft says a visitor MUST NOT act on unsigned discovery data,',
      '    so records in an unsigned zone are records a conforming agent is required to ignore.',
      '  * Point at the PUBLIC address your signed card names, not at the host that happens to',
      '    serve it. If DNS sends a visitor to an internal origin whose card names a different',
      '    address, that card reads as copied from somewhere else — and it is your own site that',
      '    will look forged.',
      '',
      HONESTY,
    ].join('\n'),
  },

  'Permissions-Policy: tools': {
    kind: 'add',
    title: 'Permissions-Policy: tools — required before any page tool is reachable',
    resources: [{ label: 'WebMCP (W3C community group)', url: 'https://github.com/webmachinelearning/webmcp' }],
    prompt: (c) => [
      `If any page on ${c.host} registers WebMCP tools, send a Permissions-Policy response header`,
      'with a tools directive. Without it the tools are registered and no agent is permitted to',
      'call them — the page looks instrumented from the inside and is inert from the outside.',
      '',
      'If a tool is meant to be callable from a cross-origin frame, the frame needs',
      'allow="tools" AND the tool needs a matching exposedTo. Either half alone is a silent dead',
      'end.',
      '',
      'This checker only reads the response header. Whether the tools are actually callable can',
      'only be measured in a real browser against the live page.',
      '',
      HONESTY,
    ].join('\n'),
  },
};

/**
 * Surfaces that are CHECKED but for which no prompt is offered, and why. Kept as an explicit
 * table rather than an omission: a reader who meets a check with no remedy deserves to know it
 * was a decision.
 *
 * Empty today, and that is the healthy state. Two entries lived here — the 2023 plugin manifest
 * and a six-week-old single-author draft — until the owner ruled that a format not standardised
 * or credibly heading there should not be CHECKED at all (see FACT_SURFACES in engine.mjs). A
 * surface that does not deserve a prompt usually does not deserve a row either; this table is
 * for the rare case where it genuinely does.
 */
export const NO_REMEDY = {};

/**
 * Build the actionable list for one result. Order is deliberate: everything BROKEN first,
 * because a signature that does not verify is a live problem, while an absent llms.txt is an
 * opportunity somebody may reasonably decline.
 */
export function remediesFor(result) {
  if (!result?.reachable) return [];
  const origin = (() => {
    try { return new URL(result.target.finalUrl || result.target.url).origin; } catch { return result.target.base; }
  })();
  const host = (() => {
    try { return new URL(result.target.finalUrl || result.target.url).hostname; } catch { return origin; }
  })();
  const v = result.verification || {};
  const ctx = { origin, host, did: v.card?.did || null, detail: '' };
  const out = [];
  const push = (id, detail) => {
    const r = REMEDIES[id];
    if (!r) return;
    out.push({ id, kind: r.kind, title: r.title, resources: r.resources,
               prompt: r.prompt({ ...ctx, detail: detail || '' }) });
  };

  // broken first
  if (v.signature?.state === 'invalid') push('signature-invalid');
  if (v.originBinding?.state === 'mismatch') push('origin-mismatch', (v.originBinding.claimedOrigins || []).join(', '));
  if (v.freshness?.state === 'stale') push('freshness-stale', v.freshness.detail);
  if (result.dnsAid?.found && result.dnsAid.dnssec?.state === 'unsigned') push('dnssec-unsigned-with-records');
  if (result.dnsAid?.dnssec?.state === 'incomplete') push('dnssec-incomplete');
  if (v.door?.reached === 'unknown') push('door-unknown', v.door.url);

  // then absent
  if (!v.card?.present) push('agent-card');
  if (!result.dnsAid?.found) push('dns-aid');
  for (const f of result.facts || []) {
    if (!f.present && !NO_REMEDY[f.surface]) push(f.surface, f.detail);
  }
  return out;
}
