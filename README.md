# Agent Site Checker

Verify what a website tells AI agents — and whether any of it can be proven.

```
npx @muretai/agent-site-checker example.com
```

Hosted at **https://check.muretai.com** (a page for people, an MCP endpoint for agents).

## What this is, and what it deliberately is not

There is already a category of tools that scan a site for the two dozen agent-facing
standards and report how many are present. Cloudflare's
[isitagentready.com](https://isitagentready.com/) is the thorough one, it is free, and it
has an MCP server. **Use it for that.** This is not a ninth scanner.

This answers the question every one of them leaves open: **of the things that are present,
which ones can be proven?** Not one tool in that category verifies a signature.

A JSON file at a well-known path is a claim. A signature that verifies under the key that
file names, from a key that provably speaks for this origin, re-signed within the last six
hours, is a fact.

## The three layers

**DNS.** Resolve DNS-AID records (`_index._agents.<domain>`, `_a2a._agents.…`,
`_mcp._agents.…` — SVCB, RFC 9460) **and report whether the zone is DNSSEC-signed.** The
draft is explicit that a visitor *"MUST NOT act on unsigned or invalidly signed discovery
data"*, so "records present, zone unsigned" is a finding, not a pass. No other checker says
this.

**HTTP.** Follow the signpost to the A2A agent card, then check what presence cannot:

| check | what it catches |
|---|---|
| the signed envelope verifies under the DID the card names | a card whose bytes were altered, or whose key is not the one signing |
| the DID is bound to **this** origin | a valid card **copied here from another site** — it still verifies, and it still names the other site |
| the envelope is fresh (≤ 6h) | a static file somebody pasted months ago, rather than a live service re-signing on a timer |

**Behaviour.** When we knock, does the **door** answer, or does something in front of it?
A proxy can return bytes byte-identical to the door's own refusal, so a checker that reports
"the door declined" may have certified a door it never reached. This reports `unknown` and
says why, rather than guessing.

Everything else — llms.txt, robots rules, sitemap, MCP server card, agent-skills index, API
catalog, Web Bot Auth directory, markdown negotiation, `Permissions-Policy: tools` — is
reported as a **fact**, with the URL fetched and the status returned. None of it is graded.

## No score

Not a `/100`, not a letter, not a star, not the word "safe". A single number hides whose
rubric produced it, and there is no arguing with a number. `assertNoScore` in
`src/report.mjs` is pointed at both the JSON and the rendered page by the test suite, so
one cannot grow back by accident.

## Every finding is actionable, and cites its source

A finding a reader cannot act on is trivia. Each one carries links to the normative text it
was measured against — RFC 9727 for the API catalog, RFC 9264 for the linkset it is written
in, RFC 9460 and the DNS-AID draft for the SVCB records, RFC 9421 for message signatures,
and so on — and a prompt written to be handed straight to whoever works on that site.

**Every generated prompt says to publish only what is already true.** That constraint is
tested, on every entry, and it is the point rather than a disclaimer: this whole category
scores sites on self-declaration, which rewards exactly one behaviour — writing a manifest
claiming a capability nobody implemented — and a remediation prompt is the most efficient
possible way to industrialise it. Several entries say in as many words which file must NOT be
created if the underlying thing does not exist.

Findings are split by what they are. Something **broken** (a signature that does not verify, a
card copied from another origin, records in an unsigned zone) is listed first, as a defect.
Something **absent** is offered as "if you want this, here is how" — publishing no agent card
is not a fault, and a checker that words it as one is grading a whole category by its own
yardstick.

## For agents

The endpoint is the whole configuration:

```
https://check.muretai.com/mcp
```

Streamable HTTP, no key, no session. Most clients take a JSON config:

```json
{
  "mcpServers": {
    "agent-site-checker": {
      "type": "http",
      "url": "https://check.muretai.com/mcp"
    }
  }
}
```

A client with no HTTP transport can reach it through a local bridge
(`npx -y mcp-remote https://check.muretai.com/mcp`), and clients with their own CLI installer
take the URL directly. Two read-only tools:

- **`check_site(url)`** — the whole chain, written for the moment you were handed a URL:
  which interfaces exist, the endpoint for each, whether the identity is verified, and what
  to call next.
- **`verify_agent_card(url)`** — the narrow check: does the signature verify, is the key
  bound to this origin, how long ago was it signed.

Both generations of the protocol are served on the one endpoint — the `initialize`
handshake and the self-describing `2026-07-28` revision (`server/discover`, per-request
`_meta`, `resultType`, `-32022`) — so a client of either era connects with no configuration
of its own. Discovery document at `/.well-known/mcp.json`.

`check_site` returns the remedies above in `structuredContent.remedies`, each with its
specification links and its prompt. The caller of this tool is usually the agent that would
do the fixing.

## For a site owner

The hosted service refuses private addresses — it is a public endpoint that fetches URLs
strangers choose. So the check you most want, your own deployment before it is public, runs
on your machine:

```
npx @muretai/agent-site-checker --allow-private http://127.0.0.1:8788
```

Exit status is 0 unless a hard check FAILED. Advisories never fail a run: publishing no
agent card is not a fault, and a checker that says otherwise is grading a whole category
against one yardstick.

**Do not verify a live deployment with `curl` instead.** It sends its own user agent and
sails through a CDN bot check that would refuse a real agent. A green `curl` tells you
nothing about whether agents can reach you — that failure mode once cost three days on a
production site.

## How it works

The verification is the published [`@muretai/agent-entry`](https://www.npmjs.com/package/@muretai/agent-entry)
library — the same code that builds the doors it checks, so the checker and the thing
checked cannot drift apart. Everything else is the standard library and `fetch`.

```
src/guard.mjs    the URL guard and the bounded fetch — the only code that opens a
                 connection to an address a stranger chose. Read this one first.
src/dns.mjs      DNS-AID over DoH, and the DNSSEC state that decides whether it means
                 anything.
src/engine.mjs   the check itself.
src/report.mjs   PASS / FAIL / WARN / INFO, and no way to produce a score.
src/remedies.mjs what to do about a finding, where the rule is written down, and the
                 constraint that keeps a remediation prompt from manufacturing lies.
src/mcp.mjs      one stateless endpoint, two generations of MCP client.
src/worker.mjs   the edge entry point: page, JSON API, MCP, discovery document.
src/page.mjs     the human surface.
```

`npm test` runs the acceptance suite. Every assertion is made on what a caller can observe,
and every verification claim is paired with a **producer mutation** — the fixture's signature
is removed, corrupted, aged, or signed for the wrong origin, one lever at a time, and the
intended check must go red and no other. A check that stays green with its producer dead is
not testing the producer.

MIT.
