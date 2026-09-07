/**
 * src/page.mjs — the human surface.
 *
 * WHY THE RESULTS RENDER ON THE PAGE. Most of this category delivers findings by email, which
 * is lead capture wearing a report's clothes. The brand rule here is the opposite — proof is
 * the page — so the whole result is visible to anyone who pastes a URL, with no address asked
 * for and nothing withheld behind a paid tier.
 *
 * WHY THERE IS NO NUMBER ANYWHERE. A single score cannot be argued with, only obeyed, and it
 * hides which rubric produced it. Every line here names the URL that was fetched and what came
 * back, so a reader who disagrees can go and look. `assertNoScore` in report.mjs is pointed at
 * this file's output by the test suite for exactly that reason.
 *
 * NOTE FOR EDITORS: the CSS below lives inside a JavaScript template literal, so a
 * BACKTICK IN A CSS COMMENT ends the string and the module stops parsing. Quote CSS
 * identifiers in comments with plain words, never with backticks. (Caught twice by
 * npm test, which imports this module — that is the only thing standing between the
 * habit and a broken deploy.)
 *
 * The theme block is the canonical muretai paper palette, inlined verbatim
 * (.claude/skills/muretai-page/assets/theme.css). Public pages are single-file HTML: no
 * framework, no build step, no external stylesheet — which is also what keeps the CSP tight.
 */

const THEME_CSS = `/* muretai public "paper" theme — the canonical token block + base + components.
 * Lifted verbatim from web/index.html (the muretai.com front page), which carries
 * the owner ruling: "Paper palette — the art-light direction (owner, 2026-07-15):
 * warm cream paper, deep-indigo ink (the birds), amber deepened for light-ground
 * contrast."
 *
 * Paste into a page's inline <style>. Public pages are single-file static HTML —
 * no framework, no build step, no external stylesheet.
 * Do NOT rename tokens. Do NOT add a dark scheme (public pages are light-only).
 */

:root {
  --bg:#f6f1e4; --bg2:#fbf7ec; --ink:#1d2547; --muted:#5d6488;
  --line:#e2d9c4; --panel2:#f0e9d8; --accent:#0f8a63; --teal:#177f76;
  --good:#1e7d57; --warn:#a86e12; --bad:#b04a5e;
  /* the PAGE spacing scale (8px base). Not the dashboard's 4px --sN scale. */
  --s1:8px; --s2:16px; --s3:24px; --s4:32px; --s5:40px; --s6:48px; --s7:64px; --s8:96px;
  --measure:34em;                        /* reading width for prose blocks */
  --col:min(520px, 100% - var(--s4));    /* single-column form width */
  --page:1080px;                         /* desktop container cap */
  --shadow:0 1px 2px rgba(63,52,24,.08), 0 14px 34px rgba(63,52,24,.10);
  --shadow-hi:0 2px 6px rgba(63,52,24,.10), 0 22px 50px rgba(63,52,24,.16);
  --radius:16px;
  --serif:ui-serif,"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
}

* { box-sizing:border-box; }
html { scroll-behavior:smooth; background:var(--bg); }
html, body { margin:0; min-height:100%; overflow-x:hidden; overflow-x:clip; }
body {
  /* the ground is not flat: a warm dome + an emerald bloom over the cream */
  background:
    radial-gradient(1100px 620px at 50% -10%, #efe7d2 0%, rgba(246,241,228,0) 60%),
    radial-gradient(900px 700px at 84% 8%, rgba(15,138,99,.07) 0%, rgba(246,241,228,0) 55%),
    var(--bg);
  color:var(--ink); min-height:100dvh;
  font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;
}
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }
:where(a, button, input, summary, [role="tab"]):focus-visible {
  outline:2px solid var(--accent); outline-offset:2px; border-radius:8px;
}
@media (prefers-reduced-motion: reduce) { html { scroll-behavior:auto; } }

/* ---------------------------------------------------------------- layout */
.wrap   { width:100%; max-width:var(--page); margin:0 auto; padding:0 var(--s3); }
.column { width:100%; max-width:var(--col); margin-inline:auto; }
section.band { padding:var(--s7) 0 0; scroll-margin-top:72px; }

/* ------------------------------------------------------------ typography */
h1, h2, h3 { text-wrap:balance; }
.hero h1 {
  font-size:clamp(40px,10vw,56px); font-weight:800; letter-spacing:-1px;
  line-height:1.0; margin:0;
}
.tag {                                   /* the brand line under an H1 — SERIF */
  font-family:var(--serif); font-weight:500;
  font-size:clamp(21px,4.6vw,28px); letter-spacing:-.3px;
  margin:var(--s2) 0 0; text-wrap:balance;
}
.lede {
  color:var(--muted); font-size:16px; line-height:1.55;
  margin:var(--s2) auto 0; max-width:var(--measure); text-wrap:balance;
}
.sec-head .eyebrow {
  font-size:12px; text-transform:uppercase; letter-spacing:.14em;
  color:var(--accent); font-weight:700; margin:0 0 var(--s1);
}
.sec-head h2 {                           /* section heads are the brand voice */
  font-family:var(--serif); font-weight:500; letter-spacing:-.4px;
  font-size:clamp(24px,4.6vw,32px); line-height:1.12; margin:0;
}
.sec-head .sub {
  color:var(--muted); font-size:15px; line-height:1.55;
  margin:var(--s2) auto 0; max-width:var(--measure); text-wrap:balance;
}
.hint { color:var(--muted); font-size:12.5px; line-height:1.55; }

/* ------------------------------------------------------------ components */
.card, .panel {
  background:var(--bg2); border:1px solid var(--line); border-radius:var(--radius);
  padding:var(--s3); box-shadow:var(--shadow);
}
.card { display:flex; flex-direction:column; align-items:flex-start; gap:var(--s1); }
.card h3 { font-size:16px; font-weight:700; letter-spacing:-.2px; margin:0; }
.card p  { font-size:14px; line-height:1.55; color:var(--muted); margin:0;
           text-wrap:pretty; }

.btn {
  font:inherit; font-weight:700; text-decoration:none; border-radius:999px;
  padding:13px 24px; color:#fdf8ee; background:var(--accent); display:inline-block;
}
.btn:hover { text-decoration:none; }
.btn:active { transform:translateY(1px); }
.btn.ghost { background:transparent; border:1px solid var(--accent);
             color:var(--accent); font-weight:600; }

button {
  font:inherit; border:0; border-radius:12px; padding:13px 16px; font-weight:700;
  color:#fdf8ee; background:var(--accent); cursor:pointer;
}
button.ghost { background:var(--panel2); border:1px solid var(--line);
               color:var(--ink); font-weight:600; }

input, textarea {
  font:inherit; color:var(--ink); background:var(--panel2);
  border:1px solid var(--line); border-radius:12px; padding:13px; width:100%;
}
input::placeholder, textarea::placeholder { color:#a49a80; }

/* the status vocabulary: signed · vouched · held · revoked */
.chip {
  display:inline-flex; align-items:center; gap:6px; font:12px/1 var(--mono);
  color:var(--muted); border:1px solid var(--line); border-radius:999px;
  padding:5px 10px;
}
.chip::before { content:""; width:7px; height:7px; border-radius:50%;
                background:var(--muted); }
.chip.good::before { background:var(--good); }
.chip.warn::before { background:var(--warn); }
.chip.bad::before  { background:var(--bad); }
.chip.dim::before  { background:var(--line); }

.cmd code {
  display:block; font:13px/1.5 var(--mono); color:var(--ink);
  background:var(--panel2); border:1px solid var(--line); border-radius:12px;
  padding:13px var(--s2); overflow-x:auto; user-select:all;
}
pre {
  font:13px/1.5 var(--mono); color:var(--ink); background:var(--panel2);
  border:1px solid var(--line); border-radius:12px; padding:13px var(--s2);
  overflow-x:auto; margin:0;
}
code { font:12.5px/1.4 var(--mono); background:var(--panel2);
       border:1px solid var(--line); border-radius:6px; padding:1px 5px; }
pre code, .cmd code { border:0; padding:0; background:none; }

table { width:100%; border-collapse:collapse; font-size:13px; }
th { color:var(--muted); font-weight:600; text-align:left; padding:var(--s1);
     border-bottom:1px solid var(--line); }
td { padding:10px var(--s1); border-bottom:1px solid var(--line);
     font-variant-numeric:tabular-nums; }
tr.row:hover { background:var(--panel2); }

details {
  background:var(--bg2); border:1px solid var(--line); border-radius:12px;
  padding:var(--s2); margin:var(--s1) 0;
}
summary { cursor:pointer; font-weight:600; list-style:none; }
summary::-webkit-details-marker { display:none; }
summary::after { content:" +"; color:var(--accent); font-weight:700; }
details[open] summary::after { content:" –"; }

footer {
  margin-top:var(--s7); padding:var(--s4) 0; border-top:1px solid var(--line);
  color:var(--muted); font-size:13px;
}
footer h4 { font-size:12px; text-transform:uppercase; letter-spacing:.12em;
            color:var(--ink); margin:0 0 var(--s1); }

/* the 群れたい motif — the only non-ASCII copy allowed */
.jp { font-family:ui-serif,"Hiragino Mincho ProN","Yu Mincho",serif; }`;

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

export function renderPage(prefill = '') {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f1e4">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="muretai">

<title>muretai — Agent Site Checker</title>
<meta name="description" content="Paste a website. See what it offers an AI agent, and which parts are actually verified: the signature on its agent card, the key's claim on the origin, how recently it was signed, and whether its discovery records are in a signed DNS zone.">
<meta name="robots" content="index,follow">
<link rel="canonical" href="https://check.muretai.com/">

<link rel="icon" href="https://muretai.com/favicon.ico" sizes="32x32">
<link rel="icon" href="https://muretai.com/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="https://muretai.com/apple-touch-icon.png">

<meta property="og:type" content="website">
<meta property="og:site_name" content="muretai">
<meta property="og:url" content="https://check.muretai.com/">
<meta property="og:title" content="muretai — Agent Site Checker">
<meta property="og:description" content="See what a website offers an AI agent — and which parts are verified rather than merely present.">
<meta property="og:image" content="https://muretai.com/og-card.png">
<meta property="og:image:alt" content="muretai — Agent Site Checker">
<meta property="og:locale" content="en_US">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="muretai — Agent Site Checker">
<meta name="twitter:description" content="See what a website offers an AI agent — and which parts are verified rather than merely present.">
<meta name="twitter:image" content="https://muretai.com/og-card.png">

<script async src="https://www.googletagmanager.com/gtag/js?id=G-13KZ2RE7K9"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-13KZ2RE7K9');
</script>
<style>
${THEME_CSS}

/* ---- page-local: the result surface, built from the same tokens ---- */
.hero { padding:var(--s7) 0 0; text-align:center; }
form.ask { display:flex; gap:var(--s1); margin:var(--s4) auto 0; max-width:var(--col); }
form.ask input { flex:1; }
.verdict { margin-top:var(--s4); }
.verdict p { font-family:var(--serif); font-weight:500; font-size:clamp(18px,3.4vw,22px);
             line-height:1.35; margin:0; text-wrap:pretty; }
.grid { display:grid; gap:var(--s2); grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
        margin-top:var(--s3); }
.kv { display:flex; justify-content:space-between; gap:var(--s2); padding:10px 0;
      border-bottom:1px solid var(--line); font-size:14px; align-items:flex-start; }
.kv:last-child { border-bottom:0; }
/* the label column takes the slack and wraps; min-width:0 is what lets a long URL wrap
   inside a flex child instead of pushing the chip off the row. */
.kv .k { flex:1 1 auto; min-width:0; color:var(--ink); overflow-wrap:anywhere; }
/* the chip column never shrinks and never breaks: "absent" split across three lines as
   "ab / se / nt" was word-break:break-all, which is meant for DIDs, reaching the status word. */
.kv .v { flex:0 0 auto; text-align:right; font-family:var(--mono); font-size:12.5px; }
.kv .v.wrap { word-break:break-all; }
.chip { white-space:nowrap; }
/* The detail line under a label. This used to be scoped to the .rows block only, so in the fact list
   it had no styles at all — no line break, no muted colour — and every row read as
   "llms.txthttps://muretai.com/llms.txt". Define it once, for every place it is used. */
.dt { display:block; color:var(--muted); font-size:12.5px; line-height:1.45;
      margin-top:3px; font-family:inherit; overflow-wrap:anywhere; }
/* mono is for DIDs and tokens only (docs/DESIGN_SYSTEM.md), not for prose detail. */
.dt.mono { font-family:var(--mono); font-size:12px; }

/* No ligatures in anything copyable. The mono stack renders "--transport" as one long dash,
   so a reader who retypes the install line instead of copying it types an em dash and the
   command fails with an error that names neither cause. The bytes were always two hyphens;
   only the glyph lied. */
.cmd code, pre, code, .dt.mono { font-variant-ligatures:none; }

/* The canonical .sec-head centres its sub-paragraph with auto margins, which is right when the
   whole head is centred. These heads are left-aligned, so the auto margins put the sentence in
   the middle of the page under a flush-left heading. Align it with its own heading. */
.sec-head .sub { margin-inline:0; }

/* THE MOBILE BREAK, and it is worth naming because the cause is invisible on a laptop. The
   verdict sentence contains a did:key — 57 characters with nothing to break on. A single
   unbreakable token is wider than a phone, so it widened the whole document, and every other
   element then laid out against that width and got clipped by the body's overflow-clip: the
   headline lost its last word, the chips left the screen, the button ran past the edge. None
   of it was a flexbox problem. break-word breaks ONLY the word that cannot fit, so ordinary
   prose is untouched. */
.verdict p, .lede, .sub, .card p, .hint, p { overflow-wrap:break-word; }
/* Belt and braces: a panel in a grid must be allowed to be narrower than its own content. */
.panel, .card, .grid > * { min-width:0; }

/* the remediation list */
.remedy summary { display:flex; align-items:center; gap:var(--s1); flex-wrap:wrap; }
.remedy pre { margin-top:var(--s2); white-space:pre-wrap; max-height:340px; overflow:auto; }
.remedy .res { display:flex; flex-wrap:wrap; gap:var(--s1); margin-top:var(--s2); }
.remedy .res a { font:12px/1 var(--mono); border:1px solid var(--line); border-radius:999px;
                 padding:6px 10px; color:var(--accent); text-decoration:none; }
.remedy .res a:hover { background:var(--panel2); text-decoration:none; }
.remedy .act { margin-top:var(--s2); display:flex; gap:var(--s1); align-items:center; }
.remedy button { padding:9px 14px; font-size:13px; }
.rows { margin-top:var(--s2); }
.rows li { list-style:none; padding:8px 0; border-bottom:1px solid var(--line);
           font-size:13.5px; display:flex; gap:var(--s1); align-items:baseline; }
.rows ul { margin:0; padding:0; }
.rows .lv { font:11px/1 var(--mono); text-transform:uppercase; letter-spacing:.08em;
            padding-top:3px; min-width:42px; }
.lv.PASS { color:var(--good); } .lv.FAIL { color:var(--bad); }
.lv.WARN { color:var(--warn); } .lv.INFO { color:var(--muted); }
.spin { color:var(--muted); font-size:14px; margin-top:var(--s3); }
@media (max-width:520px) { form.ask { flex-direction:column; } }
</style>
</head>
<body>
<main class="wrap">

  <header class="hero">
    <p class="eyebrow" style="font-size:12px;text-transform:uppercase;letter-spacing:.14em;color:var(--accent);font-weight:700;margin:0 0 var(--s1)">Agent Site Checker</p>
    <h1>Present is not the same as real.</h1>
    <p class="tag">Anyone can serve a file that says who they are. Far fewer can sign it.</p>
    <p class="lede">Paste a website. You will see what it offers an AI agent — and, for the parts
      that carry a key, whether the signature verifies, whether that key speaks for this origin
      or was copied from another one, how long ago it was signed, and whether its DNS discovery
      records sit in a signed zone. Everything else is listed as a plain fact. No number, no
      grade, no email.</p>

    <form class="ask" id="ask">
      <input id="url" name="url" type="text" inputmode="url" autocomplete="url"
             placeholder="example.com" value="${esc(prefill)}" aria-label="Website to check">
      <button type="submit">Check</button>
    </form>
    <p class="hint" style="margin-top:var(--s1)">Read-only. One knock is sent to the door a site
      itself advertises, and it is refused by design.</p>
  </header>

  <section id="out" hidden></section>

  <section class="band">
    <div class="sec-head">
      <p class="eyebrow">Why it matters</p>
      <h2>Present is cheap. Proven is what you can act on.</h2>
      <p class="sub">Not "it is safer" — that is true of everything and tells you nothing. Here
        is what actually changes.</p>
    </div>
    <div class="grid">
      <article class="card">
        <h3>A copy scores the same as the original.</h3>
        <p>An agent card is a file at a known path. Nothing stops someone serving a copy of a
          well-known company's card on a domain of their own — same name, same key, same
          everything. Every presence checker ticks both. Whether the signature holds, and
          whether the key it names speaks for the domain you are standing on, is the only thing
          that tells them apart. A checker that ticks the impostor is worse than none, because
          it was believed.</p>
      </article>
      <article class="card">
        <h3>An agent can settle it without asking you.</h3>
        <p>The reason to have agents is that they do not need supervising. If all you know is
          that a file exists, a person has to look at the site and decide whether it is really
          them — every time, before anything that costs money or sends data. Something that
          verifies is something an agent can decide by itself. That is the difference between
          an errand you delegate and one you watch.</p>
      </article>
      <article class="card">
        <h3>Fresh tells you whether anyone is home.</h3>
        <p>A card signed eight months ago and left there parses perfectly and looks completely
          fine. It means the site announced agent support once and nothing has run since — you
          would be posting into a mailbox no one empties. A live door re-signs on a timer, so
          the age of a signature separates a service from a leftover. No amount of presence
          checking gets near that.</p>
      </article>
      <article class="card">
        <h3>Afterwards, both sides can point at something.</h3>
        <p>When the exchange is signed, what was said belongs to a key rather than to an
          endpoint that answered once. If an order goes wrong there is something to show.
          Between two anonymous endpoints, nobody is holding anything.</p>
      </article>
    </div>
    <p class="hint" style="margin-top:var(--s3);max-width:var(--measure)">If you run the site,
      it reads the other way round: this is the check that makes you hard to impersonate.
      Publishing a card tells agents you exist. Signing it, from a key tied to your own domain
      and re-signed while you are still running, is what stops the next domain along from being
      you.</p>
  </section>

  <section class="band">
    <div class="sec-head">
      <p class="eyebrow">For agents</p>
      <h2>The same check, over MCP.</h2>
      <p class="sub">If you were handed a URL mid-task, you do not need this page. One endpoint,
        no key, no session, two read-only tools: <code>check_site</code> and
        <code>verify_agent_card</code>.</p>
    </div>

    <div class="cmd" style="margin-top:var(--s3)">
      <code>https://check.muretai.com/mcp</code>
    </div>
    <p class="hint" style="margin-top:var(--s1)">Streamable HTTP. Both generations of the
      protocol are served on that one address — the <code>initialize</code> handshake and the
      self-describing 2026-07-28 revision — so a client of either era connects with no
      configuration of its own. Discovery document:
      <a href="/.well-known/mcp.json">/.well-known/mcp.json</a>.</p>

    <details>
      <summary>For a client that reads a JSON config</summary>
      <pre style="margin-top:var(--s2)"><code>{
  "mcpServers": {
    "agent-site-checker": {
      "type": "http",
      "url": "https://check.muretai.com/mcp"
    }
  }
}</code></pre>
      <p class="hint" style="margin-top:var(--s1)">The shape most desktop and editor clients
        accept. Some spell the field <code>"transport"</code> rather than <code>"type"</code>,
        and a few take the URL on its own — check your client's own documentation for the key
        name; the address is the same either way.</p>
    </details>

    <details>
      <summary>For a client that speaks stdio only</summary>
      <pre style="margin-top:var(--s2)"><code>{
  "mcpServers": {
    "agent-site-checker": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://check.muretai.com/mcp"]
    }
  }
}</code></pre>
      <p class="hint" style="margin-top:var(--s1)">Clients that predate the HTTP transport can
        reach a remote server through a local bridge. Nothing is installed permanently and no
        credential is involved.</p>
    </details>

    <details>
      <summary>From a command line</summary>
      <pre style="margin-top:var(--s2)"><code>claude mcp add --transport http agent-site-checker https://check.muretai.com/mcp</code></pre>
      <p class="hint" style="margin-top:var(--s1)">One example, not a requirement. Any client
        that accepts a remote MCP URL accepts the address above directly.</p>
    </details>

    <p class="hint" style="margin-top:var(--s2)">Prefer plain HTTP? One URL, one JSON document:
      <a href="/api/check?url=muretai.com">/api/check?url=…</a></p>
  </section>

  <section class="band">
    <div class="sec-head">
      <p class="eyebrow">What this is not</p>
      <h2>It does not count your surfaces.</h2>
      <p class="sub">Several tools already scan a site for the two dozen agent-facing standards
        and rate how many are present — Cloudflare's
        <a href="https://isitagentready.com/" rel="noopener">isitagentready.com</a> is the
        thorough one, and it is free. Use it for that. This checker asks the question those
        leave open: of the things that are present, which ones can be proven?</p>
    </div>
    <div class="grid">
      <article class="card">
        <span class="chip good">signature</span>
        <h3>The card is signed, and it verifies.</h3>
        <p>An agent card is a JSON file at a well-known path — anyone can serve one naming any
          key. The signed envelope beside it either checks out under that key or it does not.</p>
      </article>
      <article class="card">
        <span class="chip good">origin</span>
        <h3>The key speaks for this site.</h3>
        <p>A card copied from another website still carries a perfectly valid signature. What
          gives it away is the endpoint inside it, pointing somewhere else.</p>
      </article>
      <article class="card">
        <span class="chip warn">freshness</span>
        <h3>Something is alive behind it.</h3>
        <p>A live door re-signs its card on a timer. One signed months ago and left there is a
          file, not a service, and a visitor is entitled to refuse it.</p>
      </article>
      <article class="card">
        <span class="chip warn">dns</span>
        <h3>The DNS records are in a signed zone.</h3>
        <p>DNS-AID publishes agent endpoints as SVCB records. Its own draft says a visitor must
          not act on them unless the zone is DNSSEC-signed — so we report both.</p>
      </article>
      <article class="card">
        <span class="chip dim">who answered</span>
        <h3>The door replied — not the edge.</h3>
        <p>A proxy in front of a door can return bytes identical to the door's own refusal. When
          we cannot tell which one spoke, we say so instead of guessing.</p>
      </article>
      <article class="card">
        <span class="chip good">terms</span>
        <h3>The door says its terms before you knock.</h3>
        <p>A guardrail is what a server does, not what a policy file says. So we read the terms
          the card states — recipient, signed fields, canonicalization — and whether the door's
          refusal repeats them, so a stranger can knock correctly on the second try. The rate
          ceiling is reported as not measured: proving it would mean flooding someone's door.</p>
      </article>
      <article class="card">
        <span class="chip dim">no score</span>
        <h3>Every line names its URL.</h3>
        <p>You get what was fetched and what came back. A single number would hide whose rubric
          produced it, and there is no arguing with a number.</p>
      </article>
    </div>
  </section>

  <footer>
    <div class="grid">
      <div>
        <h4>muretai</h4>
        <p style="margin:0">A network where an agent has its own address, gets introduced, and
          knows who it is talking to. <a href="https://muretai.com/">muretai.com</a></p>
      </div>
      <div>
        <h4>Open</h4>
        <p style="margin:0">The checks run on the wire layer every door carries —
          <code>agent-wire</code>, vendored here byte for byte. Same bytes, same answers.</p>
      </div>
      <div>
        <h4>Contact</h4>
        <p style="margin:0">muretaicom@gmail.com</p>
      </div>
    </div>
    <p style="margin-top:var(--s3)" class="jp">群れたい</p>
  </footer>
</main>

<script>
const out = document.getElementById('out');
const form = document.getElementById('ask');
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const CHIP = { verified:'good', proven:'good', fresh:'good', signed:'good',
               'door-answered':'good', stated:'good', teaches:'good', resolves:'good',
               invalid:'bad', mismatch:'bad', stale:'warn', bogus:'bad', drifted:'bad', dangling:'bad',
               absent:'warn', unproven:'warn', unsigned:'warn', incomplete:'warn', unknown:'dim',
               partial:'warn', silent:'warn', other:'dim', 'accepted-unsigned':'dim',
               'not-probed':'dim', 'not-measured':'dim', 'n/a':'dim' };

function kv(k, state, detail, mono) {
  const chip = CHIP[state] || 'dim';
  return '<div class="kv"><span class="k">' + esc(k) +
    (detail ? '<span class="dt' + (mono ? ' mono' : '') + '">' + esc(detail) + '</span>' : '') + '</span>' +
    '<span class="v"><span class="chip ' + chip + '">' + esc(state) + '</span></span></div>';
}

function render(r) {
  if (r.refused) {
    return '<div class="panel"><p>' + esc(r.refused) + '</p></div>';
  }
  const v = r.verification || {};
  let h = '<div class="verdict panel"><p>' + esc(r.verdict) + '</p>' +
    '<p class="hint" style="margin-top:var(--s2)">' + esc(r.target.finalUrl || r.target.url) +
    ' · checked ' + esc(r.checker.checkedAt) + ' · ' + esc(r.checker.name) + ' ' +
    esc(r.checker.version) + '</p></div>';

  if (r.reachable) {
    h += '<div class="grid"><div class="panel">' +
      '<h3 style="margin:0 0 var(--s1);font-size:16px">Verified, or not</h3>';
    if (v.card && v.card.present) {
      h += kv('agent card', 'present', v.card.did || '', true);
      h += kv('signature', (v.signature||{}).state, (v.signature||{}).detail);
      h += kv('origin binding', (v.originBinding||{}).state, (v.originBinding||{}).detail);
      h += kv('freshness', (v.freshness||{}).state, (v.freshness||{}).detail);
      if (v.door && v.door.advertised) h += kv('who answered', v.door.reached, v.door.detail);
      if (v.terms && v.terms.state !== 'n/a') {
        h += kv('terms before the knock', v.terms.state, v.terms.detail);
        if (v.howTo && v.howTo.url) h += kv('how-to link', v.howTo.state, v.howTo.detail);
        h += kv('the refusal teaches', (v.refusal||{}).state, (v.refusal||{}).detail);
        h += kv('rate ceiling', (v.limits||{}).state, (v.limits||{}).detail);
      }
    } else {
      h += '<p class="hint">No A2A agent card at the well-known path, so there is nothing here '
         + 'to verify. That is a fact about this site, not a fault.</p>';
    }
    const d = r.dnsAid || {};
    h += kv('DNS zone', (d.dnssec||{}).state, (d.dnssec||{}).detail);
    h += kv('DNS-AID records', d.found ? 'present' : 'absent',
            d.found ? d.records.map(x => x.label + ' -> ' + x.target).join(', ')
                    : 'nothing under _agents.' + (d.domain || ''));
    h += '</div>';

    h += '<div class="panel"><h3 style="margin:0 0 var(--s1);font-size:16px">Also published</h3>' +
      '<p class="hint" style="margin:0 0 var(--s1)">Reported as facts. Not graded, not counted.</p>';
    for (const f of (r.facts || [])) {
      h += '<div class="kv"><span class="k">' + esc(f.surface) +
        '<span class="dt">' + esc(f.detail || f.url) + '</span></span>' +
        '<span class="v"><span class="chip ' +
        (f.present === null ? 'dim' : f.present ? 'good' : 'dim') + '">' +
        (f.present === null ? 'not established' : f.present ? 'present' : 'absent') +
        '</span></span></div>';
    }
    h += '</div></div>';

    h += '<details style="margin-top:var(--s3)"><summary>Every check, in order</summary>' +
      '<div class="rows"><ul>';
    for (const row of (r.rows || [])) {
      h += '<li><span class="lv ' + esc(row.level) + '">' + esc(row.level) + '</span>' +
        '<span>' + esc(row.label) +
        (row.detail ? '<span class="dt">' + esc(row.detail) + '</span>' : '') + '</span></li>';
    }
    h += '</ul></div></details>';
  }
  h += renderRemedies(r);
  return h;
}

function renderRemedies(r) {
  const list = r.remedies || [];
  if (!list.length) return '';
  const groups = [
    ['fix', 'Broken, and worth fixing',
     'Something here is published and does not hold up. These are the ones with a reader on the '
     + 'other end who will be turned away.'],
    ['add', 'Not published',
     'Absence is not a fault — a site that publishes no agent card has done nothing wrong. These '
     + 'are offered as "if you want this, here is how", and every prompt says to publish only '
     + 'what is already true.'],
  ];
  let h = '';
  for (const [kind, title, sub] of groups) {
    const items = list.filter((x) => x.kind === kind);
    if (!items.length) continue;
    h += '<section class="band"><div class="sec-head">' +
      '<p class="eyebrow">' + (kind === 'fix' ? 'To fix' : 'To publish') + '</p>' +
      '<h2>' + esc(title) + '</h2><p class="sub">' + esc(sub) + '</p></div>';
    for (const it of items) {
      const idx = list.indexOf(it);
      h += '<details class="remedy"><summary>' +
        '<span class="chip ' + (kind === 'fix' ? 'warn' : 'dim') + '">' + esc(it.id) + '</span>' +
        '<span>' + esc(it.title) + '</span></summary>' +
        '<div class="res">' +
        it.resources.map((rs) => '<a href="' + esc(rs.url) + '" rel="noopener" target="_blank">' +
          esc(rs.label) + '</a>').join('') +
        '</div>' +
        '<pre id="p' + idx + '">' + esc(it.prompt) + '</pre>' +
        '<div class="act"><button type="button" class="copy" data-target="p' + idx + '">' +
        'Copy prompt</button><span class="hint">Paste it to whichever agent works on that site.' +
        '</span></div></details>';
    }
    h += '</section>';
  }
  return h;
}

async function run(target) {
  out.hidden = false;
  out.innerHTML = '<p class="spin">Fetching ' + esc(target) +
    ' and checking what it publishes…</p>';
  try {
    const res = await fetch('/api/check?url=' + encodeURIComponent(target));
    const data = await res.json();
    out.innerHTML = render(data);
  } catch (e) {
    out.innerHTML = '<div class="panel"><p>The check could not complete: ' +
      esc(e.message) + '</p></div>';
  }
}

out.addEventListener('click', async (e) => {
  const btn = e.target.closest('.copy');
  if (!btn) return;
  const pre = document.getElementById(btn.dataset.target);
  if (!pre) return;
  try {
    await navigator.clipboard.writeText(pre.textContent);
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = 'Copy prompt'; }, 1600);
  } catch {
    // Clipboard access can be refused, and a button that silently does nothing is worse than
    // no button: select the text so the reader can copy it the ordinary way.
    const sel = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(pre);
    sel.removeAllRanges();
    sel.addRange(range);
    btn.textContent = 'Selected — press copy';
    setTimeout(() => { btn.textContent = 'Copy prompt'; }, 2400);
  }
});

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const t = document.getElementById('url').value.trim();
  if (!t) return;
  history.replaceState(null, '', '/?url=' + encodeURIComponent(t));
  run(t);
});

const pre = new URLSearchParams(location.search).get('url');
if (pre) run(pre);
</script>
</body>
</html>`;
}
