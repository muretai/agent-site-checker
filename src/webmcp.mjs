/**
 * src/webmcp.mjs — CLI-side WebMCP read of a fetched document.
 *
 * No browser is launched here. The Worker must never grow a hosted browser farm, and
 * Playwright does not belong in this package. Tools are enumerated FROM the document that
 * arrived over the network: the HTML, the Permissions-Policy header, and the final URL
 * after redirects. A live getTools() pass needs Chrome with #enable-webmcp-testing; this
 * run names that flag and says the browser was not launched.
 *
 * W2–W7 are producer-mutation checks. Absence of WebMCP is not a fault: the checks fire
 * only when the page claims the surface.
 */

import corpusJson from './webmcp-corpus.json' with { type: 'json' };

export const WEBMCP_FLAG = '#enable-webmcp-testing';
export const NAME_BUDGET = 30;
export const DESC_BUDGET = 500;

/** Published size of the independently verified public corpus. Do not invent entries. */
export const CORPUS = Object.freeze({
  asOf: corpusJson.asOf,
  count: corpusJson.sites.length,
  headline: String(corpusJson.sites.length),
  sites: Object.freeze(corpusJson.sites.slice()),
  note: corpusJson.note,
});

export function runtimeBuild() {
  if (globalThis.process?.versions?.node) return `Node ${process.version}`;
  return 'Cloudflare Worker';
}

function parseAttrs(raw) {
  const attrs = {};
  const re = /([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let m;
  while ((m = re.exec(raw))) {
    attrs[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return attrs;
}

function extractTags(html, name) {
  const out = [];
  const re = new RegExp(`<${name}\\b([^>]*)>`, 'gi');
  let m;
  while ((m = re.exec(html))) out.push({ attrs: parseAttrs(m[1] || '') });
  return out;
}

function takeBalanced(src, start) {
  if (src[start] !== '{') return null;
  let depth = 0, inStr = null, esc = false;
  for (let i = start; i < src.length; i++) {
    const c = src[i];
    if (inStr) {
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  return null;
}

function tryParseObject(raw) {
  try { return JSON.parse(raw); } catch { /* JS literals are not always JSON */ }
  try {
    const quoted = raw.replace(/([,{]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:/g, '$1"$2":');
    return JSON.parse(quoted);
  } catch { return { __unparsed: true }; }
}

function extractInputSchemas(html) {
  const out = [];
  const re = /inputSchema\s*:\s*/g;
  let m;
  while ((m = re.exec(html))) {
    const after = html.slice(m.index + m[0].length).trimStart();
    const abs = m.index + m[0].length + (html.slice(m.index + m[0].length).length - after.length);
    if (after.startsWith('null')) { out.push(null); continue; }
    if (after[0] !== '{') { out.push({ __unparsed: true }); continue; }
    const raw = takeBalanced(html, abs);
    out.push(raw ? tryParseObject(raw) : { __unparsed: true });
  }
  return out;
}

function stringProp(html, prop) {
  const found = [];
  const re = new RegExp(`${prop}\\s*:\\s*(['"])([\\s\\S]*?)\\1`, 'g');
  let m;
  while ((m = re.exec(html))) found.push(m[2]);
  return found;
}

export function validInputSchema(schema) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema) || schema.__unparsed) {
    return false;
  }
  if (schema.type !== 'object') return false;
  if (schema.properties != null
      && (typeof schema.properties !== 'object' || Array.isArray(schema.properties))) {
    return false;
  }
  return true;
}

/**
 * Read one fetched document. `html` is the body that arrived; `finalUrl` is where the
 * redirects ended. Nothing here opens a second connection.
 */
export function analyzeWebmcp(html, {
  finalUrl = '',
  toolsHeader = false,
} = {}) {
  const text = String(html || '');
  let pageOrigin = null;
  let https = false;
  try {
    const u = new URL(finalUrl);
    pageOrigin = u.origin;
    https = u.protocol === 'https:';
  } catch { /* an unparseable final URL is not HTTPS */ }

  const hasDocument = /document\.modelContext/.test(text);
  const hasNavigator = /navigator\.modelContext/.test(text);
  const hasProvide = /\.provideContext\s*\(/.test(text);
  const hasRegister = /registerTool\s*\(/.test(text);
  const hasExposedTo = /exposedTo\s*:/.test(text);

  const iframes = extractTags(text, 'iframe');
  const forms = extractTags(text, 'form');
  const declarativeForms = forms.filter((f) => 'toolname' in f.attrs);

  const schemas = extractInputSchemas(text);
  const names = stringProp(text, 'name');
  const descriptions = stringProp(text, 'description');
  for (const f of declarativeForms) {
    if (f.attrs.toolname) names.push(f.attrs.toolname);
    if (f.attrs.tooldescription) descriptions.push(f.attrs.tooldescription);
  }

  const claimed = !!(toolsHeader || hasDocument || hasNavigator || hasRegister
    || hasProvide || declarativeForms.length);

  const xoIframes = iframes.filter((f) => {
    if (!f.attrs.src || !pageOrigin || !finalUrl) return false;
    try { return new URL(f.attrs.src, finalUrl).origin !== pageOrigin; } catch { return false; }
  });

  const checks = {};
  if (claimed) {
    checks.W2 = https ? 'pass' : 'fail';
    checks.W3 = toolsHeader ? 'pass' : 'fail';
    checks.W4 = xoIframes.length
      ? (xoIframes.every((f) => /(^|[;\s])tools($|[;\s=])/i.test(f.attrs.allow || '')) ? 'pass' : 'fail')
      : 'na';
    checks.W5 = hasRegister ? (hasExposedTo ? 'pass' : 'fail') : 'na';
    checks.W6 = schemas.length ? (schemas.every(validInputSchema) ? 'pass' : 'fail') : 'na';
    const mutating = declarativeForms.filter((f) => /^post$/i.test(f.attrs.method || ''));
    checks.W7 = mutating.length
      ? (mutating.every((f) => !('toolautosubmit' in f.attrs)) ? 'pass' : 'fail')
      : 'na';
  }

  const failed = Object.entries(checks).filter(([, s]) => s === 'fail').map(([id]) => id);

  const hasImp = hasRegister || schemas.length > 0;
  const hasDec = declarativeForms.length > 0;
  const inputSchemaForm = hasImp && hasDec ? 'both'
    : hasImp ? 'imperative'
      : hasDec ? 'declarative'
        : null;

  let getter = null;
  if (hasDocument) getter = 'document.modelContext';
  else if (hasNavigator) getter = 'navigator.modelContext';

  const tools = [];
  const n = Math.max(names.length, descriptions.length);
  for (let i = 0; i < n; i++) {
    tools.push({
      name: names[i] || null,
      description: descriptions[i] || null,
      nameChars: names[i] ? names[i].length : 0,
      descriptionChars: descriptions[i] ? descriptions[i].length : 0,
    });
  }

  return {
    claimed,
    examined: true,
    toolsHeader: !!toolsHeader,
    https,
    getter,
    navigatorOnly: !!(hasNavigator && !hasDocument),
    provideContext: hasProvide,
    exposedTo: hasExposedTo,
    inputSchemaForm,
    inputSchemas: schemas,
    checks,
    failed,
    tools,
    browser: {
      build: `not launched (${runtimeBuild()} read the document)`,
      flag: WEBMCP_FLAG,
    },
    enumeratedFrom: pageOrigin,
    finalUrl: finalUrl || null,
    corpus: { count: CORPUS.count, headline: CORPUS.headline, sites: CORPUS.sites },
  };
}

const CHECK_LABEL = {
  W2: 'W2: the page that registers tools is reached over HTTPS',
  W3: 'W3: Permissions-Policy: tools is sent',
  W4: 'W4: cross-origin iframes delegate allow="tools"',
  W5: 'W5: registerTool sets exposedTo',
  W6: 'W6: inputSchema is a JSON Schema object',
  W7: 'W7: a mutating declarative tool does not set toolautosubmit',
};

const CHECK_DETAIL = {
  W2: 'Permissions-Policy: tools or a modelContext registration arrived on a non-HTTPS origin. '
    + 'WebMCP tools only exist in a secure context.',
  W3: 'the page registers WebMCP tools but sent no Permissions-Policy: tools header',
  W4: 'a cross-origin iframe is present without allow="tools", so tools in that frame are gated off',
  W5: 'registerTool was called without exposedTo, so no cross-origin agent can be shown the tool',
  W6: 'an inputSchema was published that is not a JSON Schema object',
  W7: 'a POST declarative tool has toolautosubmit, so an agent can submit a state change unattended',
};

/**
 * Apply W2–W7, the navigator.modelContext warning, provideContext(), and the character
 * budgets to an existing Report. Budgets never fail a run.
 */
export function applyWebmcpChecks(rep, w) {
  if (!w?.claimed) return;
  for (const id of ['W2', 'W3', 'W4', 'W5', 'W6', 'W7']) {
    const state = w.checks[id];
    if (state === 'na' || state == null) continue;
    rep.check(state === 'pass', CHECK_LABEL[id], state === 'pass' ? '' : CHECK_DETAIL[id]);
  }
  if (w.navigatorOnly) {
    rep.warn(false, 'navigator.modelContext is the old getter',
      'this page registers on navigator.modelContext; the getter moved to document.modelContext '
      + '(webmcp#184).');
  }
  if (w.provideContext) {
    rep.check(false, 'provideContext() is REMOVED from the WebMCP specification',
      'provideContext() was REMOVED from the spec (webmcp#132), not merely deprecated. '
      + 'Register tools with document.modelContext.registerTool.');
  }
  for (const t of w.tools || []) {
    if (t.name && t.nameChars > NAME_BUDGET) {
      rep.warn(false, 'tool name stays within the 30-character budget',
        `${t.nameChars} characters (budget ${NAME_BUDGET})`);
    }
    if (t.description && t.descriptionChars > DESC_BUDGET) {
      rep.warn(false, 'tool description stays within the 500-character budget',
        `${t.descriptionChars} characters (budget ${DESC_BUDGET})`);
    }
  }
}
