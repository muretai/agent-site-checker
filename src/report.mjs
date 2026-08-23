/**
 * src/report.mjs — PASS / FAIL / WARN / INFO, and nothing that adds up to a number.
 *
 * WHY THIS SHAPE. It is the report contract muretai's own conformance tooling has used since
 * the first Agent Entry door, reused deliberately rather than reinvented: only FAIL sets the
 * exit status, WARN is an advisory that never fails a run, INFO is context a reader needs to
 * judge the rest. The verdict a human reads and the status a CI job reads are the same object,
 * so they cannot drift apart.
 *
 * WHY THERE IS NO SCORE, AND WHY THAT IS ENFORCED HERE. A competitor's scanner rated
 * muretai.com 22/100 by aggregating checks that did not apply to it, and Cloudflare's rates
 * it 47/100 on a rubric of its own; both numbers say more about the rubric than the site.
 * Aggregating is also how a checker becomes unfalsifiable — a single number cannot be
 * argued with, only obeyed. So this module offers no way to produce one: there is no
 * `total()`, no weight, no grade, and `assertNoScore()` exists so a test can prove the
 * rendered output never grew one.
 */

export const LEVELS = ['PASS', 'FAIL', 'WARN', 'INFO'];

export class Report {
  constructor() {
    /** @type {{level:string,label:string,detail:string}[]} */
    this.rows = [];
  }

  #add(level, label, detail = '') {
    this.rows.push({ level, label, detail: detail || '' });
    return level !== 'FAIL';
  }

  /** A hard check. A false result taints the exit status. */
  check(cond, label, detail = '') {
    return this.#add(cond ? 'PASS' : 'FAIL', label, cond ? '' : detail);
  }

  /** A soft check: a false result is an advisory, never a failure. */
  warn(cond, label, detail = '') {
    return this.#add(cond ? 'PASS' : 'WARN', label, cond ? '' : detail);
  }

  /** Context. Never affects the outcome — this is where FACTS about foreign formats go. */
  info(label, detail = '') {
    this.#add('INFO', label, detail);
  }

  get failed() { return this.rows.filter((r) => r.level === 'FAIL').map((r) => r.label); }
  get warned() { return this.rows.filter((r) => r.level === 'WARN').map((r) => r.label); }
  get passed() { return this.rows.filter((r) => r.level === 'PASS').length; }

  summary() {
    return { passed: this.passed, failed: this.failed, warnings: this.warned };
  }
}

/**
 * The shapes a score takes when it sneaks back in. Used by the test that scans both the
 * JSON and the rendered page. Kept beside the Report so the ban and the contract live in
 * one file — a rule stored away from the thing it constrains is a rule that gets forgotten.
 */
export const SCORE_PATTERNS = [
  /\b\d{1,3}\s*\/\s*100\b/,                 // 47/100
  /\bscore\s*[:=]\s*\d/i,                   // score: 47
  /\bgrade\s*[:=]\s*["']?[A-F][+-]?\b/i,    // grade: B+
  /\b[0-5](\.\d)?\s*(\/|out of)\s*5\b/i,    // 4/5 stars
  /\blevel\s+\d\b/i,                        // Level 2
  /\b(is|looks|rated)\s+safe\b/i,           // "this tool is safe"
];

/** Throw if `text` contains anything that reads as an aggregate score or a safety grade. */
export function assertNoScore(text, where = 'output') {
  for (const re of SCORE_PATTERNS) {
    const m = re.exec(text);
    if (m) throw new Error(`${where} contains a score-like string: ${JSON.stringify(m[0])}`);
  }
}
