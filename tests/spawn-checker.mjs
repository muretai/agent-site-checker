/**
 * Spawn the shipped CLI the way a user does. Tests of T123 criteria import this
 * and fixtures only — never a detection function.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const CLI = fileURLToPath(new URL('../bin/agent-site-checker.mjs', import.meta.url));

export function runShippedChecker(origin, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      CLI, '--json', '--allow-private', '--no-dns', origin,
    ], {
      env: { ...process.env, ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('error', reject);
    child.on('close', (code) => {
      let json = null;
      try { json = JSON.parse(stdout); } catch { /* assertion will fail */ }
      resolve({ code, json, stdout, stderr });
    });
  });
}

export function checkerEnv(site) {
  return site.certPath ? { NODE_EXTRA_CA_CERTS: site.certPath } : {};
}
