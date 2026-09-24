import { readFileSync } from 'node:fs';

export function parseDotenv(text: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m || line.trimStart().startsWith('#')) continue;
    const q = /^(["'])(.*)\1$/.exec(m[2]);
    env[m[1]] = q ? q[2] : m[2];
  }
  return env;
}

/** .env values fill in only what the real environment does not set. */
export function loadEnv(file: string): Record<string, string> {
  let fromFile: Record<string, string> = {};
  try {
    fromFile = parseDotenv(readFileSync(file, 'utf8'));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  const merged: Record<string, string> = { ...fromFile };
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) merged[k] = v;
  return merged;
}

export function requireVars<K extends string>(env: Record<string, string | undefined>, keys: K[]): Record<K, string> {
  const missing = keys.filter((k) => !env[k]);
  if (missing.length) throw new Error(`Missing required variables (set them in .env): ${missing.join(', ')}`);
  return Object.fromEntries(keys.map((k) => [k, env[k]!])) as Record<K, string>;
}
