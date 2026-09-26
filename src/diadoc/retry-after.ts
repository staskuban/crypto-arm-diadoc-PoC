const FALLBACK_MS = 1000;
export const MAX_RETRY_AFTER_MS = 60_000;

/**
 * Retry-After is delay-seconds or an HTTP-date; anything unusable (or not in the future) gives
 * `fallbackMs` (1 s by default).
 */
export function retryAfterMs(
  header: string | null,
  now: number = Date.now(),
  maxMs: number = MAX_RETRY_AFTER_MS,
  fallbackMs: number = FALLBACK_MS,
): number {
  const v = header?.trim() ?? '';
  const ms = /^\d+$/.test(v) ? Number(v) * 1000 : Date.parse(v) - now;
  return Number.isFinite(ms) && ms > 0 ? Math.min(ms, maxMs) : fallbackMs;
}
