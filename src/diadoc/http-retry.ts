// One bounded retry loop for every Diadoc API and IdP request: 429/503 honour Retry-After, other
// transient failures back off exponentially. The caller repeats the identical request.
import { retryAfterMs } from './retry-after.js';

export interface RetryPolicy {
  /** Attempts including the first one. */
  maxAttempts: number;
  /** First pause without Retry-After; doubles on each retry up to `maxDelayMs`. */
  baseDelayMs: number;
  maxDelayMs: number;
  /**
   * Total pause per call. A Retry-After longer than what is left ends the retries instead of being
   * shortened: asking earlier than the server said is pointless.
   */
  budgetMs: number;
}

export const DEFAULT_RETRY_POLICY: Readonly<RetryPolicy> = {
  maxAttempts: 4,
  baseDelayMs: 1_000,
  maxDelayMs: 30_000,
  budgetMs: 120_000,
};

/** 408/429: not processed; 500/502/503/504: may succeed on a repeat. 501/505 will not. */
const TRANSIENT_STATUSES: ReadonlySet<number> = new Set([408, 429, 500, 502, 503, 504]);

export function isTransientStatus(status: number): boolean {
  return TRANSIENT_STATUSES.has(status);
}

/**
 * A connection-level fetch failure (reset, DNS, TLS, refused) or a request timeout. A refused redirect
 * (`redirect: 'error'`) is deliberate and permanent.
 */
export function isTransientFetchError(error: unknown): boolean {
  if (error instanceof DOMException) return error.name === 'TimeoutError';
  if (!(error instanceof TypeError) || error.message !== 'fetch failed') return false;
  return !(error.cause instanceof Error && error.cause.message === 'unexpected redirect');
}

export interface RetryDeps {
  sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  now: () => number;
  /** Abort of the whole call: never retried. */
  signal?: AbortSignal | undefined;
  /** Absolute time (per `now`) no pause may run past. */
  deadline?: number | undefined;
}

/**
 * Calls `attempt` until it gives a non-transient response or the policy runs out. Returns the last
 * response (the caller maps a non-2xx to its error) or rethrows the last transient fetch error.
 */
export async function fetchWithRetry(
  attempt: (n: number) => Promise<Response>,
  policy: Readonly<RetryPolicy>,
  deps: RetryDeps,
): Promise<Response> {
  let waited = 0;
  for (let n = 1; ; n++) {
    let res: Response;
    try {
      res = await attempt(n);
    } catch (error) {
      if (deps.signal?.aborted || !isTransientFetchError(error)) throw error;
      const pause = nextPause(n, null);
      if (pause === undefined) throw error;
      await deps.sleep(pause, deps.signal);
      continue;
    }
    if (!isTransientStatus(res.status)) return res;
    const pause = nextPause(n, res.headers.get('retry-after'));
    if (pause === undefined) return res;
    // A body stream that already failed rejects cancel(); that must not end the retries.
    await res.body?.cancel().catch(() => undefined);
    await deps.sleep(pause, deps.signal);
  }

  /** The pause before attempt n+1, or undefined when the policy says stop. */
  function nextPause(n: number, retryAfter: string | null): number | undefined {
    if (n >= policy.maxAttempts) return undefined;
    const now = deps.now();
    const pause =
      retryAfter === null
        ? Math.min(policy.baseDelayMs * 2 ** (n - 1), policy.maxDelayMs)
        : retryAfterMs(retryAfter, now, Number.POSITIVE_INFINITY);
    if (waited + pause > policy.budgetMs) return undefined;
    if (deps.deadline !== undefined && now + pause > deps.deadline) return undefined;
    waited += pause;
    return pause;
  }
}
