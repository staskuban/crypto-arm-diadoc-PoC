import { describe, expect, it } from 'vitest';

import {
  DEFAULT_RETRY_POLICY,
  fetchWithRetry,
  isTransientFetchError,
  type RetryPolicy,
} from './http-retry.js';

const POLICY: RetryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 1000,
  maxDelayMs: 4000,
  budgetMs: 60_000,
};

const fetchFailed = (cause: string): TypeError =>
  new TypeError('fetch failed', { cause: new Error(cause) });
const timeout = (): DOMException =>
  new DOMException('The operation was aborted due to timeout', 'TimeoutError');

function run(
  outcomes: (Response | Error)[],
  o: { policy?: RetryPolicy; deadline?: number; signal?: AbortSignal } = {},
) {
  let clock = 1_000_000;
  const slept: number[] = [];
  const attempts: number[] = [];
  const promise = fetchWithRetry(
    (n) => {
      attempts.push(n);
      const next = outcomes.shift();
      if (next === undefined) return Promise.reject(new Error('unexpected attempt'));
      return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
    },
    o.policy ?? POLICY,
    {
      now: () => clock,
      sleep: (ms) => {
        slept.push(ms);
        clock += ms;
        return Promise.resolve();
      },
      ...(o.deadline === undefined ? {} : { deadline: o.deadline }),
      ...(o.signal === undefined ? {} : { signal: o.signal }),
    },
  );
  return { promise, slept, attempts };
}

const status = (code: number, headers: Record<string, string> = {}): Response =>
  new Response(code === 204 ? null : `status ${String(code)}`, { status: code, headers });

describe('fetchWithRetry', () => {
  it('has a bounded default policy', () => {
    expect(DEFAULT_RETRY_POLICY.maxAttempts).toBeGreaterThan(1);
    expect(DEFAULT_RETRY_POLICY.budgetMs).toBeLessThanOrEqual(180_000);
  });

  it('returns the first non-transient response without sleeping', async () => {
    const { promise, slept } = run([status(400)]);
    expect((await promise).status).toBe(400);
    expect(slept).toEqual([]);
  });

  it.each([408, 429, 500, 502, 503, 504])('retries %s with exponential backoff', async (code) => {
    const { promise, slept, attempts } = run([status(code), status(code), status(200)]);
    expect((await promise).status).toBe(200);
    expect(slept).toEqual([1000, 2000]);
    expect(attempts).toEqual([1, 2, 3]);
  });

  it.each([501, 505])('does not retry %s', async (code) => {
    const { promise, attempts } = run([status(code)]);
    expect((await promise).status).toBe(code);
    expect(attempts).toEqual([1]);
  });

  it('honours Retry-After in seconds and as an HTTP date', async () => {
    const date = new Date(1_000_000 + 7_000).toUTCString(); // clock starts at 1 000 000 ms
    const { promise, slept } = run([
      status(429, { 'retry-after': '3' }),
      status(503, { 'retry-after': date }),
      status(200),
    ]);
    await promise;
    expect(slept[0]).toBe(3000);
    // HTTP dates have 1 s resolution; after the first 3 s sleep about 4 s are left
    expect(slept[1]).toBeGreaterThan(3000);
    expect(slept[1]).toBeLessThanOrEqual(4000);
  });

  it('caps the backoff at maxDelayMs', async () => {
    const { promise, slept } = run([status(502), status(502), status(502), status(200)], {
      policy: { ...POLICY, baseDelayMs: 3000 },
    });
    await promise;
    expect(slept).toEqual([3000, 4000, 4000]);
  });

  it('returns the last transient response after maxAttempts', async () => {
    const { promise, attempts } = run([status(503), status(503), status(503), status(503)]);
    expect((await promise).status).toBe(503);
    expect(attempts).toEqual([1, 2, 3, 4]);
  });

  it('gives up instead of waiting past the budget (a long Retry-After is not shortened)', async () => {
    const { promise, slept } = run([status(429, { 'retry-after': '3600' })]);
    expect((await promise).status).toBe(429);
    expect(slept).toEqual([]);
  });

  it('stops when the total wait would exceed the budget', async () => {
    const { promise, slept } = run([status(503), status(503), status(503)], {
      policy: { ...POLICY, budgetMs: 2500 },
    });
    expect((await promise).status).toBe(503);
    expect(slept).toEqual([1000]);
  });

  it('still sleeps when the total wait reaches the budget exactly', async () => {
    const { promise, slept, attempts } = run([status(503), status(503), status(503)], {
      policy: { ...POLICY, budgetMs: 3000 },
    });
    expect((await promise).status).toBe(503);
    expect(slept).toEqual([1000, 2000]);
    expect(attempts).toEqual([1, 2, 3]);
  });

  it('never sleeps past the deadline', async () => {
    const { promise, slept } = run([status(503), status(503)], { deadline: 1_000_000 + 1500 });
    expect((await promise).status).toBe(503);
    expect(slept).toEqual([1000]);
  });

  it('retries network errors and timeouts, then rethrows the last one', async () => {
    const last = timeout();
    const { promise, slept } = run([fetchFailed('ECONNRESET'), timeout(), timeout(), last]);
    await expect(promise).rejects.toBe(last);
    expect(slept).toEqual([1000, 2000, 4000]);
  });

  it('recovers from a network error', async () => {
    const { promise } = run([fetchFailed('ECONNRESET'), status(200)]);
    expect((await promise).status).toBe(200);
  });

  it('does not retry a refused redirect or a non-network error', async () => {
    const redirect = fetchFailed('unexpected redirect');
    await expect(run([redirect]).promise).rejects.toBe(redirect);
    const bug = new Error('token file not writable');
    const r = run([bug]);
    await expect(r.promise).rejects.toBe(bug);
    expect(r.attempts).toEqual([1]);
  });

  it('rethrows at once when the caller signal aborted', async () => {
    const controller = new AbortController();
    const reason = new Error('shutdown');
    controller.abort(reason);
    const { promise, attempts } = run([reason], { signal: controller.signal });
    await expect(promise).rejects.toBe(reason);
    expect(attempts).toEqual([1]);
  });

  it('rethrows a transient error at once when the caller signal aborted meanwhile', async () => {
    const controller = new AbortController();
    controller.abort(new Error('shutdown'));
    const reset = fetchFailed('ECONNRESET'); // e.g. the abort tore down the connection
    const { promise, attempts, slept } = run([reset, status(200)], { signal: controller.signal });
    await expect(promise).rejects.toBe(reset);
    expect(attempts).toEqual([1]);
    expect(slept).toEqual([]);
  });

  it('cancels the body of a response it discards', async () => {
    let cancelled = false;
    const body = new ReadableStream({
      cancel() {
        cancelled = true;
      },
    });
    const { promise } = run([new Response(body, { status: 503 }), status(200)]);
    await promise;
    expect(cancelled).toBe(true);
  });
});

describe('isTransientFetchError', () => {
  it.each([
    ['fetch failed (reset)', fetchFailed('ECONNRESET'), true],
    ['timeout', timeout(), true],
    ['redirect refused', fetchFailed('unexpected redirect'), false],
    ['other TypeError', new TypeError('x is undefined'), false],
    ['plain Error', new Error('boom'), false],
    ['not an error', 'fetch failed', false],
  ])('%s → %s', (_name, error, expected) => {
    expect(isTransientFetchError(error)).toBe(expected);
  });
});
