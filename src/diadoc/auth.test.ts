import { describe, expect, it, vi } from 'vitest';

import { DEFAULT_TOKEN_URL, RefreshTokenAuth, type RefreshTokenAuthOptions } from './auth.js';
import { DiadocAuthError } from './errors.js';

interface Call {
  url: string;
  init: RequestInit;
  body: string;
}

const urlOf = (input: string | URL | Request): string =>
  typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

const bodyOf = (init?: RequestInit): string => (typeof init?.body === 'string' ? init.body : '');

function fakeFetch(responses: Response[]): { calls: Call[]; fetchFn: typeof fetch } {
  const calls: Call[] = [];
  const fetchFn = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ url: urlOf(input), init: init ?? {}, body: bodyOf(init) });
    const res = responses.shift();
    return res ? Promise.resolve(res) : Promise.reject(new Error('unexpected request'));
  };
  return { calls, fetchFn };
}

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function makeAuth(
  responses: Response[],
  overrides: Partial<RefreshTokenAuthOptions> = {},
): { auth: RefreshTokenAuth; calls: Call[]; clock: { t: number }; slept: number[] } {
  const { calls, fetchFn } = fakeFetch(responses);
  const clock = { t: 1_000_000 };
  const slept: number[] = [];
  const auth = new RefreshTokenAuth({
    clientId: 'CID',
    clientSecret: 'SECRET',
    refreshToken: 'RT0',
    fetch: fetchFn,
    now: () => clock.t,
    sleep: (ms) => {
      slept.push(ms);
      clock.t += ms;
      return Promise.resolve();
    },
    ...overrides,
  });
  return { auth, calls, clock, slept };
}

const tokenResponse = (access: string, refresh?: string, expiresIn: number | null = 3600) =>
  jsonResponse({
    access_token: access,
    token_type: 'Bearer',
    ...(expiresIn === null ? {} : { expires_in: expiresIn }),
    ...(refresh === undefined ? {} : { refresh_token: refresh }),
  });

describe('RefreshTokenAuth', () => {
  it('posts a refresh_token grant as a form to identity.kontur.ru', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1', 'RT0')]);

    expect(await auth.getAccessToken()).toBe('AT1');

    expect(DEFAULT_TOKEN_URL).toBe('https://identity.kontur.ru/connect/token');
    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.url).toBe(DEFAULT_TOKEN_URL);
    expect(call?.init.method).toBe('POST');
    expect(new Headers(call?.init.headers).get('content-type')).toBe(
      'application/x-www-form-urlencoded',
    );
    const form = new URLSearchParams(call?.body ?? '');
    expect(Object.fromEntries(form)).toEqual({
      grant_type: 'refresh_token',
      client_id: 'CID',
      client_secret: 'SECRET',
      refresh_token: 'RT0',
    });
  });

  it('uses a custom token URL', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1')], {
      tokenUrl: 'https://idp.example/token',
    });
    await auth.getAccessToken();
    expect(calls[0]?.url).toBe('https://idp.example/token');
  });

  it('caches the access token until expiry minus the margin', async () => {
    const { auth, calls, clock } = makeAuth(
      [tokenResponse('AT1', 'RT0', 3600), tokenResponse('AT2')],
      {
        expiryMarginMs: 60_000,
      },
    );

    expect(await auth.getAccessToken()).toBe('AT1');
    clock.t += 3600_000 - 60_000 - 1;
    expect(await auth.getAccessToken()).toBe('AT1');
    expect(calls).toHaveLength(1);

    clock.t += 1;
    expect(await auth.getAccessToken()).toBe('AT2');
    expect(calls).toHaveLength(2);
  });

  it('without expires_in assumes a 5 minute lifetime (not a refresh per call)', async () => {
    const { auth, calls, clock } = makeAuth(
      [tokenResponse('AT1', undefined, null), tokenResponse('AT2', undefined, null)],
      { expiryMarginMs: 60_000 },
    );
    expect(await auth.getAccessToken()).toBe('AT1');
    clock.t += 240_000 - 1;
    expect(await auth.getAccessToken()).toBe('AT1');
    expect(calls).toHaveLength(1);
    clock.t += 1;
    expect(await auth.getAccessToken()).toBe('AT2');
  });

  it.each([0, -5])('does not cache a token with expires_in %s', async (expiresIn) => {
    const { auth, calls } = makeAuth([
      tokenResponse('AT1', undefined, expiresIn),
      tokenResponse('AT2', undefined, expiresIn),
    ]);
    expect(await auth.getAccessToken()).toBe('AT1');
    expect(await auth.getAccessToken()).toBe('AT2');
    expect(calls).toHaveLength(2);
  });

  it('never follows a redirect from the token endpoint', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1')]);
    await auth.getAccessToken();
    expect(calls[0]?.init.redirect).toBe('error');
  });

  it('repeats the identical token request on 429 (Retry-After) and 503', async () => {
    const { auth, calls, slept } = makeAuth([
      new Response('slow down', { status: 429, headers: { 'retry-after': '4' } }),
      jsonResponse({ error: 'temporarily_unavailable' }, 503),
      tokenResponse('AT1'),
    ]);
    expect(await auth.getAccessToken()).toBe('AT1');
    expect(slept).toEqual([4000, 2000]);
    expect(new Set(calls.map((c) => c.body)).size).toBe(1);
  });

  it('after the retries reports an unreachable IdP as DiadocAuthError (status 0)', async () => {
    const down = (): TypeError =>
      new TypeError('fetch failed', { cause: new Error('getaddrinfo ENOTFOUND') });
    const fetchFn = vi.fn<typeof fetch>(() => Promise.reject(down()));
    const { auth } = makeAuth([], { fetch: fetchFn, retry: { maxAttempts: 2 } });
    const err = await auth.getAccessToken().catch((e: unknown) => e);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(err).toBeInstanceOf(DiadocAuthError);
    expect(err).toMatchObject({ status: 0 });
    expect((err as Error).message).toMatch(/ENOTFOUND/);
  });

  it('stores a rotated refresh token via the callback and uses it next time', async () => {
    const onRefreshTokenRotated = vi.fn<(token: string) => Promise<void>>().mockResolvedValue();
    const { auth, calls } = makeAuth(
      [tokenResponse('AT1', 'RT1', 0), tokenResponse('AT2', 'RT1')],
      {
        onRefreshTokenRotated,
      },
    );

    await auth.getAccessToken();
    expect(onRefreshTokenRotated).toHaveBeenCalledExactlyOnceWith('RT1');

    await auth.getAccessToken();
    expect(new URLSearchParams(calls[1]?.body ?? '').get('refresh_token')).toBe('RT1');
    // same token returned again: not a rotation
    expect(onRefreshTokenRotated).toHaveBeenCalledOnce();
  });

  it('keeps the old refresh token when none is returned', async () => {
    const onRefreshTokenRotated = vi.fn();
    const { auth, calls } = makeAuth([tokenResponse('AT1', undefined, 0), tokenResponse('AT2')], {
      onRefreshTokenRotated,
    });
    await auth.getAccessToken();
    await auth.getAccessToken();
    expect(new URLSearchParams(calls[1]?.body ?? '').get('refresh_token')).toBe('RT0');
    expect(onRefreshTokenRotated).not.toHaveBeenCalled();
  });

  it('propagates a failing rotation callback but keeps the new refresh token in memory', async () => {
    const { auth, calls } = makeAuth(
      [tokenResponse('AT1', 'RT1', 0), tokenResponse('AT2', 'RT1')],
      {
        onRefreshTokenRotated: () => Promise.reject(new Error('disk full')),
      },
    );
    await expect(auth.getAccessToken()).rejects.toThrow('disk full');
    await auth.getAccessToken().catch(() => undefined);
    expect(new URLSearchParams(calls[1]?.body ?? '').get('refresh_token')).toBe('RT1');
  });

  it('does not cache the access token until a rotated refresh token is persisted', async () => {
    const persisted: string[] = [];
    let fail = true;
    const { auth, calls } = makeAuth(
      [tokenResponse('AT1', 'RT1', 3600), tokenResponse('AT2', 'RT2', 3600)],
      {
        onRefreshTokenRotated: (t) => {
          if (fail) return Promise.reject(new Error('disk full'));
          persisted.push(t);
          return Promise.resolve();
        },
      },
    );
    await expect(auth.getAccessToken()).rejects.toThrow('disk full');
    fail = false;
    expect(await auth.getAccessToken()).toBe('AT2');
    expect(calls).toHaveLength(2);
    expect(persisted).toEqual(['RT2']);
  });

  it('parses a numeric-string expires_in', async () => {
    const { auth, calls } = makeAuth([
      jsonResponse({ access_token: 'AT1', expires_in: '3600' }),
      tokenResponse('AT2'),
    ]);
    await auth.getAccessToken();
    expect(await auth.getAccessToken()).toBe('AT1');
    expect(calls).toHaveLength(1);
  });

  it('invalidate(token) only drops the cache when it still holds that token', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1'), tokenResponse('AT2')]);
    await auth.getAccessToken();
    auth.invalidate('AT1');
    expect(await auth.getAccessToken()).toBe('AT2');
    auth.invalidate('AT1'); // late 401 from a request made with the old token
    expect(await auth.getAccessToken()).toBe('AT2');
    expect(calls).toHaveLength(2);
  });

  it('passes a timeout signal to the token request', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1')]);
    await auth.getAccessToken();
    expect(calls[0]?.init.signal).toBeInstanceOf(AbortSignal);
  });

  it('rejects all concurrent callers on failure and clears the in-flight refresh', async () => {
    const { auth } = makeAuth([
      jsonResponse({ error: 'invalid_grant' }, 400),
      tokenResponse('AT1'),
    ]);
    const results = await Promise.allSettled([auth.getAccessToken(), auth.getAccessToken()]);
    expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected']);
    expect(await auth.getAccessToken()).toBe('AT1');
  });

  it('shares one in-flight refresh between concurrent callers', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1')]);
    const tokens = await Promise.all([auth.getAccessToken(), auth.getAccessToken()]);
    expect(tokens).toEqual(['AT1', 'AT1']);
    expect(calls).toHaveLength(1);
  });

  it('refreshes again after invalidate(currentToken)', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1'), tokenResponse('AT2')]);
    await auth.getAccessToken();
    auth.invalidate('AT1');
    expect(await auth.getAccessToken()).toBe('AT2');
    expect(calls).toHaveLength(2);
  });

  it('throws DiadocAuthError with status and OAuth error code, without leaking secrets', async () => {
    const { auth } = makeAuth([jsonResponse({ error: 'invalid_client' }, 400)]);
    const err = await auth.getAccessToken().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocAuthError);
    expect(err).toMatchObject({ status: 400, oauthError: 'invalid_client' });
    expect((err as Error).message).not.toMatch(/SECRET|RT0|client_secret|refresh_token=/);
  });

  it('does not cache a failure: the next call retries', async () => {
    const { auth } = makeAuth([
      jsonResponse({ error: 'invalid_grant' }, 400),
      tokenResponse('AT1'),
    ]);
    await expect(auth.getAccessToken()).rejects.toBeInstanceOf(DiadocAuthError);
    expect(await auth.getAccessToken()).toBe('AT1');
  });

  it('rejects a response without access_token', async () => {
    const { auth } = makeAuth([jsonResponse({ token_type: 'Bearer' })]);
    await expect(auth.getAccessToken()).rejects.toThrow(/access_token/);
  });

  it('rejects a non-JSON response', async () => {
    const { auth } = makeAuth([new Response('<html>oops</html>', { status: 200 })]);
    await expect(auth.getAccessToken()).rejects.toBeInstanceOf(DiadocAuthError);
  });
});

describe('RefreshTokenAuth deadline and abort (R2 minor 8)', () => {
  it('does not wait for a Retry-After that leaves no time for a request before the deadline', async () => {
    const { auth, calls, clock, slept } = makeAuth(
      [
        new Response('slow down', { status: 429, headers: { 'retry-after': '40' } }),
        tokenResponse('AT1'),
      ],
      { timeoutMs: 30_000 },
    );
    const err = await auth.getAccessToken({ deadline: clock.t + 60_000 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocAuthError);
    expect(err).toMatchObject({ status: 429 });
    expect(calls).toHaveLength(1);
    expect(slept).toEqual([]);
  });

  it('does not start a token request that could not end before the deadline', async () => {
    const { auth, calls, clock } = makeAuth([tokenResponse('AT1')], { timeoutMs: 30_000 });
    const err = await auth.getAccessToken({ deadline: clock.t + 29_999 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DiadocAuthError);
    expect((err as Error).message).toMatch(/not asked.*30 s.*deadline/);
    expect(calls).toHaveLength(0);
    expect(await auth.getAccessToken({ deadline: clock.t + 30_000 })).toBe('AT1');
  });

  it('never cuts a token request with the deadline: it runs with its own full timeout', async () => {
    const { auth, calls, clock } = makeAuth([tokenResponse('AT1')], { timeoutMs: 30_000 });
    await auth.getAccessToken({ deadline: clock.t + 30_000 });
    const signal = calls[0]?.init.signal;
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(signal?.aborted).toBe(false);
  });

  it('a cached token is returned even past the deadline', async () => {
    const { auth, clock } = makeAuth([tokenResponse('AT1')]);
    await auth.getAccessToken();
    expect(await auth.getAccessToken({ deadline: clock.t - 1 })).toBe('AT1');
  });

  it('an abort does not cut a sent token request: the rotated token is persisted first', async () => {
    const controller = new AbortController();
    const reason = new Error('interrupted (SIGTERM)');
    let answer: (res: Response) => void = () => undefined;
    const persisted: string[] = [];
    const auth = new RefreshTokenAuth({
      clientId: 'CID',
      clientSecret: 'SECRET',
      refreshToken: 'RT0',
      fetch: (_input, init) =>
        new Promise((resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(init.signal?.reason as Error);
          });
          answer = resolve;
        }),
      onRefreshTokenRotated: (token) => {
        persisted.push(token);
      },
    });
    const pending = auth.getAccessToken({ signal: controller.signal });
    await Promise.resolve();
    controller.abort(reason);
    answer(tokenResponse('AT1', 'RT1'));
    expect(await pending).toBe('AT1');
    expect(persisted).toEqual(['RT1']);
  });

  it('an abort stops a retry pause with the signal reason', async () => {
    const controller = new AbortController();
    const reason = new Error('interrupted (SIGINT)');
    const { auth } = makeAuth(
      [new Response('unavailable', { status: 503, headers: { 'retry-after': '1' } })],
      {
        sleep: (_ms, signal) =>
          new Promise((_resolve, reject) => {
            signal?.addEventListener('abort', () => {
              reject(new DOMException('The operation was aborted', 'AbortError'));
            });
            controller.abort(reason);
          }),
      },
    );
    await expect(auth.getAccessToken({ signal: controller.signal })).rejects.toBe(reason);
  });

  it('an already aborted signal makes no request', async () => {
    const { auth, calls } = makeAuth([tokenResponse('AT1')]);
    const reason = new Error('stop');
    await expect(auth.getAccessToken({ signal: AbortSignal.abort(reason) })).rejects.toBe(reason);
    expect(calls).toHaveLength(0);
  });
});
