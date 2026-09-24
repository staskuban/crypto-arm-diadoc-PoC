// OIDC Refresh Token Flow against identity.kontur.ru (developer.kontur.ru/doc/diadoc-api/authentication.html).
// One IdP for prod and staging: the scope (Diadoc.PublicAPI[.Staging]) is fixed when the refresh token
// is issued in the integrator cabinet, so the refresh request carries no scope.
import { setTimeout as delay } from 'node:timers/promises';

import { DiadocAuthError } from './errors.js';
import {
  DEFAULT_RETRY_POLICY,
  fetchWithRetry,
  isTransientFetchError,
  type RetryPolicy,
} from './http-retry.js';

export const DEFAULT_TOKEN_URL = 'https://identity.kontur.ru/connect/token';
const DEFAULT_EXPIRY_MARGIN_MS = 60_000;
const DEFAULT_TIMEOUT_MS = 30_000;
/**
 * Assumed lifetime when the IdP sends no `expires_in`: short, but not a refresh (and a possible
 * token-file write) on every API call.
 */
const DEFAULT_LIFETIME_S = 300;
const MAX_BODY_IN_MESSAGE = 300;

/** Bounds for a token refresh made on behalf of one API call. */
export interface TokenRequestOptions {
  /**
   * Stops a refresh before its first request and in its retry pauses; the call then rejects with the
   * signal's reason. A token request already sent is never cut: its answer may carry a rotated refresh
   * token that has to reach the disk (the old one may be dead already).
   */
  signal?: AbortSignal | undefined;
  /**
   * Absolute time (per the provider's clock) a refresh must end by: a token request (with its full
   * timeout) is only started when it can finish before it, and no pause runs past that point. A cached
   * token is returned regardless.
   */
  deadline?: number | undefined;
}

/** Anything that can hand out a Bearer token. */
export interface AccessTokenProvider {
  getAccessToken(o?: TokenRequestOptions): Promise<string>;
  /**
   * The API rejected `accessToken` (401): forget it if it is still the cached one. Passing the rejected
   * token keeps late 401s from wiping a token that was refreshed in the meantime.
   */
  invalidate?(accessToken: string): void;
}

export interface RefreshTokenAuthOptions {
  clientId: string;
  /** API key from «Кабинет интегратора». */
  clientSecret: string;
  /** Latest known refresh token (initially the one issued in the integrator cabinet). */
  refreshToken: string;
  /**
   * Called when the IdP returns a different refresh token. Persist it: the docs say the token may be
   * rotated on each exchange. A rejection propagates to the caller of getAccessToken().
   */
  onRefreshTokenRotated?: (refreshToken: string) => void | Promise<void>;
  tokenUrl?: string;
  /** Refresh this long before `expires_in` runs out. Default 60 s. */
  expiryMarginMs?: number;
  /** Per token request. Default 30 s. */
  timeoutMs?: number;
  /**
   * Repeats of the identical token request on 429 (Retry-After), 408, 5xx, network errors and
   * timeouts. A lost response may have rotated the refresh token already; repeating with the old one
   * is still the only chance to get a token.
   */
  retry?: Partial<RetryPolicy>;
  fetch?: typeof fetch;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
}

interface TokenResponse {
  access_token?: unknown;
  expires_in?: unknown;
  refresh_token?: unknown;
  error?: unknown;
}

export class RefreshTokenAuth implements AccessTokenProvider {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly tokenUrl: string;
  private readonly expiryMarginMs: number;
  private readonly timeoutMs: number;
  private readonly onRefreshTokenRotated: RefreshTokenAuthOptions['onRefreshTokenRotated'];
  private readonly fetchFn: typeof fetch;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  private readonly now: () => number;
  private readonly retry: Readonly<RetryPolicy>;

  private refreshToken: string;
  private cached: { accessToken: string; refreshAt: number } | undefined;
  private inFlight: Promise<string> | undefined;

  constructor(o: RefreshTokenAuthOptions) {
    this.clientId = o.clientId;
    this.clientSecret = o.clientSecret;
    this.refreshToken = o.refreshToken;
    this.tokenUrl = o.tokenUrl ?? DEFAULT_TOKEN_URL;
    this.expiryMarginMs = o.expiryMarginMs ?? DEFAULT_EXPIRY_MARGIN_MS;
    this.timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.onRefreshTokenRotated = o.onRefreshTokenRotated;
    this.fetchFn = o.fetch ?? fetch;
    this.sleep =
      o.sleep ?? ((ms, signal) => delay(ms, undefined, signal === undefined ? {} : { signal }));
    this.now = o.now ?? Date.now;
    this.retry = { ...DEFAULT_RETRY_POLICY, ...o.retry };
  }

  /**
   * A call that finds a refresh already running waits for it: the refresh runs under the options of
   * the call that started it.
   */
  getAccessToken(o: TokenRequestOptions = {}): Promise<string> {
    if (this.cached && this.now() < this.cached.refreshAt) {
      return Promise.resolve(this.cached.accessToken);
    }
    this.inFlight ??= this.refresh(o).finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  invalidate(accessToken: string): void {
    if (this.cached?.accessToken === accessToken) this.cached = undefined;
  }

  private async refresh(o: TokenRequestOptions): Promise<string> {
    const { signal, deadline } = o;
    signal?.throwIfAborted();
    const startedAt = this.now();
    // The last moment a request with the full timeout can start and still end by the deadline.
    const lastStart = deadline === undefined ? undefined : deadline - this.timeoutMs;
    if (lastStart !== undefined && startedAt > lastStart) {
      throw new DiadocAuthError(
        `Token endpoint ${this.tokenUrl} not asked: a token request (up to ` +
          `${String(this.timeoutMs / 1000)} s) would not end before the deadline of the API call`,
        0,
      );
    }
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: this.refreshToken,
    }).toString();
    let res: Response;
    try {
      res = await fetchWithRetry(
        () =>
          this.fetchFn(this.tokenUrl, {
            method: 'POST',
            headers: {
              'content-type': 'application/x-www-form-urlencoded',
              accept: 'application/json',
            },
            body,
            // A 3xx to another host would carry client_secret and refresh_token there.
            redirect: 'error',
            // Not the caller's signal: see TokenRequestOptions.signal.
            signal: AbortSignal.timeout(this.timeoutMs),
          }),
        this.retry,
        { sleep: this.sleep, now: this.now, signal, deadline: lastStart },
      );
    } catch (error) {
      // An aborted pause rejects with its own AbortError.
      if (signal?.aborted) throw signal.reason;
      if (!isTransientFetchError(error)) throw error;
      // A DiadocAuthError, so callers that retry on network errors do not repeat the whole loop.
      const reason = error instanceof Error && error.cause instanceof Error ? error.cause : error;
      throw new DiadocAuthError(
        `Token endpoint ${this.tokenUrl} unreachable: ${reason instanceof Error ? reason.message : String(reason)}`,
        0,
        undefined,
        { cause: error },
      );
    }
    const text = await res.text();
    const json = parseJson(text);

    if (!res.ok) {
      const oauthError = typeof json?.error === 'string' ? json.error : undefined;
      throw new DiadocAuthError(
        `Token endpoint ${this.tokenUrl} -> ${String(res.status)}: ${text.slice(0, MAX_BODY_IN_MESSAGE)}`,
        res.status,
        oauthError,
      );
    }
    if (!json) {
      throw new DiadocAuthError(
        `Token endpoint returned non-JSON (${String(res.status)}): ${text.slice(0, MAX_BODY_IN_MESSAGE)}`,
        res.status,
      );
    }
    if (typeof json.access_token !== 'string' || json.access_token === '') {
      throw new DiadocAuthError('Token endpoint returned no access_token', res.status);
    }

    if (typeof json.refresh_token === 'string' && json.refresh_token !== '') {
      const rotated = json.refresh_token !== this.refreshToken;
      // Remember it before the callback: once rotated, the old one may already be dead.
      this.refreshToken = json.refresh_token;
      // Cache the access token only after a successful persist, so a failed persist is retried
      // on the next call instead of being hidden behind a day-long cached token.
      if (rotated) await this.onRefreshTokenRotated?.(json.refresh_token);
    }

    this.cached = {
      accessToken: json.access_token,
      refreshAt: startedAt + expiresInSeconds(json.expires_in) * 1000 - this.expiryMarginMs,
    };
    return json.access_token;
  }
}

/** Missing or unreadable → DEFAULT_LIFETIME_S; zero or negative → not cached. */
function expiresInSeconds(value: unknown): number {
  const n = typeof value === 'string' && /^-?\d+$/.test(value.trim()) ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isFinite(n)) return DEFAULT_LIFETIME_S;
  return Math.max(n, 0);
}

function parseJson(text: string): TokenResponse | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null ? value : undefined;
  } catch {
    return undefined;
  }
}
