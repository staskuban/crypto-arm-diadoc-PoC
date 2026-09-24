// OIDC Refresh Token Flow against identity.kontur.ru (developer.kontur.ru/doc/diadoc-api/authentication.html).
// One IdP for prod and staging: the scope (Diadoc.PublicAPI[.Staging]) is fixed when the refresh token
// is issued in the integrator cabinet, so the refresh request carries no scope.
import { DiadocAuthError } from './errors.js';

export const DEFAULT_TOKEN_URL = 'https://identity.kontur.ru/connect/token';
const DEFAULT_EXPIRY_MARGIN_MS = 60_000;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_BODY_IN_MESSAGE = 300;

/** Anything that can hand out a Bearer token. */
export interface AccessTokenProvider {
  getAccessToken(): Promise<string>;
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
  fetch?: typeof fetch;
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
  private readonly now: () => number;

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
    this.now = o.now ?? Date.now;
  }

  getAccessToken(): Promise<string> {
    if (this.cached && this.now() < this.cached.refreshAt) {
      return Promise.resolve(this.cached.accessToken);
    }
    this.inFlight ??= this.refresh().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  invalidate(accessToken: string): void {
    if (this.cached?.accessToken === accessToken) this.cached = undefined;
  }

  private async refresh(): Promise<string> {
    const startedAt = this.now();
    const res = await this.fetchFn(this.tokenUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        refresh_token: this.refreshToken,
      }).toString(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    const body = parseJson(text);

    if (!res.ok) {
      const oauthError = typeof body?.error === 'string' ? body.error : undefined;
      throw new DiadocAuthError(
        `Token endpoint ${this.tokenUrl} -> ${String(res.status)}: ${text.slice(0, MAX_BODY_IN_MESSAGE)}`,
        res.status,
        oauthError,
      );
    }
    if (!body) {
      throw new DiadocAuthError(
        `Token endpoint returned non-JSON (${String(res.status)}): ${text.slice(0, MAX_BODY_IN_MESSAGE)}`,
        res.status,
      );
    }
    if (typeof body.access_token !== 'string' || body.access_token === '') {
      throw new DiadocAuthError('Token endpoint returned no access_token', res.status);
    }

    if (typeof body.refresh_token === 'string' && body.refresh_token !== '') {
      const rotated = body.refresh_token !== this.refreshToken;
      // Remember it before the callback: once rotated, the old one may already be dead.
      this.refreshToken = body.refresh_token;
      // Cache the access token only after a successful persist, so a failed persist is retried
      // on the next call instead of being hidden behind a day-long cached token.
      if (rotated) await this.onRefreshTokenRotated?.(body.refresh_token);
    }

    // Without a usable lifetime the token is used for this call only.
    this.cached = {
      accessToken: body.access_token,
      refreshAt: startedAt + expiresInSeconds(body.expires_in) * 1000 - this.expiryMarginMs,
    };
    return body.access_token;
  }
}

function expiresInSeconds(value: unknown): number {
  const n = typeof value === 'string' && /^\d+$/.test(value.trim()) ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : 0;
}

function parseJson(text: string): TokenResponse | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null ? value : undefined;
  } catch {
    return undefined;
  }
}
