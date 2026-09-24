// OIDC Refresh Token Flow against identity.kontur.ru (developer.kontur.ru/doc/diadoc-api/authentication.html).
// The staging/prod choice is not a token parameter: the scope (Diadoc.PublicAPI.Staging) is fixed when
// the refresh token is issued in the integrator cabinet.

export type TokenSet = { accessToken: string; expiresIn: number; refreshToken: string };

export async function refreshAccessToken(o: {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  fetchFn?: typeof fetch;
}): Promise<TokenSet> {
  const res = await (o.fetchFn ?? fetch)(o.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: o.clientId,
      client_secret: o.clientSecret,
      refresh_token: o.refreshToken,
    }).toString(),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Token endpoint ${o.tokenUrl} -> ${res.status}: ${text.slice(0, 500)}`);
  let body: { access_token?: string; expires_in?: number; refresh_token?: string };
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`Token endpoint returned non-JSON (${res.status}): ${text.slice(0, 200)}`);
  }
  if (!body.access_token) throw new Error(`Token endpoint returned no access_token: ${text.slice(0, 200)}`);
  return {
    accessToken: body.access_token,
    expiresIn: body.expires_in ?? 0,
    // the docs say the refresh token is rotated on each exchange; fall back to the old one if it is not
    refreshToken: body.refresh_token ?? o.refreshToken,
  };
}

/**
 * The token endpoint may rotate the refresh token, so the latest one is cached in .state. A token re-issued
 * in the integrator cabinet and put into .env must win over that cache, hence the remembered .env source.
 */
export function chooseRefreshToken(envToken: string, cached?: { refreshToken: string; sourceRefreshToken: string }): string {
  return cached && cached.sourceRefreshToken === envToken ? cached.refreshToken : envToken;
}
