import { describe, expect, it } from 'vitest';

import { retryAfterMs } from './retry-after.js';

describe('retryAfterMs', () => {
  const now = Date.parse('2026-09-24T10:00:00Z');

  it.each([
    ['3', 3000],
    [' 5 ', 5000],
    ['Thu, 24 Sep 2026 10:00:04 GMT', 4000],
  ])('parses %j', (header, expected) => {
    expect(retryAfterMs(header, now)).toBe(expected);
  });

  it.each([null, '', 'soon', '0', '-3', 'Thu, 24 Sep 2026 09:59:00 GMT'])(
    'falls back to 1 s for %j',
    (header) => {
      expect(retryAfterMs(header, now)).toBe(1000);
    },
  );

  it('caps the delay', () => {
    expect(retryAfterMs('3600', now)).toBe(60_000);
    expect(retryAfterMs('3600', now, 5000)).toBe(5000);
  });
});
