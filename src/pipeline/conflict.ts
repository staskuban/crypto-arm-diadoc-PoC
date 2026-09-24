// PostMessage 409 has one status for two different situations (docs/plan.md D4): the message was
// already posted, or the recipient's settings (Sociability) forbid it. Only the response text tells
// them apart.
//
// UNVERIFIED: these patterns are guesses from the documentation wording, not texts seen live.
// Replace them with the real texts after the S1 live run. Keep every 409 text rule in this file.

export type ConflictKind = 'duplicate' | 'forbidden' | 'unknown';

export const CONFLICT_TEXT_PATTERNS: Readonly<
  Record<Exclude<ConflictKind, 'unknown'>, readonly RegExp[]>
> = {
  forbidden: [
    /sociability/i,
    /forbid/i,
    /not\s+allowed/i,
    /запре[тщ]/i,
    /не\s+разреш/i,
    /не\s+принима/i,
  ],
  duplicate: [
    /duplicate/i,
    /already/i,
    /дубл/i,
    /уже\s+(был[оаи]?\s+)?(отправлен|существ|загружен)/i,
  ],
};

/**
 * Classifies a 409 body. `forbidden` is checked first: misreading a refusal as "already sent" would
 * hide that the document never reached the recipient.
 */
export function classifyConflict(body: string): ConflictKind {
  if (CONFLICT_TEXT_PATTERNS.forbidden.some((re) => re.test(body))) return 'forbidden';
  if (CONFLICT_TEXT_PATTERNS.duplicate.some((re) => re.test(body))) return 'duplicate';
  return 'unknown';
}
