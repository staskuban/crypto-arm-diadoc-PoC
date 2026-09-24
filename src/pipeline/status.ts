import {
  DiadocAuthError,
  DiadocError,
  type DocflowStatus,
  type Document,
  type DocumentRef,
} from '../diadoc/index.js';

/**
 * `success`/`error`: a final DocflowStatus. `pending`: anything else (e.g. delivered, waiting for the
 * recipient's signature — which can take days, so polling ends at a deadline, not at "done").
 */
export type DocflowOutcome = 'success' | 'error' | 'pending';

export interface PollOptions {
  /** First pause between GetDocument calls; doubles each time. Default 2 s. */
  initialDelayMs: number;
  /** Cap for the pause. Default 30 s. */
  maxDelayMs: number;
  /** Polling stops this long after the first GetDocument. 0 = read the status once. Default 60 s. */
  timeoutMs: number;
}

export const DEFAULT_POLL_OPTIONS: Readonly<PollOptions> = {
  initialDelayMs: 2_000,
  maxDelayMs: 30_000,
  timeoutMs: 60_000,
};

/**
 * Assumption (D5, not seen live): `Severity` is `Info | Success | Warning | Error`; `Error` in either
 * status means the docflow failed (e.g. signature rejected), `Success` in the primary status is final.
 */
export function docflowOutcome(status: DocflowStatus | undefined): DocflowOutcome {
  const primary = status?.PrimaryStatus?.Severity?.toLowerCase();
  const secondary = status?.SecondaryStatus?.Severity?.toLowerCase();
  if (primary === 'error' || secondary === 'error') return 'error';
  if (primary === 'success') return 'success';
  return 'pending';
}

export interface PollResult {
  outcome: DocflowOutcome;
  /** Last DocflowStatus read successfully. */
  status?: DocflowStatus;
  /** Set when the last GetDocument call failed. */
  statusError?: unknown;
  polls: number;
}

export interface PollDeps {
  getDocument(ref: DocumentRef): Promise<Document>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  signal?: AbortSignal | undefined;
}

/**
 * A token failure, or a 4xx other than 404 (eventual consistency) and 429, will not get better by
 * asking again.
 */
function isPermanent(error: unknown): boolean {
  if (error instanceof DiadocAuthError) return true;
  return (
    error instanceof DiadocError &&
    error.status >= 400 &&
    error.status < 500 &&
    error.status !== 404 &&
    error.status !== 429
  );
}

/**
 * Never throws: the message is already sent and the caller needs its ids. A Diadoc failure or an
 * abort ends polling with `outcome: 'pending'` (and `statusError` for the failure).
 */
export async function pollDocflowStatus(
  ref: DocumentRef,
  deps: PollDeps,
  options: PollOptions,
): Promise<PollResult> {
  const deadline = deps.now() + options.timeoutMs;
  let delay = options.initialDelayMs;
  const result: PollResult = { outcome: 'pending', polls: 0 };

  for (;;) {
    if (deps.signal?.aborted) return result;
    result.polls++;
    try {
      const doc = await deps.getDocument(ref);
      delete result.statusError;
      if (doc.DocflowStatus) {
        result.status = doc.DocflowStatus;
        result.outcome = docflowOutcome(doc.DocflowStatus);
        if (result.outcome !== 'pending') return result;
      }
    } catch (error) {
      result.statusError = error;
      if (isPermanent(error)) return result;
    }

    const remaining = deadline - deps.now();
    if (remaining <= 0) return result;
    try {
      await deps.sleep(Math.min(delay, remaining));
    } catch (error) {
      if (!deps.signal?.aborted) result.statusError = error;
      return result;
    }
    delay = Math.min(delay * 2, options.maxDelayMs);
  }
}
