import { DEFAULT_POLL_OPTIONS, type PollOptions } from './status.js';

export type PipelineEnv = Record<string, string | undefined>;

export interface PipelineConfig {
  fromBoxId: string;
  toBoxId: string;
  precheck: boolean;
  /** Only the overridden fields; the rest come from DEFAULT_POLL_OPTIONS. */
  poll: Partial<PollOptions>;
}

export class PipelineConfigError extends Error {
  override readonly name = 'PipelineConfigError';
}

/** Timers overflow above 2^31-1 ms and would fire immediately. */
const MAX_MS = 2 ** 31 - 1;

/**
 * `DIADOC_FROM_BOX_ID`, `DIADOC_TO_BOX_ID` (staging and prod ids differ); optional
 * `PIPELINE_PRECHECK` (`true`|`false`), `PIPELINE_STATUS_TIMEOUT_MS` (0 = read status once),
 * `PIPELINE_STATUS_INITIAL_DELAY_MS`, `PIPELINE_STATUS_MAX_DELAY_MS`.
 */
export function loadPipelineConfig(env: PipelineEnv = process.env): PipelineConfig {
  const fromBoxId = required(env, 'DIADOC_FROM_BOX_ID');
  const toBoxId = required(env, 'DIADOC_TO_BOX_ID');
  if (fromBoxId === toBoxId) {
    throw new PipelineConfigError('DIADOC_FROM_BOX_ID and DIADOC_TO_BOX_ID must differ');
  }

  const precheckText = env.PIPELINE_PRECHECK?.trim().toLowerCase() ?? '';
  if (!['', 'true', 'false'].includes(precheckText)) {
    throw new PipelineConfigError(
      `PIPELINE_PRECHECK must be true or false, got ${JSON.stringify(env.PIPELINE_PRECHECK)}`,
    );
  }

  const poll: Partial<PollOptions> = {};
  const timeoutMs = ms(env, 'PIPELINE_STATUS_TIMEOUT_MS', 0);
  if (timeoutMs !== undefined) poll.timeoutMs = timeoutMs;
  const initialDelayMs = ms(env, 'PIPELINE_STATUS_INITIAL_DELAY_MS', 1);
  if (initialDelayMs !== undefined) poll.initialDelayMs = initialDelayMs;
  const maxDelayMs = ms(env, 'PIPELINE_STATUS_MAX_DELAY_MS', 1);
  if (maxDelayMs !== undefined) poll.maxDelayMs = maxDelayMs;

  const initial = poll.initialDelayMs ?? DEFAULT_POLL_OPTIONS.initialDelayMs;
  const max = poll.maxDelayMs ?? DEFAULT_POLL_OPTIONS.maxDelayMs;
  if (initial > max) {
    throw new PipelineConfigError(
      `PIPELINE_STATUS_INITIAL_DELAY_MS (${String(initial)}) must not exceed PIPELINE_STATUS_MAX_DELAY_MS (${String(max)})`,
    );
  }

  return { fromBoxId, toBoxId, precheck: precheckText !== 'false', poll };
}

function required(env: PipelineEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new PipelineConfigError(`${name} is not set`);
  return value;
}

function ms(env: PipelineEnv, name: string, min: number): number | undefined {
  const text = env[name];
  if (!text) return undefined;
  const value = Number(text);
  if (!Number.isInteger(value) || value < min || value > MAX_MS) {
    throw new PipelineConfigError(
      `${name} must be an integer in ${String(min)}..${String(MAX_MS)}, got ${JSON.stringify(text)}`,
    );
  }
  return value;
}
