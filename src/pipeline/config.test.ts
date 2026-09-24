import { describe, expect, it } from 'vitest';

import { loadPipelineConfig, PipelineConfigError } from './config.js';

const base = { DIADOC_FROM_BOX_ID: 'a@diadoc.ru', DIADOC_TO_BOX_ID: 'b@diadoc.ru' };

describe('loadPipelineConfig', () => {
  it('reads box ids; precheck on by default, default polling', () => {
    expect(loadPipelineConfig(base)).toEqual({
      fromBoxId: 'a@diadoc.ru',
      toBoxId: 'b@diadoc.ru',
      precheck: true,
      poll: {},
    });
  });

  it('reads precheck switch and polling overrides (0 timeout allowed)', () => {
    expect(
      loadPipelineConfig({
        ...base,
        PIPELINE_PRECHECK: 'false',
        PIPELINE_STATUS_TIMEOUT_MS: '0',
        PIPELINE_STATUS_INITIAL_DELAY_MS: '500',
        PIPELINE_STATUS_MAX_DELAY_MS: '5000',
      }),
    ).toMatchObject({
      precheck: false,
      poll: { timeoutMs: 0, initialDelayMs: 500, maxDelayMs: 5000 },
    });
  });

  it.each(['DIADOC_FROM_BOX_ID', 'DIADOC_TO_BOX_ID'])('requires %s', (name) => {
    expect(() => loadPipelineConfig({ ...base, [name]: ' ' })).toThrow(
      new PipelineConfigError(`${name} is not set`),
    );
  });

  it('rejects equal boxes, a bad switch and bad numbers', () => {
    expect(() => loadPipelineConfig({ ...base, DIADOC_TO_BOX_ID: 'a@diadoc.ru' })).toThrow(
      /differ/,
    );
    expect(() => loadPipelineConfig({ ...base, PIPELINE_PRECHECK: 'yes' })).toThrow(
      /PIPELINE_PRECHECK/,
    );
    expect(() => loadPipelineConfig({ ...base, PIPELINE_STATUS_TIMEOUT_MS: '-1' })).toThrow(
      /PIPELINE_STATUS_TIMEOUT_MS/,
    );
    expect(() => loadPipelineConfig({ ...base, PIPELINE_STATUS_INITIAL_DELAY_MS: '0' })).toThrow(
      /PIPELINE_STATUS_INITIAL_DELAY_MS/,
    );
    expect(() =>
      loadPipelineConfig({ ...base, PIPELINE_STATUS_INITIAL_DELAY_MS: '40000' }),
    ).toThrow(/must not exceed/);
  });
});
