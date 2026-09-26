import { describe, expect, it } from 'vitest';

import * as asn1 from './asn1/index.js';
import * as diadoc from './diadoc/index.js';
import * as pipeline from './pipeline/index.js';
import * as signer from './signer/index.js';
import * as utd from './utd/index.js';

describe('scaffold', () => {
  it('resolves every top-level module', () => {
    for (const mod of [asn1, signer, diadoc, utd, pipeline]) {
      expect(mod).toBeTypeOf('object');
    }
  });
});
