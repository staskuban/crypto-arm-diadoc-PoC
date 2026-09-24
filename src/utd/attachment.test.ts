import { describe, expect, it } from 'vitest';

import { buildUtdAttachment, contentPlacement, INLINE_CONTENT_LIMIT } from './attachment.js';
import { UtdError } from './errors.js';
import type { UtdDocument } from './parse.js';

const signature = Buffer.from([0x30, 0x82, 0x01, 0x00, 0x06, 0x09]);

function doc(content: Buffer): UtdDocument {
  return {
    fileName: 'ON_NSCHFDOPPR_x.xml',
    idFile: 'ON_NSCHFDOPPR_x',
    content,
    function: 'СЧФДОП',
    formatVersion: '5.03',
    version: 'utd970_05_03_01',
  };
}

describe('contentPlacement', () => {
  it('is inline strictly below 500 KB and shelf from 500 KB up', () => {
    expect(INLINE_CONTENT_LIMIT).toBe(500_000);
    expect(contentPlacement(0)).toBe('inline');
    expect(contentPlacement(INLINE_CONTENT_LIMIT - 1)).toBe('inline');
    expect(contentPlacement(INLINE_CONTENT_LIMIT)).toBe('shelf');
    expect(contentPlacement(70 * 1024 * 1024)).toBe('shelf');
  });
});

describe('buildUtdAttachment', () => {
  it('builds the DocumentAttachment input with the exact content and signature bytes', () => {
    const content = Buffer.from('<?xml version="1.0" encoding="windows-1251"?><Файл/>', 'latin1');
    const attachment = buildUtdAttachment(doc(content), signature);
    expect(attachment).toEqual({
      typeNamedId: 'UniversalTransferDocument',
      function: 'СЧФДОП',
      version: 'utd970_05_03_01',
      content,
      signature,
      contentPlacement: 'inline',
      fileName: 'ON_NSCHFDOPPR_x.xml',
    });
    expect(attachment.content).toBe(content);
    expect(attachment.signature).toBe(signature);
  });

  it('marks large content for shelf upload', () => {
    const attachment = buildUtdAttachment(doc(Buffer.alloc(INLINE_CONTENT_LIMIT)), signature);
    expect(attachment.contentPlacement).toBe('shelf');
  });

  it('passes CustomDocumentId through when given', () => {
    const attachment = buildUtdAttachment(doc(Buffer.from('x')), signature, {
      customDocumentId: 'upd-42',
    });
    expect(attachment.customDocumentId).toBe('upd-42');
  });

  it('rejects a signature that is not DER (CMS SignedData is a SEQUENCE)', () => {
    for (const bad of [Buffer.alloc(0), Buffer.from('MIIB', 'ascii')]) {
      expect(() => buildUtdAttachment(doc(Buffer.from('x')), bad)).toThrow(
        expect.objectContaining({ code: 'INVALID_SIGNATURE' }),
      );
    }
  });

  it('rejects empty content', () => {
    expect(() => buildUtdAttachment(doc(Buffer.alloc(0)), signature)).toThrow(UtdError);
    expect(() => buildUtdAttachment(doc(Buffer.alloc(0)), signature)).toThrow(
      expect.objectContaining({ code: 'INVALID_CONTENT' }),
    );
  });
});
