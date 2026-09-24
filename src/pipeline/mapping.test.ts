import { describe, expect, it } from 'vitest';

import type { UtdAttachmentInput } from '../utd/index.js';
import { toDocumentAttachment, toMessagePrototype } from './attachment.js';
import { classifyConflict } from './conflict.js';
import { docflowOutcome } from './status.js';

const attachment: UtdAttachmentInput = {
  typeNamedId: 'UniversalTransferDocument',
  function: 'СЧФ',
  version: 'utd970_05_03_01',
  content: Buffer.from('xml'),
  signature: Buffer.from([0x30, 0x00]),
  contentPlacement: 'inline',
  fileName: 'f.xml',
  customDocumentId: 'c-1',
};

describe('toDocumentAttachment', () => {
  it('maps inline content', () => {
    expect(toDocumentAttachment(attachment)).toEqual({
      TypeNamedId: 'UniversalTransferDocument',
      Function: 'СЧФ',
      Version: 'utd970_05_03_01',
      CustomDocumentId: 'c-1',
      SignedContent: { Content: attachment.content, Signature: attachment.signature },
    });
  });

  it('maps shelf content to NameOnShelf and insists on a name', () => {
    const shelf = { ...attachment, contentPlacement: 'shelf' } as const;
    expect(toDocumentAttachment(shelf, 'dd-1').SignedContent).toEqual({
      NameOnShelf: 'dd-1',
      Signature: attachment.signature,
    });
    expect(() => toDocumentAttachment(shelf)).toThrow(/needs a NameOnShelf/);
    expect(() => toDocumentAttachment(attachment, 'dd-1')).toThrow(/must not/);
  });

  it('builds the CanPostMessage prototype', () => {
    expect(toMessagePrototype('a', 'b', attachment)).toEqual({
      FromBoxId: 'a',
      ToBoxId: 'b',
      DocumentPrototypes: [
        {
          TypeNamedId: 'UniversalTransferDocument',
          Function: 'СЧФ',
          Version: 'utd970_05_03_01',
          CustomDocumentId: 'c-1',
        },
      ],
    });
  });
});

describe('classifyConflict (unverified texts, D4)', () => {
  it.each([
    ['Document is a duplicate of an already posted one', 'duplicate'],
    ['Документ уже был отправлен', 'duplicate'],
    ['Recipient Sociability settings forbid this', 'forbidden'],
    ['Контрагент не разрешает получение документов', 'forbidden'],
    ['Отправка запрещена: уже отправлено', 'forbidden'],
    ['Conflict', 'unknown'],
    ['', 'unknown'],
  ])('%j → %s', (body, kind) => {
    expect(classifyConflict(body)).toBe(kind);
  });
});

describe('docflowOutcome', () => {
  it.each([
    [undefined, 'pending'],
    [{}, 'pending'],
    [{ PrimaryStatus: { Severity: 'Info' } }, 'pending'],
    [{ PrimaryStatus: { Severity: 'Warning' } }, 'pending'],
    [{ PrimaryStatus: { Severity: 'Success' } }, 'success'],
    [{ PrimaryStatus: { Severity: 'Error' } }, 'error'],
    [{ PrimaryStatus: { Severity: 'Success' }, SecondaryStatus: { Severity: 'Error' } }, 'error'],
  ])('%j → %s', (status, outcome) => {
    expect(docflowOutcome(status)).toBe(outcome);
  });
});
