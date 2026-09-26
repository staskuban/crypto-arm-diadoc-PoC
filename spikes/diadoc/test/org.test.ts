import { test } from 'node:test';
import assert from 'node:assert/strict';
import { partyFromOrganization, toBoxGuid, mainEntity } from '../src/org.ts';

test('toBoxGuid converts <hex>@diadoc.ru and keeps GUIDs', () => {
  assert.equal(toBoxGuid('09ae254c5cd0408284de7ccb46d86f82@diadoc.ru'), '09ae254c-5cd0-4082-84de-7ccb46d86f82');
  assert.equal(toBoxGuid('09AE254C-5CD0-4082-84DE-7CCB46D86F82'), '09AE254C-5CD0-4082-84DE-7CCB46D86F82');
  assert.throws(() => toBoxGuid('nope'), /box id/);
});

test('partyFromOrganization maps GetOrganization fields to УПД party data', () => {
  const p = partyFromOrganization({
    FullName: 'ООО «Тест»',
    ShortName: 'Тест',
    Inn: '1839264655',
    Kpp: '732644841',
    FnsParticipantId: '2BM-1839264655-732644841-202407101103418496883',
    Address: { RussianAddress: { Region: '66', City: 'Екатеринбург' } },
  });
  assert.deepEqual(p, {
    name: 'ООО «Тест»',
    inn: '1839264655',
    kpp: '732644841',
    fnsParticipantId: '2BM-1839264655-732644841-202407101103418496883',
    regionCode: '66',
    regionName: 'Свердловская область',
  });
});

test('partyFromOrganization fails loudly on what the УПД cannot do without', () => {
  assert.throws(() => partyFromOrganization({ FullName: 'X', Inn: '1', Kpp: '2' }), /FnsParticipantId/);
  assert.throws(() => partyFromOrganization({ FullName: 'X', Inn: '123456789012', FnsParticipantId: 'f' }), /legal entity/);
});

test('partyFromOrganization falls back to a generic region name for unknown codes', () => {
  const p = partyFromOrganization({ FullName: 'X', Inn: '1234567890', Kpp: '123456789', FnsParticipantId: 'f', Address: { RussianAddress: { Region: '99' } } });
  assert.equal(p.regionCode, '99');
  assert.equal(p.regionName, 'Субъект РФ 99');
});

test('mainEntity picks the document attachment without a parent', () => {
  const e = mainEntity({
    MessageId: 'm',
    Entities: [
      { EntityType: 'Signature', EntityId: 's', ParentEntityId: 'd' },
      { EntityType: 'Attachment', EntityId: 'd', ParentEntityId: '' },
    ],
  });
  assert.equal(e?.EntityId, 'd');
});
