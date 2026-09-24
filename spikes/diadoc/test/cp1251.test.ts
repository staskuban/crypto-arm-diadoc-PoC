import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeCp1251 } from '../src/cp1251.ts';

test('encodes ASCII, Cyrillic, Ёё and № to windows-1251 bytes', () => {
  const bytes = encodeCp1251('Aя Ё ё №');
  assert.deepEqual([...bytes], [0x41, 0xff, 0x20, 0xa8, 0x20, 0xb8, 0x20, 0xb9]);
});

test('round-trips through TextDecoder("windows-1251")', () => {
  const text = 'Счет-фактура № 1 «тест» — ИНН 7707083893';
  assert.equal(new TextDecoder('windows-1251').decode(encodeCp1251(text)), text);
});

test('throws on characters that windows-1251 cannot represent', () => {
  assert.throws(() => encodeCp1251('中'), /windows-1251/);
});
