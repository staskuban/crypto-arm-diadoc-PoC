// windows-1251 encoder. Node's TextDecoder knows the codepage, TextEncoder does not,
// so the reverse table is derived from the decoder instead of being hand-written.
const decoder = new TextDecoder('windows-1251');
const table = new Map<string, number>();
for (let b = 0x80; b <= 0xff; b++) {
  const ch = decoder.decode(Uint8Array.of(b));
  if (ch !== '�') table.set(ch, b);
}

export function encodeCp1251(text: string): Buffer {
  const out = Buffer.alloc(text.length);
  let i = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    const b = code < 0x80 ? code : table.get(ch);
    if (b === undefined) {
      throw new Error(`Character ${JSON.stringify(ch)} (U+${code.toString(16).toUpperCase()}) is not representable in windows-1251`);
    }
    out[i++] = b;
  }
  return out.subarray(0, i);
}
