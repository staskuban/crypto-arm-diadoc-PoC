import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDotenv, requireVars } from '../src/env.ts';

test('parses KEY=VALUE, comments, blank lines and quotes', () => {
  const env = parseDotenv('# c\nA=1\n\nB="two words"\nC=\'x=y\'\nD=\n E = spaced \n');
  assert.deepEqual(env, { A: '1', B: 'two words', C: 'x=y', D: '', E: 'spaced' });
});

test('requireVars lists every missing or empty variable', () => {
  assert.throws(() => requireVars({ A: '1', B: '' }, ['A', 'B', 'C']), /B, C/);
  assert.deepEqual(requireVars({ A: '1' }, ['A']), { A: '1' });
});
