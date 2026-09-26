import { fileURLToPath } from 'node:url';

import { ESLint } from 'eslint';
import { getFileInfo } from 'prettier';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));

// Local Claude Code files (e.g. the git-ignored .claude/settings.local.json) are
// not project code: `npm run lint` must not check them (F20).
describe('lint ignores', () => {
  it('prettier ignores .claude/', async () => {
    const info = await getFileInfo(`${root}.claude/settings.local.json`, {
      ignorePath: `${root}.prettierignore`,
    });
    expect(info.ignored).toBe(true);
  });

  it('eslint ignores .claude/', async () => {
    const eslint = new ESLint({ cwd: root });
    expect(await eslint.isPathIgnored(`${root}.claude/hooks/hook.js`)).toBe(true);
  });

  it('both still check source files', async () => {
    const info = await getFileInfo(`${root}src/cli.ts`, { ignorePath: `${root}.prettierignore` });
    expect(info.ignored).toBe(false);
    expect(await new ESLint({ cwd: root }).isPathIgnored(`${root}src/cli.ts`)).toBe(false);
  });
});
