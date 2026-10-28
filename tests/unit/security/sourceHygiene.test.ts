import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../../../', import.meta.url));

function files(dir: string, exts: string[]): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return files(path, exts);
    return exts.some((e) => name.endsWith(e)) ? [path] : [];
  });
}

const sources = files(join(root, 'src'), ['.ts', '.tsx', '.css']);
const all = [...sources, ...files(join(root, 'tests'), ['.ts', '.tsx'])];

describe('source hygiene', () => {
  it('contains no invisible, bidirectional or control characters (Trojan Source guard)', () => {
    const invisible =
      // eslint-disable-next-line no-control-regex
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/;
    const offenders = all
      .filter((f) => invisible.test(readFileSync(f, 'utf8')))
      .map((f) => relative(root, f));
    expect(offenders).toEqual([]);
  });

  it('never uses HTML sinks, dynamic code evaluation, persistent storage or network APIs', () => {
    const forbidden: Array<[string, RegExp]> = [
      ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
      ['innerHTML/outerHTML', /\.(inner|outer)HTML\s*=/],
      ['insertAdjacentHTML', /insertAdjacentHTML/],
      ['document.write', /document\.write/],
      ['eval', /\beval\s*\(/],
      ['new Function', /new\s+Function\s*\(/],
      ['localStorage', /\blocalStorage\b/],
      ['sessionStorage', /\bsessionStorage\b/],
      ['indexedDB', /\bindexedDB\b/],
      ['fetch', /\bfetch\s*\(/],
      ['XMLHttpRequest', /XMLHttpRequest/],
      ['WebSocket', /new\s+WebSocket/],
      ['sendBeacon', /sendBeacon/],
      ['console.log', /console\.(log|info|debug)\s*\(/],
    ];
    const hits = sources.flatMap((f) => {
      const text = readFileSync(f, 'utf8');
      return forbidden
        .filter(([, re]) => re.test(text))
        .map(([name]) => `${relative(root, f)}: ${name}`);
    });
    expect(hits).toEqual([]);
  });

  it('declares a strict Content-Security-Policy for production builds', () => {
    const config = readFileSync(join(root, 'vite.config.ts'), 'utf8');
    for (const directive of [
      "default-src 'none'",
      "script-src 'self'",
      "connect-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
    ]) {
      expect(config).toContain(directive);
    }
    expect(readFileSync(join(root, 'index.html'), 'utf8')).toContain('<!-- CSP -->');
  });
});
