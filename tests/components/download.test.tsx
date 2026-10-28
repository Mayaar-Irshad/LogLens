import { afterEach, describe, expect, it, vi } from 'vitest';
import { downloadText } from '../../src/utils/download';

describe('downloadText', () => {
  afterEach(() => vi.restoreAllMocks());

  it('downloads via a temporary object URL and revokes it', async () => {
    const created: Blob[] = [];
    const create = vi.fn((b: Blob) => {
      created.push(b);
      return 'blob:loglens/1';
    });
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    downloadText('loglens-report.json', '{"a":1}', 'application/json');

    expect(click).toHaveBeenCalledTimes(1);
    expect(created[0]!.type).toBe('application/json;charset=utf-8');
    expect(await created[0]!.text()).toBe('{"a":1}');
    expect(document.querySelector('a[download]')).toBeNull();
    await new Promise((r) => setTimeout(r, 0));
    expect(revoke).toHaveBeenCalledWith('blob:loglens/1');
  });
});
