import type { AuthDetails, HttpDetails, NormalizedEvent } from '../../src/types/events';

export const T0 = Date.UTC(2026, 9, 27, 10, 0, 0);
export const MIN = 60_000;
export const SEC = 1000;

type Spec = Partial<Omit<NormalizedEvent, 'id'>>;

/** Assign sequential ids (= array index) and sensible defaults to event specs. */
export function build(specs: Spec[]): NormalizedEvent[] {
  return specs.map((s, id) => ({
    line: id + 1,
    format: s.http ? 'apache' : 'linux-auth',
    category: 'other',
    action: 'event',
    raw: `synthetic event ${id}`,
    status: 'parsed',
    ...s,
    id,
  }));
}

export const fail = (
  t: number | undefined,
  ip?: string,
  user?: string,
  auth: Partial<AuthDetails> = {},
): Spec => ({
  category: 'authentication',
  action: 'ssh_login_failed',
  ...(t !== undefined ? { timestamp: t } : {}),
  ...(ip ? { sourceIp: ip } : {}),
  ...(user ? { username: user } : {}),
  auth: { outcome: 'failure', method: 'password', ...auth },
});

export const ok = (t: number, ip?: string, user?: string): Spec => ({
  category: 'authentication',
  action: 'ssh_login_success',
  timestamp: t,
  ...(ip ? { sourceIp: ip } : {}),
  ...(user ? { username: user } : {}),
  auth: { outcome: 'success', method: 'password' },
});

export const req = (
  t: number | undefined,
  ip: string,
  path: string,
  status: number,
  http: Partial<HttpDetails> = {},
): Spec => {
  const q = path.indexOf('?');
  return {
    category: 'web',
    action: 'http_request',
    ...(t !== undefined ? { timestamp: t } : {}),
    sourceIp: ip,
    http: {
      method: 'GET',
      path: q === -1 ? path : path.slice(0, q),
      ...(q === -1 ? {} : { query: path.slice(q + 1) }),
      status,
      ...http,
    },
  };
};

export const times = (n: number, start: number, step: number): number[] =>
  Array.from({ length: n }, (_, i) => start + i * step);
