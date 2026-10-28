/**
 * Strict IP address validation and canonicalization. Canonical forms make the
 * same address correlate across sources ("2001:DB8::1" and "2001:db8:0:0::1",
 * or "::ffff:192.0.2.1" and "192.0.2.1").
 */

export function parseIPv4(text: string): [number, number, number, number] | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null; // ambiguous octal form
    const n = Number(part);
    if (n > 255) return null;
    out.push(n);
  }
  return out as [number, number, number, number];
}

export function isValidIPv4(text: string): boolean {
  return parseIPv4(text) !== null;
}

/** Parse an IPv6 address into eight 16-bit groups, or null when invalid. */
export function parseIPv6(text: string): number[] | null {
  if (text.length < 2 || text.length > 45) return null;
  const doubleColon = text.indexOf('::');
  if (doubleColon !== -1 && text.indexOf('::', doubleColon + 1) !== -1) return null;

  const parseGroups = (segment: string): number[] | null => {
    if (segment === '') return [];
    const groups = segment.split(':');
    const out: number[] = [];
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i]!;
      if (i === groups.length - 1 && g.includes('.')) {
        const v4 = parseIPv4(g);
        if (!v4) return null;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        out.push(parseInt(g, 16));
      }
    }
    return out;
  };

  if (doubleColon === -1) {
    const groups = parseGroups(text);
    return groups && groups.length === 8 ? groups : null;
  }
  const head = parseGroups(text.slice(0, doubleColon));
  const tail = parseGroups(text.slice(doubleColon + 2));
  if (!head || !tail) return null;
  // An embedded IPv4 address is only valid at the end.
  if (text.slice(0, doubleColon).includes('.')) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null;
  return [...head, ...new Array<number>(missing).fill(0), ...tail];
}

export function isValidIPv6(text: string): boolean {
  return parseIPv6(text) !== null;
}

/** RFC 5952 canonical text form. */
function formatIPv6(groups: number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

/**
 * Validate and canonicalize an IP address. Accepts bracketed IPv6 ("[::1]") and
 * strips IPv6 zone identifiers. IPv4-mapped IPv6 addresses become plain IPv4.
 * Returns undefined for anything that is not an IP address (including hostnames).
 */
export function normalizeIp(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  let t = text.trim();
  // "[2001:db8::1]:443" and "203.0.113.5:51234" (host:port, as many proxies and Go log it).
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(t);
  if (bracketed) t = bracketed[1]!;
  else {
    const v4port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(t);
    if (v4port) t = v4port[1]!;
  }
  if (t === '') return undefined;
  const v4 = parseIPv4(t);
  if (v4) return v4.join('.');
  const zone = t.indexOf('%');
  if (zone !== -1) t = t.slice(0, zone);
  const v6 = parseIPv6(t);
  if (!v6) return undefined;
  const isMapped = v6.slice(0, 5).every((g) => g === 0) && v6[5] === 0xffff;
  if (isMapped) {
    return [v6[6]! >> 8, v6[6]! & 0xff, v6[7]! >> 8, v6[7]! & 0xff].join('.');
  }
  return formatIPv6(v6);
}

export type IpClass =
  | 'public'
  | 'private'
  | 'loopback'
  | 'link-local'
  | 'documentation'
  | 'shared-cgnat'
  | 'multicast'
  | 'unspecified'
  | 'reserved'
  | 'unique-local';

export const IP_CLASS_LABELS: Record<IpClass, string> = {
  public: 'Public address',
  private: 'Private (RFC 1918)',
  loopback: 'Loopback',
  'link-local': 'Link-local',
  documentation: 'Documentation range (RFC 5737 / 3849)',
  'shared-cgnat': 'Shared address space (CGNAT)',
  multicast: 'Multicast',
  unspecified: 'Unspecified',
  reserved: 'Reserved',
  'unique-local': 'Unique local (IPv6)',
};

/**
 * Address-space context for analysts. Classification describes where an
 * address sits in the IP plan; it says nothing about intent.
 */
export function classifyIp(ip: string): IpClass {
  const v4 = parseIPv4(ip);
  if (v4) {
    const [a, b, c] = v4;
    if (a === 0) return 'unspecified';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
    if (a === 127) return 'loopback';
    if (a === 169 && b === 254) return 'link-local';
    if (a === 100 && b >= 64 && b <= 127) return 'shared-cgnat';
    if (
      (a === 192 && b === 0 && c === 2) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    ) {
      return 'documentation';
    }
    if (a >= 224 && a <= 239) return 'multicast';
    if (a >= 240) return 'reserved';
    return 'public';
  }
  const v6 = parseIPv6(ip);
  if (!v6) return 'reserved';
  if (v6.every((g) => g === 0)) return 'unspecified';
  if (v6.slice(0, 7).every((g) => g === 0) && v6[7] === 1) return 'loopback';
  const first = v6[0]!;
  if ((first & 0xffc0) === 0xfe80) return 'link-local';
  if ((first & 0xfe00) === 0xfc00) return 'unique-local';
  if ((first & 0xff00) === 0xff00) return 'multicast';
  if (first === 0x2001 && v6[1] === 0x0db8) return 'documentation';
  return 'public';
}
