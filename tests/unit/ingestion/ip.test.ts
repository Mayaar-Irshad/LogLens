import { describe, expect, it } from 'vitest';
import {
  classifyIp,
  isValidIPv4,
  isValidIPv6,
  normalizeIp,
} from '../../../src/features/log-ingestion/normalization/ip';

describe('IPv4 validation', () => {
  it.each(['0.0.0.0', '192.0.2.1', '255.255.255.255', '10.0.0.1'])('accepts %s', (ip) => {
    expect(isValidIPv4(ip)).toBe(true);
  });
  it.each(['256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4', 'a.b.c.d', '1.2.3.-4', ''])(
    'rejects %s',
    (ip) => {
      expect(isValidIPv4(ip)).toBe(false);
    },
  );
});

describe('IPv6 validation', () => {
  it.each([
    '::1',
    '::',
    '2001:db8::1',
    '2001:0db8:0000:0000:0000:ff00:0042:8329',
    'fe80::1',
    '::ffff:192.0.2.1',
  ])('accepts %s', (ip) => {
    expect(isValidIPv6(ip)).toBe(true);
  });
  it.each(['2001:db8:::1', '1::2::3', '12345::1', 'gggg::1', '1:2:3:4:5:6:7:8:9', '192.0.2.1::'])(
    'rejects %s',
    (ip) => {
      expect(isValidIPv6(ip)).toBe(false);
    },
  );
});

describe('normalizeIp', () => {
  it('canonicalizes IPv6 per RFC 5952 so equivalent forms correlate', () => {
    expect(normalizeIp('2001:DB8:0:0::1')).toBe('2001:db8::1');
    expect(normalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1');
    expect(normalizeIp('2001:db8:0:1:0:0:0:1')).toBe('2001:db8:0:1::1');
    expect(normalizeIp('[2001:db8::5]')).toBe('2001:db8::5');
    expect(normalizeIp('fe80::1%eth0')).toBe('fe80::1');
  });

  it('maps IPv4-mapped IPv6 to IPv4', () => {
    expect(normalizeIp('::ffff:192.0.2.1')).toBe('192.0.2.1');
    expect(normalizeIp('::ffff:c000:0201')).toBe('192.0.2.1');
  });

  it('returns undefined for hostnames and garbage', () => {
    expect(normalizeIp('example.test')).toBeUndefined();
    expect(normalizeIp('<script>')).toBeUndefined();
    expect(normalizeIp('')).toBeUndefined();
    expect(normalizeIp(undefined)).toBeUndefined();
  });
});

describe('classifyIp', () => {
  it.each([
    ['10.1.2.3', 'private'],
    ['172.16.0.1', 'private'],
    ['172.32.0.1', 'public'],
    ['192.168.1.1', 'private'],
    ['127.0.0.1', 'loopback'],
    ['169.254.1.1', 'link-local'],
    ['100.64.0.1', 'shared-cgnat'],
    ['192.0.2.1', 'documentation'],
    ['198.51.100.1', 'documentation'],
    ['203.0.113.1', 'documentation'],
    ['224.0.0.1', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['0.0.0.0', 'unspecified'],
    ['8.8.8.8', 'public'],
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fe80::1', 'link-local'],
    ['fd00::1', 'unique-local'],
    ['ff02::1', 'multicast'],
    ['2001:db8::1', 'documentation'],
    ['2606:4700::1111', 'public'],
  ])('%s is %s', (ip, cls) => {
    expect(classifyIp(ip)).toBe(cls);
  });
});
