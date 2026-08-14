import { describe, it, expect } from 'vitest';
import { isRfc1918, isPrivateIp, ipInCidr } from '../ipClassification';
import type { CustomPrivateRange } from '@/features/cluster/types/customPrivateRange.types';

describe('isRfc1918', () => {
  it('recognises RFC1918 / loopback / link-local IPv4', () => {
    for (const ip of ['10.0.1.5', '172.16.0.1', '172.31.255.254', '192.168.1.1', '127.0.0.1', '169.254.1.1']) {
      expect(isRfc1918(ip)).toBe(true);
    }
  });

  it('rejects public IPv4 and 172.15/172.32 (just outside the private block)', () => {
    for (const ip of ['8.8.8.8', '203.0.113.1', '172.15.0.1', '172.32.0.1']) {
      expect(isRfc1918(ip)).toBe(false);
    }
  });

  it('recognises IPv6 ULA / link-local / loopback', () => {
    for (const ip of ['fc00::1', 'fd12:3456::1', 'fe80::1', '::1']) {
      expect(isRfc1918(ip)).toBe(true);
    }
    expect(isRfc1918('2001:4860:4860::8888')).toBe(false);
  });
});

describe('link-local matches the backend', () => {
  // fe80::/10 spans fe80–febf. The regex used to test `fe80:`, one hextet of it, so feb0::1
  // read as public here and internal in IpLocality — the same host classified differently
  // depending on which side of the wire answered.
  it.each(['fe80::1', 'fe90::1', 'fea0::1', 'febf::1', 'FEB0::1'])('treats %s as internal', ip => {
    expect(isRfc1918(ip)).toBe(true)
  })

  it.each(['fec0::1', 'ff02::1', '2001:db8::1'])('leaves %s external', ip => {
    expect(isRfc1918(ip)).toBe(false)
  })
})

describe('ipInCidr', () => {
  it('matches inside an IPv4 CIDR and rejects outside', () => {
    expect(ipInCidr('10.0.1.5', '10.0.0.0/16')).toBe(true);
    expect(ipInCidr('10.1.1.5', '10.0.0.0/16')).toBe(false);
  });

  it('never matches when either side is IPv6', () => {
    expect(ipInCidr('fc00::1', '10.0.0.0/8')).toBe(false);
    expect(ipInCidr('10.0.0.1', 'fc00::/7')).toBe(false);
  });
});

describe('isPrivateIp with custom overrides', () => {
  const ranges: CustomPrivateRange[] = [
    { id: 1, cidr: '203.0.113.0/24', classification: 'PRIVATE' }, // force a public block internal
    { id: 2, cidr: '10.9.0.0/16', classification: 'PUBLIC' },     // force a 10.x block external
  ];

  it('falls back to the RFC1918 heuristic with no ranges', () => {
    expect(isPrivateIp('10.0.1.5')).toBe(true);
    expect(isPrivateIp('8.8.8.8')).toBe(false);
  });

  it('lets an override win in either direction', () => {
    expect(isPrivateIp('203.0.113.10', ranges)).toBe(true);  // public → forced private
    expect(isPrivateIp('10.9.1.1', ranges)).toBe(false);     // private → forced public
  });

  it('uses the heuristic for addresses no override covers', () => {
    expect(isPrivateIp('10.0.1.5', ranges)).toBe(true);
    expect(isPrivateIp('1.1.1.1', ranges)).toBe(false);
  });
});
