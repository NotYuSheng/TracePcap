import { describe, it, expect } from 'vitest';
import { isRfc1918, isPrivateIp, ipInCidr, isUnspecified, isHostAddress, parseIp, formatIp, networkOf, compareIps } from '../ipClassification';
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

  it('never matches across families', () => {
    expect(ipInCidr('fc00::1', '10.0.0.0/8')).toBe(false);
    expect(ipInCidr('10.0.0.1', 'fc00::/7')).toBe(false);
    expect(ipInCidr('::1', '0.0.0.0/0')).toBe(false);
  });

  it('matches IPv6, compressed or not (#1354)', () => {
    expect(ipInCidr('fd00::1:0:0:0:9', 'fd00:0:0:1::/64')).toBe(true);
    expect(ipInCidr('FD00:0000:0000:0001:abcd::1', 'fd00:0:0:1::/64')).toBe(true);
    expect(ipInCidr('fd00:0:0:2::1', 'fd00:0:0:1::/64')).toBe(false);
    expect(ipInCidr('febf::1%eth0', 'fe80::/10')).toBe(true);
    expect(ipInCidr('fec0::1', 'fe80::/10')).toBe(false);
  });

  it('reads saved rows as the backend does', () => {
    expect(ipInCidr('10.1.2.9', '10.1.2.3/24')).toBe(true); // host bits ignored
    expect(ipInCidr('10.0.0.5', '10.0.0.5')).toBe(true); // a bare address is one host
    expect(ipInCidr('10.0.0.6', '10.0.0.5')).toBe(false);
    expect(ipInCidr('10.0.0.1', '10.0.0.0/33')).toBe(false);
    expect(ipInCidr('10.0.0.1', 'gw.corp/24')).toBe(false);
    expect(ipInCidr('aa:bb:cc:dd:ee:ff', '10.0.0.0/8')).toBe(false);
  });
});

describe('parseIp / formatIp / networkOf / compareIps', () => {
  it('parses IPv4 and IPv6 literals only', () => {
    expect(parseIp('10.0.0.1')).toEqual([10, 0, 0, 1]);
    expect(parseIp('::')).toEqual(new Array(16).fill(0));
    expect(parseIp('::ffff:10.0.0.1')).toEqual([10, 0, 0, 1]); // mapped reads as IPv4
    expect(parseIp('64:ff9b::192.0.2.1')?.slice(12)).toEqual([192, 0, 2, 1]);
    for (const bad of ['10.0.0.256', '10.1', '1::2::3', '1:2:3:4:5:6:7:8:9', ':1', '1.2.3.4::', '1.2.3.4:1::', 'aa:bb:cc:dd:ee:ff', 'host', '', null]) {
      expect(parseIp(bad)).toBeNull();
    }
  });

  it('writes IPv6 in RFC 5952 form, as the backend does', () => {
    expect(formatIp(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001')!)).toBe('2001:db8::1');
    expect(formatIp(parseIp('2001:db8:0:1:0:0:0:1')!)).toBe('2001:db8:0:1::1');
    expect(formatIp(parseIp('1:0:0:2:0:0:0:3')!)).toBe('1:0:0:2::3');
    expect(formatIp(parseIp('1:0:2:3:4:5:6:7')!)).toBe('1:0:2:3:4:5:6:7');
    expect(formatIp([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1])).toBe('::ffff:10.0.0.1');
  });

  it('names the network an address is on', () => {
    expect(networkOf('10.1.2.3', 24)).toBe('10.1.2.0/24');
    expect(networkOf('fe80::1', 64)).toBe('fe80::/64');
    expect(networkOf('fe80::2', 64)).toBe('fe80::/64');
    expect(networkOf('nope', 24)).toBeNull();
  });

  it('sorts by value, IPv4 first', () => {
    expect(['10.0.0.10', 'fe80::1', '10.0.0.9', 'x', '::1'].sort(compareIps)).toEqual(['10.0.0.9', '10.0.0.10', '::1', 'fe80::1', 'x']);
  });
});

describe('isPrivateIp with an IPv6 custom range (#1354)', () => {
  it('honours it, as the Investigation does', () => {
    const v6: CustomPrivateRange[] = [{ id: 3, cidr: '2001:db8::/32', classification: 'PRIVATE' }];
    expect(isPrivateIp('2001:db8:1::5', v6)).toBe(true);
    expect(isPrivateIp('2001:db8:1::5')).toBe(false);
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

describe('isUnspecified / isHostAddress (as the backend IpLocality answers them)', () => {
  it('reads 0.0.0.0 and :: as a sender with no address yet', () => {
    expect(isUnspecified('0.0.0.0')).toBe(true);
    expect(isUnspecified(' :: ')).toBe(true);
    expect(isUnspecified('255.255.255.255')).toBe(false);
  });

  it('says whether one machine can hold the address', () => {
    expect(isHostAddress('10.0.0.5')).toBe(true);
    expect(isHostAddress('fe80::1')).toBe(true);
    expect(isHostAddress('0.0.0.0')).toBe(false);
    expect(isHostAddress('255.255.255.255')).toBe(false);
    expect(isHostAddress('224.0.0.251')).toBe(false);
    expect(isHostAddress('240.0.0.1')).toBe(false); // reserved
    expect(isHostAddress('ff02::fb')).toBe(false);
    expect(isHostAddress('FF:FF:FF:FF:FF:FF')).toBe(false);
    expect(isHostAddress('not-an-ip')).toBe(true); // unparseable: callers keep treating it as a host
    expect(isHostAddress('300.0.0.1')).toBe(true); // an octet past 255 is unparseable, as on the backend
    expect(isHostAddress(undefined)).toBe(false);
    expect(isUnspecified(null)).toBe(false);
  });
});
