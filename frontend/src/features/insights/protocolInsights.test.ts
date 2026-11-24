import { describe, expect, it } from 'vitest';
import { worthALook } from './protocolInsights';

// What the STRRAT exercise's Overview lists (2024-07-30).
const STRRAT_L7 = ['BROWSER', 'CLDAP', 'DCERPC', 'DNS', 'HTTP', 'JSON', 'KERBEROS', 'LLMNR', 'MDNS', 'NBNS', 'NBSS', 'NTP', 'SMB', 'SMB2', 'SPNEGO-KRB5', 'SSDP', 'TLS'];
const STRRAT_APPS = ['DCERPC', 'DNS', 'Github', 'HTTP', 'Kerberos', 'LDAP', 'LLMNR', 'MDNS', 'Microsoft', 'NetBIOS', 'NTP', 'SMBv1', 'SMBv23', 'TLS'];

describe('worthALook (#1292)', () => {
  it('names Kerberos and LDAP for who is signed in on the STRRAT capture, answered there', () => {
    const groups = worthALook(STRRAT_L7, STRRAT_APPS, ['victim', 'signed-in-user', 'malware', 'c2']);
    const who = groups.find(g => g.key === 'who')!;
    expect(who.status).toBe('answered');
    expect(who.items.map(i => i.label)).toEqual(['Kerberos', 'LDAP']);
    // nDPI's names: tshark's CLDAP would miss LDAP over TCP, its SPNEGO-KRB5 is Kerberos inside SMB.
    expect(who.items[0].query).toBe('apps=Kerberos');
    expect(who.items[1].query).toBe('apps=LDAP');
    // TLS by tshark's name: nDPI names most TLS sessions by service.
    const c2 = groups.find(g => g.key === 'c2')!;
    expect(c2.items.find(i => i.label === 'TLS')?.query).toBe('l7Protocols=TLS');
  });

  it('marks a question nothing answered as open, and leaves out questions with no protocol present', () => {
    const groups = worthALook(STRRAT_L7, STRRAT_APPS, ['c2']);
    expect(groups.find(g => g.key === 'lateral')?.status).toBe('open');
    expect(groups.find(g => g.key === 'remote')).toBeUndefined(); // no remote-control tool in it
    expect(groups.find(g => g.key === 'leaving')).toBeUndefined(); // no mail, no FTP
    expect(groups.find(g => g.key === 'machine')?.status).toBe('context');
  });

  it('finds a remote-control tool by its nDPI name', () => {
    const groups = worthALook([], ['AnyDesk'], []);
    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({ key: 'remote', status: 'open' });
    expect(groups[0].items[0].query).toBe('apps=AnyDesk');
  });

  it('calls nothing open before the investigation is in, and a question with ruled-out candidates ruled out', () => {
    expect(worthALook(STRRAT_L7, STRRAT_APPS, null).filter(g => g.key !== 'machine').map(g => g.status))
      .toEqual(expect.arrayContaining(['unknown']));
    expect(worthALook(STRRAT_L7, STRRAT_APPS, null).some(g => g.status === 'open')).toBe(false);
    expect(worthALook(STRRAT_L7, STRRAT_APPS, [], ['kerberos-attack']).find(g => g.key === 'accounts')?.status).toBe('ruled-out');
  });

  it('doesn’t count the victim as an answer for command and control', () => {
    expect(worthALook(STRRAT_L7, STRRAT_APPS, ['victim']).find(g => g.key === 'c2')?.status).toBe('open');
  });

  it('returns nothing for a capture with none of the catalogue’s protocols', () => {
    expect(worthALook(['NTP', 'SSDP'], ['Microsoft'], [])).toEqual([]);
  });
});
