import { axisFacts, detectAxisConflict, AXIS_ORDER, AXIS_META } from '../classificationAxes';
import type { NodeData } from '../types';

/** Minimal NodeData factory — only the fields the axes read matter. */
function node(overrides: Partial<NodeData>): NodeData {
  return {
    ip: '10.0.0.1',
    packetsSent: 0,
    packetsReceived: 0,
    bytesSent: 0,
    bytesReceived: 0,
    totalBytes: 0,
    role: 'unknown',
    protocols: [],
    connections: 0,
    nodeType: 'unknown',
    nodeTypeEvidence: { ndpiApps: [] },
    ...overrides,
  } as NodeData;
}

describe('axisFacts — hardware (physical fingerprint, never the device type)', () => {
  it('lists the OUI manufacturer and observed TTL', () => {
    const n = node({ manufacturer: 'Belkin International Inc.', ttl: 63 });
    expect(axisFacts(n, 'hardware')).toEqual([
      'MAC OUI manufacturer: Belkin International Inc.',
      'Observed TTL: 63',
    ]);
  });

  it('lists whichever fingerprint fact exists on its own', () => {
    expect(axisFacts(node({ ttl: 128 }), 'hardware')).toEqual(['Observed TTL: 128']);
    expect(axisFacts(node({ manufacturer: 'Cisco' }), 'hardware')).toEqual([
      'MAC OUI manufacturer: Cisco',
    ]);
  });

  it('is empty when no fingerprint was observed', () => {
    expect(axisFacts(node({}), 'hardware')).toEqual([]);
  });

  it('never echoes the device type (that is the Identity verdict, not evidence)', () => {
    const n = node({ deviceType: 'MOBILE', deviceConfidence: 33 });
    expect(axisFacts(n, 'hardware')).toEqual([]);
  });
});

describe('axisFacts — service (what it does on the wire)', () => {
  it('states confirmed service roles', () => {
    expect(axisFacts(node({ serviceRoles: ['dns', 'web'] }), 'service')).toEqual([
      'Observed serving DNS (confirmed from its responses)',
      'Observed serving WEB (confirmed from its responses)',
    ]);
  });

  it('falls back to nDPI-identified apps when no role was detected', () => {
    const n = node({ nodeTypeEvidence: { ndpiApps: ['WHATSAPP'] } });
    expect(axisFacts(n, 'service')).toEqual(['App identified in its traffic: WHATSAPP']);
  });

  it('prefers roles over the nDPI fallback', () => {
    const n = node({ serviceRoles: ['dns'], nodeTypeEvidence: { ndpiApps: ['WHATSAPP'] } });
    expect(axisFacts(n, 'service')).toEqual(['Observed serving DNS (confirmed from its responses)']);
  });

  it('is empty when nothing was observed', () => {
    expect(axisFacts(node({}), 'service')).toEqual([]);
  });
});

describe('axisFacts — behaviour (measured who-opened-it counts)', () => {
  it('states opened and answered counts', () => {
    const n = node({ initiatedConversations: 12, answeredConversations: 3 });
    expect(axisFacts(n, 'behaviour')).toEqual([
      'Opened 12 connections',
      'Answered 3 connections opened by peers',
    ]);
  });

  it('singularises a count of one', () => {
    const n = node({ initiatedConversations: 1, answeredConversations: 1 });
    expect(axisFacts(n, 'behaviour')).toEqual([
      'Opened 1 connection',
      'Answered 1 connection opened by peers',
    ]);
  });

  it('calls out a host that only ever opened connections', () => {
    const n = node({ initiatedConversations: 5 });
    expect(axisFacts(n, 'behaviour')).toEqual([
      'Opened 5 connections',
      'Never seen answering a connection',
    ]);
  });

  it('is empty when no initiator was ever measured (unknown, not guessed)', () => {
    expect(axisFacts(node({}), 'behaviour')).toEqual([]);
  });

  it('never reads the identity candidates (vote reasons are not behaviour facts)', () => {
    const n = node({
      identityCandidates: [
        { label: 'SERVER', source: 'classification', score: 15, reasons: ['Never initiates connections → +15'] },
      ],
    });
    expect(axisFacts(n, 'behaviour')).toEqual([]);
  });
});

describe('AXIS_ORDER / AXIS_META', () => {
  it('renders the three axes in Hardware/Service/Behaviour order', () => {
    expect(AXIS_ORDER).toEqual(['hardware', 'service', 'behaviour']);
    expect(AXIS_ORDER.map(k => AXIS_META[k].label)).toEqual([
      'Hardware',
      'Ports / Service',
      'Behaviour',
    ]);
  });
});

describe('detectAxisConflict (observed service vs Identity verdict)', () => {
  it('flags an exposed *-server service on an endpoint verdict (the #499 case)', () => {
    const { conflict, detail } = detectAxisConflict(
      node({ nodeType: 'web-server', deviceType: 'IOT' }),
    );
    expect(conflict).toBe(true);
    expect(detail).toContain('Web Server');
    expect(detail).toContain('IoT');
  });

  it('does not flag when service and verdict agree (router + ROUTER)', () => {
    expect(detectAxisConflict(node({ nodeType: 'router', deviceType: 'ROUTER' })).conflict).toBe(
      false,
    );
  });

  it('does not flag a server service on a server verdict (both "server" kind)', () => {
    expect(
      detectAxisConflict(node({ nodeType: 'web-server', deviceType: 'SERVER' })).conflict,
    ).toBe(false);
    expect(
      detectAxisConflict(node({ nodeType: 'dns-server', deviceType: 'WEB_SERVER' })).conflict,
    ).toBe(false);
  });

  it('flags a router service on a server verdict (the inverse case)', () => {
    const { conflict, detail } = detectAxisConflict(
      node({ nodeType: 'router', deviceType: 'SERVER' }),
    );
    expect(conflict).toBe(true);
    expect(detail).toContain('Router / Gateway');
    expect(detail).toContain('Server');
  });

  it('does not flag when no service is exposed', () => {
    expect(detectAxisConflict(node({ nodeType: 'client', deviceType: 'IOT' })).conflict).toBe(
      false,
    );
  });

  it('does not flag when the verdict is unknown', () => {
    expect(detectAxisConflict(node({ nodeType: 'web-server' })).conflict).toBe(false);
  });
});
