import {
  deviceTypeLabel,
  deviceTypeColor,
  confidenceLevel,
  deviceTypeIcon,
  nodeIdentityKey,
} from '../deviceType';

describe('deviceTypeLabel', () => {
  it('returns human-readable label for known types', () => {
    expect(deviceTypeLabel('ROUTER')).toBe('Router');
    expect(deviceTypeLabel('MOBILE')).toBe('Mobile');
    expect(deviceTypeLabel('SERVER')).toBe('Server');
  });

  it('falls back to the raw value for unknown types', () => {
    expect(deviceTypeLabel('CUSTOM_TYPE' as never)).toBe('CUSTOM_TYPE');
  });
});

describe('deviceTypeColor', () => {
  it('returns a hex colour for known types', () => {
    expect(deviceTypeColor('ROUTER')).toBe('#f97316');
    expect(deviceTypeColor('UNKNOWN')).toBe('#6b7280');
  });

  it('returns default grey for unrecognised types', () => {
    expect(deviceTypeColor('CUSTOM' as never)).toBe('#6b7280');
  });
});

describe('confidenceLevel', () => {
  it.each([
    [100, 'Strong'],
    [75, 'Strong'],
    [74, 'Moderate'],
    [50, 'Moderate'],
    [49, 'Low'],
    [25, 'Low'],
    [24, 'Uncertain'],
    [0, 'Uncertain'],
  ])('maps %i%% to "%s"', (pct, expected) => {
    expect(confidenceLevel(pct)).toBe(expected);
  });
});

describe('deviceTypeIcon', () => {
  it('returns the correct Bootstrap icon class', () => {
    expect(deviceTypeIcon('SERVER')).toBe('bi-server');
    expect(deviceTypeIcon('DNS_SERVER')).toBe('bi-hdd-network');
  });

  it('returns question-circle for unknown types', () => {
    expect(deviceTypeIcon('CUSTOM' as never)).toBe('bi-question-circle');
  });
});

describe('nodeIdentityKey', () => {
  it('prefers the adjudicated identity label over everything else', () => {
    expect(
      nodeIdentityKey({ identityLabel: 'WEB_SERVER', deviceType: 'ROUTER', nodeType: 'router' })
    ).toBe('WEB_SERVER');
  });

  it('falls back to the machine device type when there is no identity', () => {
    expect(nodeIdentityKey({ deviceType: 'MOBILE', nodeType: 'client' })).toBe('MOBILE');
  });

  it('ignores a non-committal UNKNOWN device type', () => {
    expect(nodeIdentityKey({ deviceType: 'UNKNOWN', nodeType: 'client' })).toBe('UNKNOWN');
    expect(nodeIdentityKey({ deviceType: 'UNKNOWN', nodeType: 'l2-device' })).toBe('L2_DEVICE');
  });

  it('maps pure L2 nodes to the L2_DEVICE identity', () => {
    expect(nodeIdentityKey({ nodeType: 'l2-device' })).toBe('L2_DEVICE');
  });

  it('returns UNKNOWN for a node with no signals', () => {
    expect(nodeIdentityKey({ nodeType: 'unknown' })).toBe('UNKNOWN');
    expect(nodeIdentityKey({})).toBe('UNKNOWN');
  });

  it('collapses the old two-taxonomy overlaps to a single key (the #499/#537 fix)', () => {
    // Router: was "Router / Gateway" (nt:router) AND "Router" (dt:ROUTER) — now one key.
    expect(nodeIdentityKey({ identityLabel: 'ROUTER', nodeType: 'router', deviceType: 'ROUTER' }))
      .toBe('ROUTER');
    // Web server: was "Web Server" twice — now one key.
    expect(
      nodeIdentityKey({ identityLabel: 'WEB_SERVER', nodeType: 'web-server', deviceType: 'WEB_SERVER' })
    ).toBe('WEB_SERVER');
    // DNS server: was "DNS Server" twice — now one key.
    expect(
      nodeIdentityKey({ identityLabel: 'DNS_SERVER', nodeType: 'dns-server', deviceType: 'DNS_SERVER' })
    ).toBe('DNS_SERVER');
  });

  it('keeps the Mobile/IoT/Laptop family distinct (finer than the rendered nodeType)', () => {
    // All three render as the generic "client" nodeType but stay separate identities.
    expect(nodeIdentityKey({ deviceType: 'MOBILE', nodeType: 'client' })).toBe('MOBILE');
    expect(nodeIdentityKey({ deviceType: 'IOT', nodeType: 'client' })).toBe('IOT');
    expect(nodeIdentityKey({ deviceType: 'LAPTOP_DESKTOP', nodeType: 'client' })).toBe('LAPTOP_DESKTOP');
  });

  it('renders every resolved key through the display helpers with no missing config', () => {
    for (const key of ['ROUTER', 'MOBILE', 'IOT', 'WEB_SERVER', 'DNS_SERVER', 'L2_DEVICE', 'UNKNOWN']) {
      expect(deviceTypeLabel(key)).not.toBe(key === 'UNKNOWN' ? '' : key); // has a real label
      expect(deviceTypeColor(key)).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });
});
