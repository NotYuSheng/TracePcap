import { deviceTypeLabel, deviceTypeColor, confidenceLevel, deviceTypeIcon } from '../deviceType';

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
