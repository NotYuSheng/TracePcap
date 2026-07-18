import { buildProtocolLegend, PROTOCOL_COLORS, DEFAULT_EDGE_COLOR } from '../constants';

describe('buildProtocolLegend', () => {
  it('lists only protocols present in the graph, in PROTOCOL_COLORS order', () => {
    // Deliberately out of definition order on input.
    const { entries } = buildProtocolLegend(['UDP', 'HTTP', 'DNS']);
    expect(entries).toEqual([
      { color: PROTOCOL_COLORS.HTTP, label: 'HTTP' },
      { color: PROTOCOL_COLORS.DNS, label: 'DNS' },
      { color: PROTOCOL_COLORS.UDP, label: 'UDP' },
    ]);
  });

  it('is case-insensitive on the protocol string', () => {
    const { entries } = buildProtocolLegend(['http', 'Dns']);
    expect(entries.map(e => e.label)).toEqual(['HTTP', 'DNS']);
  });

  it('collapses protocols sharing a colour into one entry via PROTOCOL_LABELS', () => {
    const { entries } = buildProtocolLegend(['HTTPS', 'TLS']);
    expect(entries).toEqual([{ color: PROTOCOL_COLORS.HTTPS, label: 'HTTPS/TLS' }]);
  });

  it('collapses STP/RSTP into a single "STP/RSTP" entry', () => {
    const { entries } = buildProtocolLegend(['RSTP', 'STP']);
    expect(entries).toEqual([{ color: PROTOCOL_COLORS.STP, label: 'STP/RSTP' }]);
  });

  it('labels a shared-colour entry from the first present protocol', () => {
    // Only TLS present (no HTTPS) → the entry reflects what is actually there.
    const { entries } = buildProtocolLegend(['TLS']);
    expect(entries).toEqual([{ color: PROTOCOL_COLORS.TLS, label: 'TLS' }]);
  });

  it('flags unmapped protocols so the grey "Other" swatch can be shown', () => {
    const { entries, hasUnmapped } = buildProtocolLegend(['HTTP', 'GQUIC', '']);
    expect(hasUnmapped).toBe(true);
    expect(entries).toEqual([{ color: PROTOCOL_COLORS.HTTP, label: 'HTTP' }]);
    // Sanity: the fallback colour those edges render with.
    expect(DEFAULT_EDGE_COLOR).toBeDefined();
  });

  it('does not flag unmapped when every protocol is known', () => {
    const { hasUnmapped } = buildProtocolLegend(['TCP', 'UDP']);
    expect(hasUnmapped).toBe(false);
  });

  it('returns an empty legend for no edges', () => {
    expect(buildProtocolLegend([])).toEqual({ entries: [], hasUnmapped: false });
  });
});
