import {
  buildProtocolLegend,
  getProtocolColor,
  normalizeProtocol,
  PROTOCOL_COLORS,
  DEFAULT_EDGE_COLOR,
} from '../constants';

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

  it('folds version-suffixed variants into their base entry (not a grey Other)', () => {
    const { entries, hasUnmapped } = buildProtocolLegend(['TLSv1.2', 'TLSv1.3', 'SSHv2', 'IGMPv3']);
    expect(hasUnmapped).toBe(false);
    expect(entries).toEqual([
      // Only TLS present (no HTTPS), so the shared #3498db entry is labelled "TLS".
      { color: PROTOCOL_COLORS.TLS, label: 'TLS' },
      { color: PROTOCOL_COLORS.IGMP, label: 'IGMP' },
      { color: PROTOCOL_COLORS.SSH, label: 'SSH' },
    ]);
  });
});

describe('normalizeProtocol', () => {
  it('returns an exact curated match unchanged', () => {
    expect(normalizeProtocol('icmpv6')).toBe('ICMPV6'); // distinct entry, not folded to ICMP
    expect(normalizeProtocol('RSTP')).toBe('RSTP');
  });

  it('resolves explicit aliases', () => {
    expect(normalizeProtocol('SSL')).toBe('TLS');
    expect(normalizeProtocol('SIP/SDP')).toBe('SIP');
    expect(normalizeProtocol('FTP-DATA')).toBe('FTP');
  });

  it('strips a trailing version suffix and folds to the base', () => {
    expect(normalizeProtocol('TLSv1.2')).toBe('TLS');
    expect(normalizeProtocol('SSHv2')).toBe('SSH');
    expect(normalizeProtocol('IGMPv3')).toBe('IGMP');
    expect(normalizeProtocol('SMB2')).toBe('SMB');
  });

  it('leaves pure-numeric / raw-ethertype names untouched (stays grey)', () => {
    expect(normalizeProtocol('802.11')).toBe('802.11');
    expect(normalizeProtocol('0X5E00')).toBe('0X5E00');
    expect(getProtocolColor('0X5E00')).toBe(DEFAULT_EDGE_COLOR);
  });

  it('drives getProtocolColor so a variant paints its base colour', () => {
    expect(getProtocolColor('TLSv1.3')).toBe(PROTOCOL_COLORS.TLS);
    expect(getProtocolColor('SSHv2')).toBe(PROTOCOL_COLORS.SSH);
    expect(getProtocolColor('WHOIS')).toBe(DEFAULT_EDGE_COLOR); // genuinely unmapped
  });
});

describe('PROTOCOL_COLORS palette', () => {
  it('gives every non-aliased protocol a unique colour (legend groups by colour)', () => {
    // HTTPS/TLS and STP/RSTP and ICMP/ICMPV6 deliberately share; everything else must be unique.
    const sharedByDesign = new Set(['TLS', 'RSTP', 'ICMPV6']);
    const seen = new Map<string, string>();
    for (const [proto, color] of Object.entries(PROTOCOL_COLORS)) {
      if (sharedByDesign.has(proto)) continue;
      const prev = seen.get(color);
      expect(prev, `${proto} shares ${color} with ${prev}`).toBeUndefined();
      seen.set(color, proto);
    }
  });
});
