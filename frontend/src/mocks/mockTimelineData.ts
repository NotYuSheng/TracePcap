import type { TimelineDataPoint } from '@/types';

// Generate realistic timeline data over 1 hour with varying traffic patterns
export const generateMockTimelineData = (intervalMs: number = 60000): TimelineDataPoint[] => {
  const data: TimelineDataPoint[] = [];
  const startTime = Date.now() - 3600000; // 1 hour ago
  const endTime = Date.now();
  const intervals = Math.floor((endTime - startTime) / intervalMs);

  for (let i = 0; i < intervals; i++) {
    const timestamp = startTime + i * intervalMs;

    // Create traffic patterns (peaks and valleys)
    const hourProgress = i / intervals;
    let baseTraffic = 2000;

    // Morning peak (first 20%)
    if (hourProgress < 0.2) {
      baseTraffic = 1000 + hourProgress * 5000;
    }
    // Sustained high (20-60%)
    else if (hourProgress < 0.6) {
      baseTraffic = 3000 + Math.sin(hourProgress * 10) * 1000;
    }
    // Gradual decline (60-100%)
    else {
      baseTraffic = 3000 - (hourProgress - 0.6) * 5000;
    }

    // Add some randomness
    const packets = Math.floor(baseTraffic + Math.random() * 500);
    const avgPacketSize = 800 + Math.random() * 700;
    const bytes = Math.floor(packets * avgPacketSize);

    // Protocol distribution (varies over time)
    const httpRatio = 0.3 + Math.random() * 0.2;
    const tcpRatio = 0.25 + Math.random() * 0.15;
    const udpRatio = 0.15 + Math.random() * 0.1;
    const dnsRatio = 0.05 + Math.random() * 0.05;
    const tlsRatio = 0.1 + Math.random() * 0.1;
    const other = 1 - (httpRatio + tcpRatio + udpRatio + dnsRatio + tlsRatio);

    data.push({
      timestamp,
      packetCount: packets,
      bytes,
      protocols: {
        HTTP: Math.floor(packets * httpRatio),
        TCP: Math.floor(packets * tcpRatio),
        UDP: Math.floor(packets * udpRatio),
        DNS: Math.floor(packets * dnsRatio),
        TLS: Math.floor(packets * tlsRatio),
        Other: Math.floor(packets * other),
      },
    });
  }

  return data;
};

export const mockTimelineData = generateMockTimelineData();

// Generate timeline data for a specific time range
export const generateTimelineForRange = (
  start: number,
  end: number,
  intervalMs: number = 60000
): TimelineDataPoint[] => {
  const data: TimelineDataPoint[] = [];
  const intervals = Math.floor((end - start) / intervalMs);

  for (let i = 0; i < intervals; i++) {
    const timestamp = start + i * intervalMs;
    const packets = Math.floor(1500 + Math.random() * 2000);
    const bytes = Math.floor(packets * (800 + Math.random() * 700));

    data.push({
      timestamp,
      packetCount: packets,
      bytes,
      protocols: {
        HTTP: Math.floor(packets * (0.3 + Math.random() * 0.2)),
        TCP: Math.floor(packets * (0.25 + Math.random() * 0.15)),
        UDP: Math.floor(packets * (0.15 + Math.random() * 0.1)),
        DNS: Math.floor(packets * (0.05 + Math.random() * 0.05)),
        TLS: Math.floor(packets * (0.1 + Math.random() * 0.1)),
      },
    });
  }

  return data;
};
