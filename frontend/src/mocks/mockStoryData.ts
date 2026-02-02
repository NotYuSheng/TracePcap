import type { Story } from '@/types';

export const mockStory: Story = {
  id: 'story-1',
  fileId: 'mock-file-123',
  generatedAt: Date.now(),
  narrative: [
    {
      title: 'Executive Summary',
      content:
        'This network capture reveals typical enterprise network activity over a 55-minute period, with 125,432 packets exchanged across 6 unique hosts. The traffic pattern shows heavy reliance on HTTP/HTTPS protocols (66% of total traffic) with consistent DNS resolution activity. A client device (192.168.1.100) initiated most connections, communicating primarily with external API servers and content delivery networks.',
      type: 'summary',
      relatedData: {
        hosts: ['192.168.1.100', '93.184.216.34', '172.217.14.206'],
      },
    },
    {
      title: 'Network Activity Overview',
      content:
        'The capture began with a burst of DNS queries as the client device resolved multiple domain names for api.example.com, www.google.com, and cdn.cloudflare.com. Following DNS resolution, the device established HTTPS connections to these endpoints. The most significant conversation involved 8,934 packets (4.5 MB) exchanged with api.example.com over port 443, suggesting sustained API communication or data synchronization.',
      type: 'detail',
      relatedData: {
        conversations: ['conv-1', 'conv-2', 'conv-3'],
        packets: ['conv-1-pkt-0', 'conv-2-pkt-0'],
      },
    },
    {
      title: 'Identified Patterns',
      content:
        'Three distinct communication patterns emerged:\n\n1. **API Communication**: Persistent HTTPS session with api.example.com showing regular request-response cycles every 30-45 seconds, consistent with polling or heartbeat mechanisms.\n\n2. **Web Browsing**: HTTP traffic to www.google.com with typical browser fingerprints including user-agent strings and cookie exchanges.\n\n3. **CDN Content Delivery**: High-bandwidth HTTPS traffic from cdn.cloudflare.com, likely serving static assets or media content based on packet sizes averaging 1.2KB.',
      type: 'detail',
      relatedData: {
        conversations: ['conv-1', 'conv-3', 'conv-4'],
      },
    },
    {
      title: 'Security Observations',
      content:
        'While the majority of traffic appears benign, several observations warrant attention:\n\n• **Port Scanning Activity**: A sequence of 47 packets sent to sequential ports on 192.168.1.1 between timestamps 14:23:15 and 14:23:47. This pattern is consistent with automated port scanning tools.\n\n• **High Volume Traffic**: The API communication session transferred 4.5MB in 55 minutes, which is above typical baseline for this endpoint. This could indicate legitimate bulk data operations or potential data exfiltration.\n\n• **DNS Query Pattern**: Multiple queries for the same domain (api.example.com) with short TTLs suggest either DNS issues or potential DNS tunneling attempts.',
      type: 'anomaly',
      relatedData: {
        packets: ['anom-1234', 'anom-1235'],
      },
    },
    {
      title: 'Recommendations',
      content:
        'Based on this analysis, the following actions are recommended:\n\n1. **Investigate Port Scanning**: Review logs for 192.168.1.100 to determine if the port scanning was authorized security testing or malicious reconnaissance.\n\n2. **Validate API Traffic**: Confirm that the high-volume API communication aligns with expected application behavior. Consider implementing traffic baselines and alerts for deviations.\n\n3. **Monitor DNS Patterns**: Implement DNS monitoring to detect unusual query patterns that might indicate DNS tunneling or command-and-control communications.\n\n4. **Apply TLS Inspection**: Consider implementing TLS/SSL inspection for outbound HTTPS traffic to gain visibility into encrypted communications while maintaining compliance with privacy requirements.',
      type: 'conclusion',
      relatedData: {},
    },
  ],
  highlights: [
    {
      id: 'highlight-1',
      type: 'anomaly',
      title: 'Port Scanning Detected',
      description: 'Sequential port scan detected from client device targeting internal gateway',
      timestamp: Date.now() - 2000000,
    },
    {
      id: 'highlight-2',
      type: 'warning',
      title: 'High Volume API Traffic',
      description: 'Unusual data volume (4.5MB) transferred in API session',
      timestamp: Date.now() - 1500000,
    },
    {
      id: 'highlight-3',
      type: 'insight',
      title: 'CDN Content Delivery',
      description: 'Large media assets delivered via Cloudflare CDN',
      timestamp: Date.now() - 1000000,
    },
    {
      id: 'highlight-4',
      type: 'info',
      title: 'DNS Resolution Successful',
      description: 'All DNS queries resolved successfully with avg latency 23ms',
      timestamp: Date.now() - 3500000,
    },
  ],
  timeline: [
    {
      timestamp: Date.now() - 3600000,
      title: 'Capture Started',
      description: 'Network capture initiated, initial DNS queries observed',
      type: 'normal',
      relatedData: { conversations: ['conv-2'] },
    },
    {
      timestamp: Date.now() - 3500000,
      title: 'HTTPS Sessions Established',
      description: 'Multiple HTTPS connections established to external APIs',
      type: 'normal',
      relatedData: { conversations: ['conv-1', 'conv-4'] },
    },
    {
      timestamp: Date.now() - 3200000,
      title: 'Web Browsing Activity',
      description: 'HTTP traffic to www.google.com initiated',
      type: 'normal',
      relatedData: { conversations: ['conv-3'] },
    },
    {
      timestamp: Date.now() - 2000000,
      title: '⚠️ Port Scan Detected',
      description: 'Sequential port scanning activity identified',
      type: 'suspicious',
      relatedData: { packets: ['anom-1234'] },
    },
    {
      timestamp: Date.now() - 1500000,
      title: '⚠️ High Traffic Volume',
      description: 'Unusually high data transfer rate observed',
      type: 'suspicious',
      relatedData: { conversations: ['conv-1'] },
    },
    {
      timestamp: Date.now() - 500000,
      title: 'Sessions Closing',
      description: 'HTTPS connections gracefully terminated',
      type: 'normal',
      relatedData: { conversations: ['conv-1', 'conv-3'] },
    },
  ],
};

export const generateMockStory = (fileId: string): Story => {
  return {
    ...mockStory,
    id: `story-${Date.now()}`,
    fileId,
    generatedAt: Date.now(),
  };
};
