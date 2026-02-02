import type { AnalysisSummary } from '@/types';

export const mockAnalysisSummary: AnalysisSummary = {
  fileId: 'mock-file-123',
  fileName: 'free5gc.pcap',
  fileSize: 47589632, // ~45 MB
  uploadTime: Date.now() - 300000, // 5 minutes ago
  totalPackets: 125432,
  timeRange: [Date.now() - 3600000, Date.now() - 300000], // 1 hour capture
  protocolDistribution: [
    { protocol: 'HTTP', count: 45162, percentage: 36.0, bytes: 18456789 },
    { protocol: 'TCP', count: 37630, percentage: 30.0, bytes: 15423678 },
    { protocol: 'UDP', count: 25086, percentage: 20.0, bytes: 10285432 },
    { protocol: 'DNS', count: 8767, percentage: 7.0, bytes: 3589632 },
    { protocol: 'TLS', count: 5021, percentage: 4.0, bytes: 2056789 },
    { protocol: 'ICMP', count: 2509, percentage: 2.0, bytes: 1028456 },
    { protocol: 'ARP', count: 1254, percentage: 1.0, bytes: 514289 },
  ],
  topConversations: [
    {
      id: 'conv-1',
      endpoints: [
        { ip: '192.168.1.100', port: 52341, hostname: 'client-device.local' },
        { ip: '93.184.216.34', port: 443, hostname: 'api.example.com' },
      ],
      protocol: { layer: 'application', name: 'HTTPS' },
      startTime: Date.now() - 3500000,
      endTime: Date.now() - 400000,
      packetCount: 8934,
      totalBytes: 4567890,
      packets: [],
      direction: 'bidirectional',
    },
    {
      id: 'conv-2',
      endpoints: [
        { ip: '192.168.1.100', port: 51234, hostname: 'client-device.local' },
        { ip: '8.8.8.8', port: 53, hostname: 'dns.google' },
      ],
      protocol: { layer: 'application', name: 'DNS' },
      startTime: Date.now() - 3600000,
      endTime: Date.now() - 300000,
      packetCount: 5621,
      totalBytes: 2345678,
      packets: [],
      direction: 'bidirectional',
    },
    {
      id: 'conv-3',
      endpoints: [
        { ip: '192.168.1.100', port: 49876, hostname: 'client-device.local' },
        { ip: '172.217.14.206', port: 80, hostname: 'www.google.com' },
      ],
      protocol: { layer: 'application', name: 'HTTP' },
      startTime: Date.now() - 3200000,
      endTime: Date.now() - 800000,
      packetCount: 12456,
      totalBytes: 7890123,
      packets: [],
      direction: 'bidirectional',
    },
  ],
  uniqueHosts: [
    { ip: '192.168.1.100', port: 0, hostname: 'client-device.local' },
    { ip: '93.184.216.34', port: 443, hostname: 'api.example.com' },
    { ip: '8.8.8.8', port: 53, hostname: 'dns.google' },
    { ip: '172.217.14.206', port: 80, hostname: 'www.google.com' },
    { ip: '192.168.1.1', port: 0, hostname: 'gateway.local' },
    { ip: '10.0.0.5', port: 0, hostname: 'server-01.internal' },
  ],
  fiveWs: {
    who: {
      hosts: [
        {
          endpoint: { ip: '192.168.1.100', port: 0, hostname: 'client-device.local' },
          packetsSent: 65432,
          packetsReceived: 60000,
          bytesSent: 25678900,
          bytesReceived: 21910732,
          role: 'client',
        },
        {
          endpoint: { ip: '192.168.1.1', port: 0, hostname: 'gateway.local' },
          packetsSent: 45000,
          packetsReceived: 40000,
          bytesSent: 15678900,
          bytesReceived: 14000000,
          role: 'both',
        },
      ],
      topTalkers: [
        { ip: '192.168.1.100', port: 0, hostname: 'client-device.local' },
        { ip: '192.168.1.1', port: 0, hostname: 'gateway.local' },
      ],
      roles: {
        '192.168.1.100': 'client',
        '192.168.1.1': 'both',
        '93.184.216.34': 'server',
      },
    },
    what: {
      protocols: [
        { protocol: 'HTTP', count: 45162, percentage: 36.0, bytes: 18456789 },
        { protocol: 'TCP', count: 37630, percentage: 30.0, bytes: 15423678 },
      ],
      services: [
        { name: 'HTTPS', port: 443, protocol: 'TCP', packetCount: 35678, bytes: 14567890 },
        { name: 'HTTP', port: 80, protocol: 'TCP', packetCount: 28934, bytes: 11890234 },
        { name: 'DNS', port: 53, protocol: 'UDP', packetCount: 8767, bytes: 3589632 },
      ],
      dataTransferred: 47589632,
    },
    when: {
      startTime: Date.now() - 3600000,
      endTime: Date.now() - 300000,
      duration: 3300000, // 55 minutes
      peakActivity: [
        {
          start: Date.now() - 3000000,
          end: Date.now() - 2700000,
          packetCount: 25678,
          bytes: 10456789,
        },
      ],
    },
    where: {
      internalNetworks: ['192.168.1.0/24', '10.0.0.0/24'],
      externalNetworks: ['93.184.216.0/24', '172.217.14.0/24'],
      geolocation: {
        '93.184.216.34': { country: 'United States', city: 'New York' },
        '172.217.14.206': { country: 'United States', city: 'Mountain View' },
      },
    },
    why: {
      purposes: ['Web Browsing', 'DNS Resolution', 'API Communication'],
      anomalies: [
        {
          id: 'anom-1',
          type: 'Unusual Port Scan',
          severity: 'medium',
          description: 'Port scanning detected from 192.168.1.100',
          timestamp: Date.now() - 2000000,
          relatedPackets: ['pkt-1234', 'pkt-1235'],
          recommendations: ['Investigate source device', 'Check for malware'],
        },
      ],
      suspiciousActivity: [
        {
          id: 'susp-1',
          type: 'High Volume Traffic',
          description: 'Unusually high traffic volume to external IP',
          timestamp: Date.now() - 1500000,
          source: { ip: '192.168.1.100', port: 52341 },
          destination: { ip: '93.184.216.34', port: 443 },
          confidence: 0.75,
        },
      ],
    },
  },
};

// Generate additional mock summaries for different file IDs
export const generateMockAnalysis = (fileId: string, fileName: string): AnalysisSummary => {
  return {
    ...mockAnalysisSummary,
    fileId,
    fileName,
    uploadTime: Date.now(),
  };
};
