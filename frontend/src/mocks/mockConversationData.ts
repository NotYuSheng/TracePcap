import type { Conversation, Packet, Session } from '@/types';

// Mock packets for a conversation
const generateMockPackets = (count: number, conversationId: string): Packet[] => {
  const packets: Packet[] = [];
  const baseTime = Date.now() - 3600000;

  for (let i = 0; i < count; i++) {
    packets.push({
      id: `${conversationId}-pkt-${i}`,
      timestamp: baseTime + i * 1000,
      source: { ip: '192.168.1.100', port: 52341 + i },
      destination: { ip: '93.184.216.34', port: 443 },
      protocol: { layer: 'application', name: 'HTTPS' },
      size: Math.floor(Math.random() * 1500) + 60,
      payload: btoa(`Mock payload data for packet ${i}`),
      flags: i % 2 === 0 ? ['ACK'] : ['PSH', 'ACK'],
    });
  }

  return packets;
};

export const mockConversations: Conversation[] = [
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
    packets: generateMockPackets(50, 'conv-1'),
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
    packets: generateMockPackets(30, 'conv-2'),
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
    packets: generateMockPackets(60, 'conv-3'),
    direction: 'bidirectional',
  },
  {
    id: 'conv-4',
    endpoints: [
      { ip: '192.168.1.100', port: 48765, hostname: 'client-device.local' },
      { ip: '104.16.123.96', port: 443, hostname: 'cdn.cloudflare.com' },
    ],
    protocol: { layer: 'application', name: 'HTTPS' },
    startTime: Date.now() - 2800000,
    endTime: Date.now() - 500000,
    packetCount: 6543,
    totalBytes: 3456789,
    packets: generateMockPackets(40, 'conv-4'),
    direction: 'bidirectional',
  },
  {
    id: 'conv-5',
    endpoints: [
      { ip: '192.168.1.100', port: 47654, hostname: 'client-device.local' },
      { ip: '192.168.1.1', port: 0, hostname: 'gateway.local', mac: 'aa:bb:cc:dd:ee:ff' },
    ],
    protocol: { layer: 'network', name: 'ARP' },
    startTime: Date.now() - 3600000,
    endTime: Date.now() - 300000,
    packetCount: 1234,
    totalBytes: 514289,
    packets: generateMockPackets(20, 'conv-5'),
    direction: 'unidirectional',
  },
];

export const mockSessions: Session[] = [
  {
    id: 'session-1',
    conversations: [mockConversations[0], mockConversations[3]],
    startTime: Date.now() - 3500000,
    endTime: Date.now() - 400000,
    totalPackets: 15477,
    totalBytes: 8024679,
    purpose: 'HTTPS API Communication',
  },
  {
    id: 'session-2',
    conversations: [mockConversations[1]],
    startTime: Date.now() - 3600000,
    endTime: Date.now() - 300000,
    totalPackets: 5621,
    totalBytes: 2345678,
    purpose: 'DNS Queries',
  },
  {
    id: 'session-3',
    conversations: [mockConversations[2]],
    startTime: Date.now() - 3200000,
    endTime: Date.now() - 800000,
    totalPackets: 12456,
    totalBytes: 7890123,
    purpose: 'HTTP Web Browsing',
  },
];

export const getConversationById = (id: string): Conversation | undefined => {
  return mockConversations.find(conv => conv.id === id);
};
