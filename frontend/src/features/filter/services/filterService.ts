import { apiClient } from '@/services/api/client'
import { API_ENDPOINTS } from '@/services/api/endpoints'
import type {
  FilterGenerationRequest,
  FilterGenerationResponse,
  FilterExecutionRequest,
  FilterExecutionResponse
} from '@/types'

const USE_MOCK = import.meta.env.VITE_USE_MOCK_DATA === 'true'

// Mock data for development
const generateMockFilter = (query: string): FilterGenerationResponse => {
  const queryLower = query.toLowerCase()

  // Simple pattern matching for common queries
  let filter = ''
  let explanation = ''
  let confidence = 0.85
  const suggestions: string[] = []

  if (queryLower.includes('http') || queryLower.includes('web')) {
    filter = 'tcp.port == 80 || tcp.port == 443'
    explanation = 'This filter captures HTTP (port 80) and HTTPS (port 443) traffic.'
    suggestions.push('Add "http.request" to see only HTTP requests', 'Use "ssl.handshake" for SSL/TLS handshakes')
  } else if (queryLower.includes('dns')) {
    filter = 'udp.port == 53 || tcp.port == 53'
    explanation = 'This filter captures DNS traffic on both UDP and TCP port 53.'
    suggestions.push('Add "dns.qry.name" to filter specific domains')
  } else if (queryLower.includes('ssh')) {
    filter = 'tcp.port == 22'
    explanation = 'This filter captures SSH traffic on port 22.'
  } else if (queryLower.includes('ftp')) {
    filter = 'tcp.port == 21 || tcp.port == 20'
    explanation = 'This filter captures FTP control (21) and data (20) traffic.'
  } else if (queryLower.match(/\d+\.\d+\.\d+\.\d+/)) {
    const ip = queryLower.match(/\d+\.\d+\.\d+\.\d+/)?.[0]
    filter = `ip.addr == ${ip}`
    explanation = `This filter captures all traffic to or from IP address ${ip}.`
    suggestions.push(`Use "ip.src == ${ip}" for source only`, `Use "ip.dst == ${ip}" for destination only`)
  } else if (queryLower.includes('tcp')) {
    filter = 'tcp'
    explanation = 'This filter captures all TCP traffic.'
    suggestions.push('Add port filters like "tcp.port == 80"', 'Use "tcp.flags.syn == 1" for SYN packets')
  } else if (queryLower.includes('udp')) {
    filter = 'udp'
    explanation = 'This filter captures all UDP traffic.'
    suggestions.push('Add port filters like "udp.port == 53"')
  } else {
    filter = 'ip'
    explanation = 'Generic IP filter - showing all IP traffic. Try being more specific in your query.'
    confidence = 0.6
    suggestions.push(
      'Try: "show me HTTP traffic"',
      'Try: "DNS queries"',
      'Try: "traffic from 192.168.1.1"'
    )
  }

  return {
    filter,
    explanation,
    confidence,
    suggestions: suggestions.length > 0 ? suggestions : undefined
  }
}

const generateMockPackets = (): FilterExecutionResponse => {
  const packets: FilterExecutionResponse['packets'] = [
    {
      id: '1',
      timestamp: Date.now() - 5000,
      source: { ip: '192.168.1.100', port: 54321 },
      destination: { ip: '93.184.216.34', port: 80 },
      protocol: { layer: 'application' as const, name: 'HTTP' },
      size: 512,
      payload: 'GET / HTTP/1.1\r\nHost: example.com\r\n',
      flags: ['SYN', 'ACK']
    },
    {
      id: '2',
      timestamp: Date.now() - 4000,
      source: { ip: '93.184.216.34', port: 80 },
      destination: { ip: '192.168.1.100', port: 54321 },
      protocol: { layer: 'application' as const, name: 'HTTP' },
      size: 1024,
      payload: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n',
      flags: ['ACK']
    },
    {
      id: '3',
      timestamp: Date.now() - 3000,
      source: { ip: '192.168.1.100', port: 54322 },
      destination: { ip: '151.101.1.140', port: 443 },
      protocol: { layer: 'application' as const, name: 'HTTPS' },
      size: 768,
      payload: '[Encrypted]',
      flags: ['PSH', 'ACK']
    }
  ]

  return {
    packets,
    totalMatches: packets.length,
    executionTime: 45
  }
}

export const filterService = {
  /**
   * Generate a pcap filter from natural language query
   * @param fileId - The file ID to generate filter for
   * @param query - Natural language query
   * @returns Generated filter with explanation
   */
  generateFilter: async (fileId: string, query: string): Promise<FilterGenerationResponse> => {
    if (USE_MOCK) {
      // Simulate AI processing time
      await new Promise((resolve) => setTimeout(resolve, 1500))
      return generateMockFilter(query)
    }

    const request: FilterGenerationRequest = {
      fileId,
      naturalLanguageQuery: query
    }

    const response = await apiClient.post<FilterGenerationResponse>(
      API_ENDPOINTS.GENERATE_FILTER(fileId),
      request
    )
    return response.data
  },

  /**
   * Execute a pcap filter and get matching packets with pagination
   * @param fileId - The file ID to execute filter on
   * @param filter - The pcap filter string
   * @param page - Page number (1-indexed)
   * @param pageSize - Number of packets per page
   * @returns Matching packets with pagination info
   */
  executeFilter: async (
    fileId: string,
    filter: string,
    page: number = 1,
    pageSize: number = 25
  ): Promise<FilterExecutionResponse> => {
    if (USE_MOCK) {
      // Simulate filter execution time
      await new Promise((resolve) => setTimeout(resolve, 800))
      const mockData = generateMockPackets()
      return {
        ...mockData,
        page,
        pageSize,
        totalPages: Math.ceil(mockData.totalMatches / pageSize),
      }
    }

    const request: FilterExecutionRequest = {
      fileId,
      filter
    }

    const response = await apiClient.post<FilterExecutionResponse>(
      API_ENDPOINTS.EXECUTE_FILTER(fileId),
      request,
      {
        params: { page, pageSize }
      }
    )
    return response.data
  }
}
