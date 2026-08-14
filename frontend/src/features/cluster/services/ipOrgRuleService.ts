import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export interface IpOrgRule {
  id: number;
  label: string;
  cidr: string;
}

function normaliseTocidr(input: string): string {
  const s = input.trim();
  // Already a CIDR
  if (s.includes('/')) {
    const [ip, prefix] = s.split('/');
    const prefixNum = parseInt(prefix, 10);
    if (isNaN(prefixNum)) throw new Error(`Invalid prefix in "${s}"`);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
      const octets = ip.split('.').map(Number);
      if (octets.some(o => isNaN(o) || o < 0 || o > 255)) throw new Error(`Invalid IPv4 address in "${s}"`);
      if (prefixNum < 0 || prefixNum > 32) throw new Error(`IPv4 prefix must be 0–32 in "${s}"`);
    } else if (ip.includes(':')) {
      if (prefixNum < 0 || prefixNum > 128) throw new Error(`IPv6 prefix must be 0–128 in "${s}"`);
    } else {
      throw new Error(`Invalid IP address in "${s}"`);
    }
    return s;
  }
  // Plain IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
    const octets = s.split('.').map(Number);
    if (octets.some(o => isNaN(o) || o < 0 || o > 255)) throw new Error(`Invalid IP address: "${s}"`);
    return `${s}/32`;
  }
  // Plain IPv6
  if (s.includes(':')) return `${s}/128`;
  throw new Error(`Invalid IP or CIDR: "${s}". Use an IP (e.g. 8.8.8.8) or a range (e.g. 10.0.1.0/24).`);
}

export const ipOrgRuleService = {
  async list(): Promise<IpOrgRule[]> {
    const res = await apiClient.get<IpOrgRule[]>(API_ENDPOINTS.IP_ORG_RULES);
    return res.data;
  },

  async create(label: string, cidr: string): Promise<IpOrgRule> {
    const normalisedCidr = normaliseTocidr(cidr);
    const res = await apiClient.post<IpOrgRule>(API_ENDPOINTS.IP_ORG_RULES, { label, cidr: normalisedCidr });
    return res.data;
  },

  async delete(id: number): Promise<void> {
    await apiClient.delete(API_ENDPOINTS.IP_ORG_RULE_DELETE(id));
  },
};
