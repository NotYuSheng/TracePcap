import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export interface IpOrgRule {
  id: number;
  label: string;
  cidr: string;
}

export const ipOrgRuleService = {
  async list(): Promise<IpOrgRule[]> {
    const res = await apiClient.get<IpOrgRule[]>(API_ENDPOINTS.IP_ORG_RULES);
    return res.data;
  },

  async create(label: string, cidr: string): Promise<IpOrgRule> {
    // The backend's Cidr.normalise checks and writes it (#1351): one CIDR rule.
    const res = await apiClient.post<IpOrgRule>(API_ENDPOINTS.IP_ORG_RULES, { label, cidr: cidr.trim() });
    return res.data;
  },

  async delete(id: number): Promise<void> {
    await apiClient.delete(API_ENDPOINTS.IP_ORG_RULE_DELETE(id));
  },
};
