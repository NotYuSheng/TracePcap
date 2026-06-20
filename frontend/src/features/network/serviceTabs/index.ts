import type { ServiceTabConfig } from './types';
import { dnsServiceTab } from './dnsServiceTab';

export type { ServiceTabConfig, ServiceLogColumn } from './types';

/**
 * Registry of per-service-role tabs the node modal can show, keyed by role. Add a role = add an
 * entry here (plus its backend extractor + classification signal). The modal renders one tab per
 * role a host serves, in registry order.
 */
const SERVICE_TABS: ServiceTabConfig<unknown, unknown>[] = [
  dnsServiceTab as ServiceTabConfig<unknown, unknown>,
];

const BY_ROLE = new Map(SERVICE_TABS.map(t => [t.role, t]));

/** Returns the tab config for a role, or undefined when the role has no registered tab. */
export function getServiceTab(role: string): ServiceTabConfig<unknown, unknown> | undefined {
  return BY_ROLE.get(role);
}
