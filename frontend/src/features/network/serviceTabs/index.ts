import type { ServiceTabConfig } from './types';
import { dnsServiceTab } from './dnsServiceTab';
import { webServiceTab } from './webServiceTab';

export type { ServiceTabConfig, ServiceLogColumn, ServiceLogInfoField } from './types';

/**
 * Registry mapping a host service role → the tab the node modal renders for it. Add a role = add an
 * entry here (plus its backend extractor + classification signal). The modal renders one tab per
 * role a host serves. The web tab is registered under both `api` and `web` since both share the
 * same HTTP endpoint view.
 */
const BY_ROLE = new Map<string, ServiceTabConfig<unknown, unknown>>([
  ['dns', dnsServiceTab as ServiceTabConfig<unknown, unknown>],
  ['api', webServiceTab as ServiceTabConfig<unknown, unknown>],
  ['web', webServiceTab as ServiceTabConfig<unknown, unknown>],
]);

/** Returns the tab config for a role, or undefined when the role has no registered tab. */
export function getServiceTab(role: string): ServiceTabConfig<unknown, unknown> | undefined {
  return BY_ROLE.get(role);
}
