/**
 * Reading the investigation's category statuses (docs/architecture/investigation-framework.rst):
 * the helpers the Overview's "Worth a look" and Story's summary share.
 */
import type { CategoryLead, CategoryStatus } from '@/types';

type Status = CategoryStatus['status'];

export { plural } from '@/utils/formatters';
import { plural } from '@/utils/formatters';

export interface WorthALookGroup {
  key: string;
  label: string;
  status: Status;
  leads: CategoryLead[];
}

/**
 * The categories worth a look in this capture, merging ones that point at the same traffic and have
 * the same status (a C2 server and Command and Control, both open, both pointing at DNS, TLS and
 * HTTP) so a protocol isn't listed twice. Categories whose statuses differ stay apart: an answered
 * Command and Control (a remote-access tool) mustn't make an open C2 server read as answered.
 */
export function worthALookGroups(categories: CategoryStatus[]): WorthALookGroup[] {
  const groups = new Map<string, WorthALookGroup>();
  for (const c of categories) {
    if (c.axis === 'CONTEXT' || c.leads.length === 0) continue;
    const sig = `${c.status}|${c.leads.map(l => l.query).join('|')}`;
    const g = groups.get(sig);
    if (!g) {
      groups.set(sig, { key: c.key, label: c.label, status: c.status, leads: c.leads });
    } else {
      g.label = `${g.label} · ${c.label}`;
    }
  }
  return [...groups.values()];
}

/** "Nothing is concluded yet. 12 are still open, 4 were ruled out and 5 can't be seen in this capture." */
export function summarySentence(counts: Record<Status, number>): string {
  const lead = counts.ANSWERED === 0
    ? 'Nothing is concluded yet.'
    : `${plural(counts.ANSWERED, 'category is', 'categories are')} answered.`;
  const parts: string[] = [];
  if (counts.OPEN > 0) parts.push(`${counts.OPEN} ${counts.OPEN === 1 ? 'is' : 'are'} still open`);
  if (counts.RULED_OUT > 0) parts.push(`${counts.RULED_OUT} ${counts.RULED_OUT === 1 ? 'was' : 'were'} ruled out`);
  if (counts.NOT_OBSERVABLE > 0) parts.push(`${counts.NOT_OBSERVABLE} can't be seen in this capture`);
  if (parts.length === 0) return lead;
  const tail = parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}`;
  return `${lead} ${tail.charAt(0).toUpperCase()}${tail.slice(1)}.`;
}

/**
 * Open categories in reading order: those with traffic in this capture to look at first (a person
 * can act on them now), then the ones no check covers yet. Capture context is left out.
 */
export function worthALookNext(categories: CategoryStatus[]): CategoryStatus[] {
  const open = categories.filter(c => c.status === 'OPEN' && c.axis !== 'CONTEXT');
  return [...open.filter(c => c.leads.length > 0), ...open.filter(c => c.leads.length === 0)];
}
