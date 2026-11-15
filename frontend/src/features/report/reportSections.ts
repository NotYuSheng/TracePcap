/** The report's parts, as the backend names them (ReportRequest.Section). */
export type ReportSection =
  | 'NEEDS_A_LOOK'
  | 'HOSTS'
  | 'MAP'
  | 'STORY'
  | 'TRAFFIC'
  | 'CONVERSATIONS'
  | 'EXTRACTED_FILES'
  | 'APPENDIX';

export type ReportKind = 'briefing' | 'full';

export const BRIEFING: ReportSection[] = ['NEEDS_A_LOOK', 'HOSTS', 'MAP', 'STORY'];
export const FULL: ReportSection[] = [...BRIEFING, 'TRAFFIC', 'CONVERSATIONS', 'EXTRACTED_FILES', 'APPENDIX'];

export interface SectionRow {
  key: ReportSection;
  label: string;
  hint: string;
}

export const ROWS: SectionRow[] = [
  { key: 'NEEDS_A_LOOK', label: 'Needs a look', hint: 'What was flagged, with the devices named' },
  { key: 'HOSTS', label: 'Hosts by network', hint: 'Names, addresses and MACs' },
  { key: 'MAP', label: 'Network map', hint: 'Grouped as on the Network tab' },
  { key: 'STORY', label: 'Story', hint: 'The Story tab’s narrative' },
  { key: 'TRAFFIC', label: 'Traffic', hint: 'Where it goes, flows, protocols, apps' },
  { key: 'CONVERSATIONS', label: 'Conversations', hint: 'The busiest, and the internet hosts' },
  { key: 'EXTRACTED_FILES', label: 'Extracted files', hint: 'Files carved from the capture' },
  { key: 'APPENDIX', label: 'Appendix', hint: 'Every flagged conversation; how devices were classified' },
];

/** The sections a kind starts with, less the ones this capture can't have. */
export function sectionsFor(kind: ReportKind, unavailable: Set<ReportSection>): Set<ReportSection> {
  return new Set((kind === 'full' ? FULL : BRIEFING).filter(s => !unavailable.has(s)));
}

/** "As left on the Network tab: Protocol: HTTPS · Risks only" or the whole capture's line. */
export function mapCaption(asLeft: boolean, filters: string[], nodeLimitNote: string | null): string {
  if (!asLeft) return 'The whole capture, without the Network tab’s filters.';
  const parts = [filters.length ? `Filters: ${filters.join(' · ')}` : 'No filters', nodeLimitNote].filter(Boolean);
  return `As left on the Network tab. ${parts.join('. ')}${parts.length ? '.' : ''}`;
}

