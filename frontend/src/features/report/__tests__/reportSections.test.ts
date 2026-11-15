/** The Download report drawer's choices (#1152). */
import { describe, expect, it } from 'vitest';
import { mapCaption, sectionsFor, type ReportSection } from '../reportSections';

describe('sectionsFor', () => {
  it('starts the briefing with what needs a look, the hosts, the map and the story', () => {
    expect([...sectionsFor('briefing', new Set())]).toEqual(['NEEDS_A_LOOK', 'HOSTS', 'MAP', 'STORY']);
  });

  it('adds the evidence for the full report, less what this capture cannot have', () => {
    const off = new Set<ReportSection>(['STORY', 'EXTRACTED_FILES']);
    expect([...sectionsFor('full', off)]).toEqual([
      'NEEDS_A_LOOK', 'HOSTS', 'MAP', 'TRAFFIC', 'CONVERSATIONS', 'APPENDIX',
    ]);
  });
});

describe('mapCaption', () => {
  it('says which map, and the filters it was left with', () => {
    expect(mapCaption(true, ['Protocol: HTTPS', 'Risks only'], null)).toBe(
      'As left on the Network tab. Filters: Protocol: HTTPS · Risks only.'
    );
    expect(mapCaption(true, [], null)).toBe('As left on the Network tab. No filters.');
    expect(mapCaption(false, ['Protocol: HTTPS'], null)).toBe(
      'The whole capture, without the Network tab’s filters.'
    );
  });
});
