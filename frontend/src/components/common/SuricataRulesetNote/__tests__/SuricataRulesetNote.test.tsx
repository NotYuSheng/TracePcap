import { render, screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { SuricataRulesetNote } from '../SuricataRulesetNote';

const base = { engineVersion: '1:6.0.4-3', staleAfterDays: 30, ruleCount: 50000, importDir: '/var/lib/tracepcap/suricata-rules' };

describe('SuricataRulesetNote (#600)', () => {
  it('says which ruleset is in use and how old it is', async () => {
    server.use(
      http.get('*/system/suricata', () =>
        HttpResponse.json({ ...base, source: 'built-in', rulesetDate: '2026-11-08', ageDays: 14, stale: false, importError: null })
      )
    );
    render(<SuricataRulesetNote />);
    expect(await screen.findByTestId('suricata-ruleset')).toHaveTextContent('14 days old');
    expect(screen.queryByTestId('suricata-ruleset-stale')).not.toBeInTheDocument();
  });

  it('flags a stale ruleset, and says why an imported bundle was not used', async () => {
    server.use(
      http.get('*/system/suricata', () =>
        HttpResponse.json({ ...base, source: 'built-in', rulesetDate: '2026-08-01', ageDays: 113, stale: true, importError: 'Suricata couldn\'t load it' })
      )
    );
    render(<SuricataRulesetNote />);
    expect(await screen.findByTestId('suricata-ruleset-stale')).toHaveTextContent('Older than 30 days');
    expect(screen.getByTestId('suricata-import-error')).toHaveTextContent("Suricata couldn't load it");
  });

  it('says when the rules were imported', async () => {
    server.use(
      http.get('*/system/suricata', () =>
        HttpResponse.json({ ...base, source: 'imported', rulesetDate: '2026-11-21', ageDays: 1, stale: false, importError: null })
      )
    );
    render(<SuricataRulesetNote />);
    expect(await screen.findByTestId('suricata-ruleset')).toHaveTextContent('Emerging Threats, imported');
  });
});
