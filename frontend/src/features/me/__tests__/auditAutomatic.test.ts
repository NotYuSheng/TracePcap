import { describe, expect, it } from 'vitest';
import { kindOf, summarize } from '../auditDiff';

const auto = (action: string, after: Record<string, unknown>, targetId?: string) => ({
  action,
  targetId,
  before: null,
  after: { request: 'X /y', status: 200, ...after },
});

describe('automatically recorded audit entries', () => {
  it('read as the endpoint summary in the past tense, with what they acted on', () => {
    expect(summarize(auto('network.snapshots.create', { summary: 'Add a snapshot to a network' }))).toBe(
      'Added a snapshot to a network'
    );
    expect(summarize(auto('file.delete', { summary: 'Delete file', name: 'ftp.pcap' }, 'f1'))).toBe(
      'Deleted file: ftp.pcap'
    );
    expect(summarize(auto('file.create', { summary: 'Upload PCAP file', name: 'a.pcap' }))).toBe(
      'Uploaded PCAP file: a.pcap'
    );
  });

  it('puts both verbs of "X or Y" in the past tense', () => {
    expect(summarize(auto('node-role.set', { summary: "Create or update an entity's role in a file", name: '10.0.0.5 → NAS' }))).toBe(
      "Created or updated an entity's role in a file: 10.0.0.5 → NAS"
    );
  });

  it('names a capture from the ids it knows', () => {
    const names = new Map([['f1', 'strrat.pcapng']]);
    expect(summarize(auto('file.favourite.set', { summary: 'Mark a capture as a favourite' }, 'f1'), names)).toBe(
      'Marked a capture as a favourite: strrat.pcapng'
    );
  });

  it('says when it was refused', () => {
    expect(summarize(auto('file.delete.denied', { summary: 'Delete file', name: 'x.pcap', denied: true }))).toBe(
      'Tried to delete file: x.pcap (refused, no permission)'
    );
  });

  it('files the new kinds under readable tags', () => {
    expect(kindOf('file')).toBe('Capture');
    expect(kindOf('network')).toBe('Network');
    expect(kindOf('node-role')).toBe('Label');
  });
});
