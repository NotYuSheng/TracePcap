/**
 * One status per capture, for where it is in its life, plus quiet notes for everything else
 * (the "File statuses" proposal). Colour is kept for what needs the analyst: amber to act soon,
 * red when it failed.
 */

export type StatusKey = 'queued' | 'analysing' | 'ready' | 'expiring' | 'failed';

export interface CaptureStatus {
  key: StatusKey;
  label: string;
}

export interface CaptureNote {
  key: string;
  label: string;
  /** Where the note's action goes, when it has one. */
  to?: string;
  /** Green for good news (kept), grey otherwise. */
  tone?: 'kept';
}

export interface StatusFile {
  fileId: string;
  status: string;
  source?: string;
  uploadedAt: number;
  enableNdpi?: boolean;
  enableSuricata?: boolean;
  enableFileExtraction?: boolean;
  packetsRemoved?: boolean;
}

export interface StatusContext {
  /** Hours a capture is kept; 0 or null means it is never deleted. */
  retentionHours: number | null;
  /** The networks this capture is a snapshot of. */
  keptWith: { networkId: string; networkName: string }[];
  /** Detection rules changed after it was analysed. */
  rulesChanged: boolean;
  now: number;
}

/** "Expiring soon": deleted within this long. */
export const EXPIRING_WITHIN_MS = 2 * 3600_000;

const LABELS: Record<StatusKey, string> = {
  queued: 'Queued',
  analysing: 'Analysing',
  ready: 'Ready',
  expiring: 'Expiring soon',
  failed: 'Failed',
};

/** When a capture will be deleted, or null if it is kept. */
export function expiresAt(file: StatusFile, ctx: StatusContext): number | null {
  if (!ctx.retentionHours || file.source === 'MONITOR' || ctx.keptWith.length > 0) return null;
  return file.uploadedAt + ctx.retentionHours * 3600_000;
}

export function statusOf(file: StatusFile, ctx: StatusContext): CaptureStatus {
  const s = file.status.toUpperCase();
  let key: StatusKey;
  if (s === 'FAILED') key = 'failed';
  else if (s === 'UPLOADING') key = 'queued';
  else if (s === 'PROCESSING') key = 'analysing';
  else {
    const at = expiresAt(file, ctx);
    key = at != null && at - ctx.now <= EXPIRING_WITHIN_MS ? 'expiring' : 'ready';
  }
  return { key, label: LABELS[key] };
}

/** The notes under a capture's name, only those that apply. */
export function notesOf(file: StatusFile, ctx: StatusContext): CaptureNote[] {
  const notes: CaptureNote[] = ctx.keptWith.map(n => ({
    key: `kept-${n.networkId}`,
    label: `Kept with ${n.networkName}`,
    to: `/monitor/${n.networkId}`,
    tone: 'kept' as const,
  }));
  if (file.source === 'MONITOR' && ctx.keptWith.length === 0) {
    notes.push({ key: 'monitor', label: 'Monitor upload' });
  }
  const skipped = [
    file.enableSuricata === false && 'Suricata',
    file.enableNdpi === false && 'nDPI',
    file.enableFileExtraction === false && 'file extraction',
  ].filter((x): x is string => !!x);
  if (skipped.length > 0) {
    notes.push({ key: 'without', label: `Without ${skipped.join(', ')}` });
  }
  if (ctx.rulesChanged) {
    notes.push({ key: 'rules', label: 'Rules changed since', to: '/settings?tab=rules' });
  }
  if (file.packetsRemoved) notes.push({ key: 'packets', label: 'Packets removed' });
  return notes;
}

/** What the row's button does for each status. */
export function actionOf(key: StatusKey): string {
  switch (key) {
    case 'queued':
    case 'analysing':
      return 'Watch';
    case 'failed':
      return 'See why';
    case 'expiring':
    case 'ready':
      return 'Open';
  }
}
