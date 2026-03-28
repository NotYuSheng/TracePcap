export type ColumnKey =
  | 'source'
  | 'destination'
  | 'protocol'
  | 'appName'
  | 'category'
  | 'risks'
  | 'packets'
  | 'bytes'
  | 'duration'
  | 'startTime';

export const COLUMN_DEFS: { key: ColumnKey; label: string; defaultVisible: boolean }[] = [
  { key: 'source', label: 'Source', defaultVisible: true },
  { key: 'destination', label: 'Destination', defaultVisible: true },
  { key: 'protocol', label: 'Protocol', defaultVisible: false },
  { key: 'appName', label: 'Application', defaultVisible: true },
  { key: 'category', label: 'Category', defaultVisible: true },
  { key: 'risks', label: 'Risks', defaultVisible: true },
  { key: 'packets', label: 'Packets', defaultVisible: true },
  { key: 'bytes', label: 'Bytes', defaultVisible: true },
  { key: 'duration', label: 'Duration', defaultVisible: true },
  { key: 'startTime', label: 'Start Time', defaultVisible: true },
];

export const COLUMN_STORAGE_KEY = 'conv-visible-columns';

export function loadVisibleColumns(): Set<ColumnKey> {
  try {
    const stored = localStorage.getItem(COLUMN_STORAGE_KEY);
    if (stored) return new Set(JSON.parse(stored) as ColumnKey[]);
  } catch {
    /* ignore */
  }
  return new Set(COLUMN_DEFS.filter(c => c.defaultVisible).map(c => c.key));
}
