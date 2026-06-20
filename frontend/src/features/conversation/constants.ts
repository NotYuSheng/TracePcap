export type ColumnKey =
  | 'source'
  | 'destination'
  | 'protocol'
  | 'tsharkProtocol'
  | 'appName'
  | 'category'
  | 'risks'
  | 'customRules'
  | 'idsAlerts'
  | 'fileTypes'
  | 'srcCountry'
  | 'dstCountry'
  | 'packets'
  | 'bytes'
  | 'duration'
  | 'startTime';

export const COLUMN_DEFS: { key: ColumnKey; label: string; defaultVisible: boolean }[] = [
  { key: 'source', label: 'Source', defaultVisible: true },
  { key: 'destination', label: 'Destination', defaultVisible: true },
  { key: 'protocol', label: 'Protocol', defaultVisible: false },
  { key: 'tsharkProtocol', label: 'Dissected Protocol', defaultVisible: true },
  { key: 'appName', label: 'Application', defaultVisible: true },
  { key: 'category', label: 'Category', defaultVisible: true },
  { key: 'risks', label: 'Risks', defaultVisible: true },
  { key: 'customRules', label: 'Custom Rules', defaultVisible: true },
  { key: 'idsAlerts', label: 'IDS Alerts', defaultVisible: true },
  { key: 'fileTypes', label: 'File Type', defaultVisible: true },
  { key: 'srcCountry', label: 'Src Country', defaultVisible: false },
  { key: 'dstCountry', label: 'Dst Country', defaultVisible: false },
  { key: 'packets', label: 'Packets', defaultVisible: false },
  { key: 'bytes', label: 'Bytes', defaultVisible: false },
  { key: 'duration', label: 'Duration', defaultVisible: false },
  { key: 'startTime', label: 'Start Time', defaultVisible: true },
];

export const COLUMN_STORAGE_KEY = 'conv-visible-columns-v6';

/** The default set of visible columns, ignoring any stored user override. */
export function defaultVisibleColumns(): Set<ColumnKey> {
  return new Set(COLUMN_DEFS.filter(c => c.defaultVisible).map(c => c.key));
}

export function loadVisibleColumns(): Set<ColumnKey> {
  try {
    const stored = localStorage.getItem(COLUMN_STORAGE_KEY);
    if (stored) return new Set(JSON.parse(stored) as ColumnKey[]);
  } catch {
    /* ignore */
  }
  return defaultVisibleColumns();
}
