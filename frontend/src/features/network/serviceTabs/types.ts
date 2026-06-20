import type { CSSProperties, ReactNode } from 'react';

/** One column of a service-log detail table. */
export interface ServiceLogColumn<Row> {
  header: string;
  cell: (row: Row) => ReactNode;
}

/**
 * Describes one service-role tab shown in the network-diagram node modal. DNS is the first
 * ({@link ./dnsServiceTab}); a future web/API-server role supplies another config of the same shape
 * and registers it — no changes to the modal or the table renderer.
 */
export interface ServiceTabConfig<Detail = unknown, Row = unknown> {
  /** Backend service role this tab renders, matching `serviceRoles` on the host (e.g. "dns"). */
  role: string;
  /** Tab label, e.g. "DNS". */
  label: string;
  /** Bootstrap icon class, e.g. "bi-hdd-network". */
  icon: string;

  /** Loads the per-host detail for this role. */
  fetchDetail: (fileId: string, ip: string) => Promise<Detail>;
  /** Extracts the table rows from the detail payload. */
  getRows: (detail: Detail) => Row[];
  columns: ServiceLogColumn<Row>[];
  /** Optional inline style per row (e.g. light-red for failed/flagged rows). */
  rowStyle?: (row: Row) => CSSProperties | undefined;
  /** One-line summary shown above the table. */
  getSummary: (detail: Detail) => string;
  /** Alert-banner text when the host looks suspicious for this role; null when not. */
  getBanner: (detail: Detail) => string | null;
}
