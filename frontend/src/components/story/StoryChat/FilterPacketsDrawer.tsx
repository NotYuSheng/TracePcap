import { useEffect, useState } from 'react';
import { SideDrawer } from '@components/common/SideDrawer';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Pagination } from '@components/common/Pagination';
import { filterService } from '@/features/filter/services/filterService';
import { formatBytes } from '@/utils/formatters';
import type { Packet } from '@/types';

/** The packets a checked filter matches, paged, in the side drawer. */
export function FilterPacketsDrawer({ fileId, filter, onHide }: { fileId: string; filter: string; onHide: () => void }) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  // Loading until the page asked for has come back (derived, so the effect sets no state up front).
  const key = `${page}:${pageSize}`;
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const loading = loadedKey !== key;

  useEffect(() => {
    let live = true;
    filterService
      .executeFilter(fileId, filter, page, pageSize)
      .then(r => {
        if (!live) return;
        setPackets(r.packets ?? []);
        setTotal(r.totalMatches ?? 0);
        setError(null);
      })
      .catch(() => live && setError('The packets couldn’t be read.'))
      .finally(() => live && setLoadedKey(`${page}:${pageSize}`));
    return () => {
      live = false;
    };
  }, [fileId, filter, page, pageSize]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <SideDrawer show onHide={onHide} title="Matching packets" titleId="chat-filter-packets" className="side-drawer-wide">
      <code className="chat-filter-expr d-block mb-2">{filter}</code>
      <p className="text-muted small">{total.toLocaleString()} packets match.</p>
      {error && <p className="text-danger small">{error}</p>}
      {loading ? (
        <div className="text-muted small"><Spinner animation="border" size="sm" className="me-2" />Reading packets…</div>
      ) : (
        <div className="table-responsive">
        <table className="table table-sm small chat-packets-table">
          <thead>
            <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th className="text-end">Size</th></tr>
          </thead>
          <tbody>
            {packets.map(p => (
              <tr key={p.id}>
                <td className="font-monospace">{new Date(p.timestamp).toISOString().slice(11, 23)}</td>
                <td className="font-monospace">{p.source?.ip}{p.source?.port ? `:${p.source.port}` : ''}</td>
                <td className="font-monospace">{p.destination?.ip}{p.destination?.port ? `:${p.destination.port}` : ''}</td>
                <td>{p.protocol?.name}</td>
                <td className="text-end">{formatBytes(p.size ?? 0)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {total > 10 && (
        <Pagination
          currentPage={Math.min(page, totalPages)}
          totalPages={totalPages}
          totalItems={total}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={n => { setPageSize(n); setPage(1); }}
          pageSizeOptions={[10, 25, 50, 100]}
        />
      )}
    </SideDrawer>
  );
}
