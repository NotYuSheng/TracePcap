export function ClassificationLegend({ highlight }: { highlight: 'role' | 'type' | 'device' }) {
  const rows: { key: 'role' | 'type' | 'device'; label: string; source: string; signal: string }[] = [
    { key: 'role',   label: 'Role',   source: 'TCP session direction',   signal: 'Who initiates' },
    { key: 'type',   label: 'Type',   source: 'Network topology',        signal: 'Ports listened on, peer count' },
    { key: 'device', label: 'Device', source: 'Hardware fingerprinting', signal: 'MAC OUI, TTL, app profile' },
  ];

  return (
    <table className="table table-sm table-bordered mb-0 mt-2" style={{ fontSize: '0.72rem' }}>
      <thead className="table-light">
        <tr>
          <th></th>
          <th>Source</th>
          <th>Signal used</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(r => (
          <tr key={r.key} className={r.key === highlight ? 'table-active' : ''}>
            <td>{r.label}</td>
            <td>{r.source}</td>
            <td>{r.signal}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
