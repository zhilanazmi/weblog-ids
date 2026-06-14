// AlertTable.jsx - Tabel ringkas alert/deteksi terbaru.
// rows: array hasil deteksi (mis. dari GET /api/detections/latest).

// matched_rules disimpan di DB sebagai TEXT JSON (mis. '["XSS-001"]').
// Helper ini mengubahnya menjadi string rapi untuk ditampilkan.
function formatRules(matched) {
  if (!matched) return "-";
  if (Array.isArray(matched)) return matched.join(", ");
  try {
    const arr = JSON.parse(matched);
    return Array.isArray(arr) ? arr.join(", ") : String(matched);
  } catch {
    return String(matched);
  }
}

export default function AlertTable({ rows }) {
  if (!rows || rows.length === 0) {
    return <p className="label">Belum ada alert.</p>;
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Waktu</th>
          <th>IP</th>
          <th>Method</th>
          <th>Request URI</th>
          <th>Label</th>
          <th>Severity</th>
          <th>Rules</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id} className={`sev-${r.severity}`}>
            <td>{r.timestamp}</td>
            <td>{r.ip}</td>
            <td>{r.method}</td>
            <td className="wrap">{r.request_uri}</td>
            <td>
              <span className={`badge label-${r.label}`}>{r.label}</span>
            </td>
            <td>
              <span className={`badge ${r.severity}`}>{r.severity}</span>
            </td>
            <td className="wrap">{formatRules(r.matched_rules)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
