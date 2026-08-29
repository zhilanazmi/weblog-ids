// SummaryCards.jsx - Kartu ringkasan angka deteksi + status watcher.
// Menerima objek summary dari props (di-fetch oleh halaman Dashboard).
export default function SummaryCards({ summary }) {
  // Agregat latency deteksi (ms) dari backend; null bila belum ada data.
  const latency = summary.latency || {};
  const avgLatency =
    latency.avg_ms != null ? `${latency.avg_ms} ms` : "-";
  const latencyDetail =
    latency.min_ms != null && latency.max_ms != null
      ? `min ${latency.min_ms} ms · max ${latency.max_ms} ms`
      : "menunggu data deteksi";

  // Definisi kartu agar mudah ditambah/diubah tanpa mengulang markup.
  const cards = [
    { label: "Total Log", value: summary.total_logs },
    { label: "Normal", value: summary.total_normal },
    { label: "XSS", value: summary.total_xss },
    { label: "SQLi", value: summary.total_sqli },
    { label: "Multiple", value: summary.total_multiple },
    { label: "Total Alert", value: summary.total_alert },
  ];

  return (
    <div className="cards">
      {cards.map((c) => (
        <div className="card" key={c.label}>
          <div className="label">{c.label}</div>
          <div className="value">{c.value ?? 0}</div>
        </div>
      ))}

      {/* Kartu latency deteksi: bukti sistem mendeteksi secara realtime. */}
      <div className="card">
        <div className="label">Avg. Latency Deteksi</div>
        <div className="value">{avgLatency}</div>
        <div className="label" style={{ marginTop: 6, fontSize: 12 }}>
          {latencyDetail}
        </div>
      </div>

      {/* Kartu status watcher: hijau bila berjalan, merah bila tidak. */}
      <div className="card">
        <div className="label">Status Watcher</div>
        <div className="status" style={{ marginTop: 10 }}>
          <span
            className={`dot ${summary.watcher_running ? "on" : "off"}`}
          ></span>
          {summary.watcher_running ? "Berjalan" : "Berhenti"}
        </div>
      </div>
    </div>
  );
}
