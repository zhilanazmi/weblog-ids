// SummaryCards.jsx - Kartu ringkasan angka deteksi + status watcher.
// Menerima objek summary dari props (di-fetch oleh halaman Dashboard).
export default function SummaryCards({ summary }) {
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
