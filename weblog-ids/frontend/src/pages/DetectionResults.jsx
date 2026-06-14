import { useState, useEffect, useCallback } from "react";
import { fetchDetections } from "../api/api.js";

// DetectionResults.jsx - Tabel semua hasil deteksi + filter label + paginasi.

const LABELS = ["Semua", "Normal", "XSS", "SQLi", "Multiple"];
const PAGE_SIZE = 20;

// matched_rules dari DB berupa TEXT JSON; ubah jadi string rapi.
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

export default function DetectionResults() {
  const [rows, setRows] = useState([]);
  const [label, setLabel] = useState("Semua");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Ambil data sesuai filter & paginasi. "Semua" dikirim sebagai label kosong
  // agar backend tidak memfilter.
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchDetections({
        limit: PAGE_SIZE,
        offset,
        label: label === "Semua" ? "" : label,
      });
      setRows(res.data || []);
      setError("");
    } catch (e) {
      setError(
        "Gagal mengambil data deteksi. Pastikan backend berjalan. (" +
          e.message + ")"
      );
    } finally {
      setLoading(false);
    }
  }, [label, offset]);

  useEffect(() => {
    load();
  }, [load]);

  // Saat ganti filter label: kembali ke halaman pertama (offset 0).
  const onChangeLabel = (e) => {
    setLabel(e.target.value);
    setOffset(0);
  };

  const page = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div>
      <h2 className="page-title">Hasil Deteksi</h2>

      <div className="controls">
        <label>
          Filter label:{" "}
          <select value={label} onChange={onChangeLabel}>
            {LABELS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </label>

        {/* Paginasi sederhana berbasis offset. Tombol Prev nonaktif di halaman 1. */}
        <button
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          disabled={offset === 0}
        >
          ← Sebelumnya
        </button>
        <span>Halaman {page}</span>
        <button
          onClick={() => setOffset(offset + PAGE_SIZE)}
          disabled={rows.length < PAGE_SIZE}
        >
          Berikutnya →
        </button>
      </div>

      {error && <div className="msg error">{error}</div>}
      {loading && <div className="msg loading">Memuat...</div>}

      {!loading && rows.length === 0 && !error && (
        <p className="label">Tidak ada data untuk filter ini.</p>
      )}

      {rows.length > 0 && (
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Waktu</th>
                <th>IP</th>
                <th>Method</th>
                <th>Request URI</th>
                <th>Decoded Payload</th>
                <th>Label</th>
                <th>Severity</th>
                <th>Rules</th>
                <th>Rekomendasi</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                // class sev-* memberi warna baris sesuai severity.
                <tr key={r.id} className={`sev-${r.severity}`}>
                  <td>{r.timestamp}</td>
                  <td>{r.ip}</td>
                  <td>{r.method}</td>
                  <td className="wrap">{r.request_uri}</td>
                  <td className="wrap">{r.decoded_payload}</td>
                  <td>
                    <span className={`badge label-${r.label}`}>{r.label}</span>
                  </td>
                  <td>
                    <span className={`badge ${r.severity}`}>{r.severity}</span>
                  </td>
                  <td className="wrap">{formatRules(r.matched_rules)}</td>
                  <td className="wrap">{r.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
